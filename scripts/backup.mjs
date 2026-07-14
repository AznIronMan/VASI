import { createHash, randomUUID } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

import {
  defaultSettingsPath,
  loadBootstrapSettings,
} from "./settings-core.mjs";

export const BACKUP_SCHEMA = "vasi-matched-backup/v1";

export async function createBackup(destination, { now = new Date(), quiet = false } = {}) {
  if (!destination) throw new Error("A backup directory is required.");
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("The backup creation time is invalid.");
  const target = path.resolve(destination);
  await assertMissing(target);
  const temporary = `${target}.partial-${randomUUID()}`;
  await mkdir(temporary, { mode: 0o700, recursive: false });
  try {
    const bootstrap = loadBootstrapSettings();
    const databasePath = path.join(temporary, "postgresql.dump");
    await runPostgresTool("pg_dump", [
      "--format=custom",
      "--no-owner",
      "--no-privileges",
      "--serializable-deferrable",
      `--file=${databasePath}`,
    ], bootstrap.databaseURL);
    await chmod(databasePath, 0o600);
    const settingsPath = path.join(temporary, "VASI.settings");
    await copyFile(defaultSettingsPath(), settingsPath);
    await chmod(settingsPath, 0o600);
    const manifest = {
      createdAt: now.toISOString(),
      files: {
        "VASI.settings": await digestFile(settingsPath),
        "postgresql.dump": await digestFile(databasePath),
      },
      installationFingerprint: createHash("sha256").update(bootstrap.installationId).digest("hex"),
      schema: BACKUP_SCHEMA,
    };
    await writeFile(path.join(temporary, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, target);
    if (!quiet) console.info("Matched PostgreSQL and VASI.settings backup created. Store this directory in an encrypted backup system.");
    return manifest;
  } catch (error) {
    await rm(temporary, { force: true, recursive: true }).catch(() => undefined);
    throw error;
  }
}

export async function verifyBackup(source, { quiet = false } = {}) {
  const { directory, manifest } = await verifiedManifest(source);
  await runCommand("pg_restore", ["--list", path.join(directory, "postgresql.dump")]);
  if (!quiet) console.info(`Backup verified: ${manifest.createdAt}.`);
  return manifest;
}

export async function restoreBackup(source, confirmation) {
  if (confirmation !== "--confirm-replace-database") {
    throw new Error("Restore requires the explicit --confirm-replace-database argument.");
  }
  const { directory } = await verifiedManifest(source);
  const destination = loadBootstrapSettings();
  await runPostgresTool("pg_restore", [
    "--clean",
    "--if-exists",
    "--exit-on-error",
    "--no-owner",
    "--no-privileges",
    path.join(directory, "postgresql.dump"),
  ], destination.databaseURL);
  console.info("PostgreSQL restore completed. Restore the matched VASI.settings only when it belongs to this database endpoint, then run migrations and conformance probes.");
}

async function verifiedManifest(source) {
  if (!source) throw new Error("A backup directory is required.");
  const directory = path.resolve(source);
  const manifest = validateBackupManifest(JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8")));
  for (const filename of ["VASI.settings", "postgresql.dump"]) {
    const actual = await digestFile(path.join(directory, filename));
    if (actual !== manifest.files[filename]) throw new Error(`Backup file ${filename} failed its checksum.`);
  }
  return { directory, manifest };
}

export function validateBackupManifest(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("The backup manifest is unsupported.");
  if (Object.keys(value).sort().join(",") !== "createdAt,files,installationFingerprint,schema") {
    throw new Error("The backup manifest fields are unsupported.");
  }
  if (value.schema !== BACKUP_SCHEMA || !value.files || Array.isArray(value.files) || typeof value.files !== "object") {
    throw new Error("The backup manifest is unsupported.");
  }
  if (Object.keys(value.files).sort().join(",") !== "VASI.settings,postgresql.dump") {
    throw new Error("The backup manifest file inventory is unsupported.");
  }
  const createdAt = new Date(value.createdAt);
  if (!Number.isFinite(createdAt.getTime()) || createdAt.toISOString() !== value.createdAt) {
    throw new Error("The backup manifest creation time is invalid.");
  }
  if (!/^[a-f0-9]{64}$/.test(value.installationFingerprint)) {
    throw new Error("The backup manifest installation fingerprint is invalid.");
  }
  for (const digest of Object.values(value.files)) {
    if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) {
      throw new Error("The backup manifest file digest is invalid.");
    }
  }
  return value;
}

async function runPostgresTool(command, argumentsList, databaseURL) {
  const parsed = new URL(databaseURL);
  const password = decodeURIComponent(parsed.password);
  if (!password) throw new Error("The PostgreSQL bootstrap URL does not contain a password.");
  parsed.password = "";
  const pgpass = [parsed.hostname, parsed.port || "5432", parsed.pathname.slice(1), decodeURIComponent(parsed.username), password]
    .map(escapePgpass)
    .join(":");
  const temporary = await mkdtemp(path.join(tmpdir(), "vasi-pgpass-"));
  const passfile = path.join(temporary, "pgpass");
  await writeFile(passfile, `${pgpass}\n`, { mode: 0o600 });
  try {
    await new Promise((resolve, reject) => {
      const child = spawn(command, [`--dbname=${parsed.toString()}`, ...argumentsList], {
        env: { ...process.env, PGPASSFILE: passfile },
        stdio: ["ignore", "inherit", "inherit"],
      });
      child.once("error", reject);
      child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`${command} exited with status ${code}.`)));
    });
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
}

async function runCommand(command, argumentsList) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, argumentsList, { stdio: ["ignore", "ignore", "inherit"] });
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`${command} exited with status ${code}.`)));
  });
}

function escapePgpass(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll(":", "\\:");
}

async function digestFile(filePath) {
  const input = (await import("node:fs")).createReadStream(filePath);
  const digest = createHash("sha256");
  for await (const chunk of input) digest.update(chunk);
  return digest.digest("hex");
}

async function assertMissing(target) {
  try {
    await stat(target);
    throw new Error("The backup destination already exists.");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await mkdir(path.dirname(target), { recursive: true });
}

function usage() {
  console.info(`VASI matched backup:
  node scripts/backup.mjs create BACKUP_DIRECTORY
  node scripts/backup.mjs verify BACKUP_DIRECTORY
  node scripts/backup.mjs restore BACKUP_DIRECTORY --confirm-replace-database`);
  process.exitCode = 1;
}

async function main(args) {
  const [command, source, confirmation] = args;
  if (command === "create") await createBackup(source);
  else if (command === "verify") await verifyBackup(source);
  else if (command === "restore") await restoreBackup(source, confirmation);
  else usage();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : "VASI backup operation failed.");
    process.exitCode = 1;
  });
}
