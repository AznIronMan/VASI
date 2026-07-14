import { createHash, randomUUID } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";

import {
  defaultSettingsPath,
  loadBootstrapSettings,
} from "./settings-core.mjs";

const BACKUP_SCHEMA = "vasi-matched-backup/v1";

try {
  const [command, source, confirmation] = process.argv.slice(2);
  if (command === "create") await createBackup(source);
  else if (command === "verify") await verifyBackup(source);
  else if (command === "restore") await restoreBackup(source, confirmation);
  else usage();
} catch (error) {
  console.error(error instanceof Error ? error.message : "VASI backup operation failed.");
  process.exitCode = 1;
}

async function createBackup(destination) {
  if (!destination) throw new Error("A backup directory is required.");
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
      createdAt: new Date().toISOString(),
      files: {
        "VASI.settings": await digestFile(settingsPath),
        "postgresql.dump": await digestFile(databasePath),
      },
      installationFingerprint: createHash("sha256").update(bootstrap.installationId).digest("hex"),
      schema: BACKUP_SCHEMA,
    };
    await writeFile(path.join(temporary, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, target);
    console.info("Matched PostgreSQL and VASI.settings backup created. Store this directory in an encrypted backup system.");
  } catch (error) {
    await rm(temporary, { force: true, recursive: true }).catch(() => undefined);
    throw error;
  }
}

async function verifyBackup(source) {
  const { directory, manifest } = await verifiedManifest(source);
  await runCommand("pg_restore", ["--list", path.join(directory, "postgresql.dump")]);
  console.info(`Backup verified: ${manifest.createdAt}.`);
}

async function restoreBackup(source, confirmation) {
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
  const manifest = JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8"));
  if (manifest.schema !== BACKUP_SCHEMA || !manifest.files) throw new Error("The backup manifest is unsupported.");
  for (const filename of ["VASI.settings", "postgresql.dump"]) {
    const actual = await digestFile(path.join(directory, filename));
    if (actual !== manifest.files[filename]) throw new Error(`Backup file ${filename} failed its checksum.`);
  }
  return { directory, manifest };
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
