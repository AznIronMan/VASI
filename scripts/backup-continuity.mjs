import { lstat, open, readdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { isDirectExecution } from "./direct-execution.mjs";

import policy from "../config/assurance-policy.json" with { type: "json" };
import { BACKUP_SCHEMA, createBackup, validateBackupManifest, verifyBackup } from "./backup.mjs";

export const BACKUP_CONTINUITY_SCHEMA = "vasi-backup-continuity/v1";
const BACKUP_NAME = /^vasi-\d{8}T\d{6}Z$/;
const LOCK_NAME = ".vasi-backup.lock";

export class BackupContinuityError extends Error {
  constructor(message, result) {
    super(message);
    this.result = result;
  }
}

export async function createBackupCycle({
  backupRoot,
  create = createBackup,
  maximumAgeHours = policy.backups.maximumAgeHours,
  now = new Date(),
  retain = policy.backups.retain,
  verify = verifyBackup,
} = {}) {
  const root = await secureBackupRoot(backupRoot);
  const instant = validDate(now);
  boundedInteger(retain, "retained backup count", 2, 365);
  boundedNumber(maximumAgeHours, "maximum backup age", 1, 8_760);
  const releaseLock = await acquireLock(root, instant);
  const name = backupDirectoryName(instant);
  const destination = path.join(root, name);
  let created = false;
  let verified = false;
  try {
    await create(destination, { now: instant, quiet: true });
    created = true;
    const manifest = await verify(destination, { quiet: true });
    assertManagedManifest(name, manifest);
    verified = true;

    let names = await managedBackupNames(root);
    let removed = 0;
    while (names.length > retain) {
      const candidate = names.find((entry) => entry !== name);
      if (!candidate) throw new Error("Backup retention cannot remove the newly verified backup.");
      const candidatePath = path.join(root, candidate);
      const candidateManifest = await verify(candidatePath, { quiet: true });
      assertManagedManifest(candidate, candidateManifest);
      await rm(candidatePath, { recursive: true });
      removed += 1;
      names = await managedBackupNames(root);
    }

    const readiness = readinessResult({
      createdAt: manifest.createdAt,
      managedBackups: names.length,
      maximumAgeHours,
      now: instant,
    });
    return Object.freeze({
      ...readiness,
      created: true,
      removed,
      retained: names.length,
    });
  } catch (error) {
    if (created && !verified) await rm(destination, { force: true, recursive: true }).catch(() => undefined);
    throw error;
  } finally {
    await releaseLock();
  }
}

export async function checkLatestBackup({
  backupRoot,
  maximumAgeHours = policy.backups.maximumAgeHours,
  now = new Date(),
  verify = verifyBackup,
} = {}) {
  const root = await secureBackupRoot(backupRoot);
  const instant = validDate(now);
  boundedNumber(maximumAgeHours, "maximum backup age", 1, 8_760);
  const names = await managedBackupNames(root);
  if (!names.length) {
    throw readinessFailure("No managed matched backup is available.", maximumAgeHours, "backup_missing");
  }
  const name = names.at(-1);
  let manifest;
  try {
    manifest = await verify(path.join(root, name), { quiet: true });
    assertManagedManifest(name, manifest);
  } catch {
    throw readinessFailure("The newest managed matched backup failed verification.", maximumAgeHours, "backup_verification_failed", names.length);
  }
  return readinessResult({
    createdAt: manifest.createdAt,
    managedBackups: names.length,
    maximumAgeHours,
    now: instant,
  });
}

function readinessResult({ createdAt, managedBackups, maximumAgeHours, now }) {
  const created = validDate(new Date(createdAt));
  const ageHours = rounded((now.getTime() - created.getTime()) / 3_600_000);
  if (ageHours < -5 / 60) {
    throw readinessFailure("The newest managed backup has a future creation time.", maximumAgeHours, "backup_time_in_future", managedBackups);
  }
  const result = Object.freeze({
    ageHours: Math.max(0, ageHours),
    createdAt: created.toISOString(),
    managedBackups,
    maximumAgeHours,
    reasons: [],
    schema: BACKUP_CONTINUITY_SCHEMA,
    status: "ready",
  });
  if (ageHours > maximumAgeHours) {
    throw new BackupContinuityError(
      "The newest managed matched backup is older than the configured threshold.",
      Object.freeze({ ...result, reasons: ["backup_age_threshold_exceeded"], status: "critical" }),
    );
  }
  return result;
}

function readinessFailure(message, maximumAgeHours, reason, managedBackups = 0) {
  return new BackupContinuityError(message, Object.freeze({
    ageHours: null,
    createdAt: null,
    managedBackups,
    maximumAgeHours,
    reasons: [reason],
    schema: BACKUP_CONTINUITY_SCHEMA,
    status: "critical",
  }));
}

async function secureBackupRoot(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("A protected backup root is required.");
  const root = path.resolve(value);
  const details = await lstat(root).catch(() => undefined);
  if (!details?.isDirectory() || details.isSymbolicLink()) throw new Error("The backup root must be an existing real directory.");
  if ((details.mode & 0o077) !== 0) throw new Error("The backup root must be mode 0700 or stricter.");
  return root;
}

async function acquireLock(root, now) {
  const lockPath = path.join(root, LOCK_NAME);
  let handle;
  try {
    handle = await open(lockPath, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify({ schema: "vasi-backup-lock/v1", startedAt: now.toISOString() })}\n`);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error?.code === "EEXIST") throw new Error("Another backup cycle holds the protected backup lock.");
    throw error;
  }
  await handle.close();
  return async () => rm(lockPath, { force: true });
}

async function managedBackupNames(root) {
  const entries = await readdir(root, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory() && BACKUP_NAME.test(entry.name))
    .map((entry) => entry.name)
    .sort();
}

function assertManagedManifest(name, manifest) {
  const validated = validateBackupManifest(manifest);
  if (validated.schema !== BACKUP_SCHEMA) throw new Error("The managed backup manifest is unsupported.");
  const createdAt = validDate(new Date(validated.createdAt));
  if (backupDirectoryName(createdAt) !== name) throw new Error("The managed backup name and manifest creation time disagree.");
}

function backupDirectoryName(date) {
  return `vasi-${date.toISOString().slice(0, 19).replaceAll("-", "").replaceAll(":", "")}Z`;
}

function validDate(value) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("The backup timestamp is invalid.");
  return value;
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`The ${name} must be between ${minimum} and ${maximum}.`);
  }
}

function boundedNumber(value, name, minimum, maximum) {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`The ${name} must be between ${minimum} and ${maximum}.`);
  }
}

function rounded(value) {
  return Number(value.toFixed(3));
}

function parseArguments(args) {
  const [command, backupRoot, ...options] = args;
  if (!["create", "check"].includes(command) || !backupRoot) usage();
  const parsed = { backupRoot };
  for (let index = 0; index < options.length; index += 2) {
    const name = options[index];
    const value = Number(options[index + 1]);
    if (!Number.isFinite(value)) throw new Error(`Backup continuity option ${name || "(missing)"} requires a number.`);
    if (name === "--maximum-age-hours") parsed.maximumAgeHours = value;
    else if (name === "--retain" && command === "create") parsed.retain = value;
    else throw new Error(`Unknown backup continuity option ${name}.`);
  }
  return { command, options: parsed };
}

function usage() {
  console.info(`VASI recurring matched backup continuity:
  node scripts/backup-continuity.mjs create PROTECTED_ROOT [--retain N] [--maximum-age-hours N]
  node scripts/backup-continuity.mjs check PROTECTED_ROOT [--maximum-age-hours N]`);
  process.exit(1);
}

async function main(args) {
  const parsed = parseArguments(args);
  const result = parsed.command === "create"
    ? await createBackupCycle(parsed.options)
    : await checkLatestBackup(parsed.options);
  console.info(JSON.stringify(result, null, 2));
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main(process.argv.slice(2)).catch((error) => {
    if (error?.result) console.error(JSON.stringify(error.result, null, 2));
    console.error(error instanceof BackupContinuityError
      ? error.message
      : "VASI backup continuity operation failed.");
    process.exitCode = 1;
  });
}
