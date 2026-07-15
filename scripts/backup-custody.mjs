import process from "node:process";
import { isDirectExecution } from "./direct-execution.mjs";

import policy from "../config/assurance-policy.json" with { type: "json" };
import {
  BackupCustodyError,
  authenticateCustodyPackage,
  checkLatestCustody,
  createCustodyCycle,
  extractCustodyPackage,
  generateCustodyRecipient,
  inspectCustodyPackage,
  parseCustodyRecipients,
} from "../packages/backup-custody/index.mjs";
import { verifyBackup } from "./backup.mjs";
import { readRuntimeSetting } from "./settings-core.mjs";

export async function runBackupCustodyCommand(args) {
  const [command, ...rest] = args;
  if (command === "recipient") {
    if (rest.length !== 2) return usage();
    const recipient = await generateCustodyRecipient({ keyId: rest[0], privateKeyFile: rest[1] });
    console.info(JSON.stringify(recipient, null, 2));
    return recipient;
  }
  if (command === "inspect") {
    if (rest.length !== 1) return usage();
    const result = await inspectCustodyPackage(rest[0]);
    console.info(JSON.stringify(result, null, 2));
    return result;
  }
  if (command === "authenticate") {
    if (!rest[0]) return usage();
    const options = parseOptions(rest.slice(1), new Set(["--key-id", "--private-key-file"]));
    if (!options["--key-id"] || !options["--private-key-file"]) {
      throw new Error("Custody authentication requires --key-id and --private-key-file.");
    }
    const result = await authenticateCustodyPackage({
      keyId: options["--key-id"],
      packagePath: rest[0],
      privateKeyFile: options["--private-key-file"],
    });
    console.info(JSON.stringify(result, null, 2));
    return result;
  }
  if (command === "check") {
    if (!rest[0]) return usage();
    const options = parseOptions(rest.slice(1), new Set(["--maximum-age-hours"]));
    const result = await checkLatestCustody({
      custodyRoot: rest[0],
      maximumAgeHours: numericOption(
        options["--maximum-age-hours"],
        policy.backups.custodyMaximumAgeHours,
        "--maximum-age-hours",
      ),
    });
    console.info(JSON.stringify(result, null, 2));
    return result;
  }
  if (command === "create") {
    if (!rest[0] || !rest[1]) return usage();
    const options = parseOptions(rest.slice(2), new Set(["--maximum-age-hours", "--retain", "--scope"]));
    const scope = options["--scope"] || "gateway";
    if (!new Set(["gateway", "engine"]).has(scope)) throw new Error("Backup custody scope must be gateway or engine.");
    const configuredRecipients = await readRuntimeSetting({ name: "BACKUP_CUSTODY_RECIPIENTS", scope });
    if (!configuredRecipients) {
      throw new Error(`BACKUP_CUSTODY_RECIPIENTS is not configured for the VASI ${scope} scope.`);
    }
    const result = await createCustodyCycle({
      custodyRoot: rest[1],
      matchedBackupRoot: rest[0],
      maximumAgeHours: numericOption(
        options["--maximum-age-hours"],
        policy.backups.custodyMaximumAgeHours,
        "--maximum-age-hours",
      ),
      recipients: parseCustodyRecipients(configuredRecipients),
      retain: numericOption(options["--retain"], policy.backups.custodyRetain, "--retain"),
      verify: verifyBackup,
    });
    console.info(JSON.stringify(result, null, 2));
    return result;
  }
  if (command === "extract") {
    if (!rest[0] || !rest[1]) return usage();
    const options = parseOptions(rest.slice(2), new Set(["--key-id", "--private-key-file"]));
    if (!options["--key-id"] || !options["--private-key-file"]) {
      throw new Error("Custody extraction requires --key-id and --private-key-file.");
    }
    const result = await extractCustodyPackage({
      destination: rest[1],
      keyId: options["--key-id"],
      packagePath: rest[0],
      privateKeyFile: options["--private-key-file"],
      verify: verifyBackup,
    });
    console.info(JSON.stringify(result, null, 2));
    return result;
  }
  return usage();
}

function parseOptions(args, allowed) {
  if (args.length % 2 !== 0) throw new Error(`Backup custody option ${args.at(-1)} requires a value.`);
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!allowed.has(name)) throw new Error(`Unknown backup custody option ${name || "(missing)"}.`);
    if (result[name] !== undefined) throw new Error(`Backup custody option ${name} was repeated.`);
    result[name] = args[index + 1];
  }
  return result;
}

function numericOption(value, fallback, name) {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new Error(`Backup custody option ${name} requires a number.`);
  return parsed;
}

function usage() {
  console.info(`VASI recipient-encrypted backup custody:
  node scripts/backup-custody.mjs recipient OPAQUE_KEY_ID PRIVATE_JWK_FILE
  node scripts/backup-custody.mjs create MATCHED_BACKUP_ROOT CUSTODY_ROOT [--scope gateway|engine] [--retain N] [--maximum-age-hours N]
  node scripts/backup-custody.mjs check CUSTODY_ROOT [--maximum-age-hours N]
  node scripts/backup-custody.mjs inspect PACKAGE.vbc
  node scripts/backup-custody.mjs authenticate PACKAGE.vbc --key-id OPAQUE_KEY_ID --private-key-file PRIVATE_JWK_FILE
  node scripts/backup-custody.mjs extract PACKAGE.vbc DESTINATION --key-id OPAQUE_KEY_ID --private-key-file PRIVATE_JWK_FILE`);
  process.exitCode = 1;
  return undefined;
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runBackupCustodyCommand(process.argv.slice(2)).catch((error) => {
    if (error?.result) console.error(JSON.stringify(error.result, null, 2));
    console.error(error instanceof BackupCustodyError
      ? error.message
      : error instanceof Error ? error.message : "VASI backup custody operation failed.");
    process.exitCode = 1;
  });
}
