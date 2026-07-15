import process from "node:process";

import {
  createPilotGateEvidenceManifestFile,
  verifyPilotGateEvidenceManifestFile,
} from "../packages/pilot-gate-evidence/index.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

export async function runPilotGateEvidence(argumentsList) {
  const operation = parseArguments(argumentsList);
  if (operation.command === "create") {
    return createPilotGateEvidenceManifestFile(
      operation.descriptorFile,
      operation.evidenceDirectory,
      operation.outputManifest,
    );
  }
  return verifyPilotGateEvidenceManifestFile(
    operation.manifestFile,
    operation.evidenceDirectory,
    { expectedDigest: operation.expectedDigest },
  );
}

function parseArguments(argumentsList) {
  if (!Array.isArray(argumentsList) || !argumentsList.length) usage();
  if (argumentsList[0] === "create" && argumentsList.length === 4 &&
      argumentsList.slice(1).every(nonemptyString)) {
    return {
      command: "create",
      descriptorFile: argumentsList[1],
      evidenceDirectory: argumentsList[2],
      outputManifest: argumentsList[3],
    };
  }
  if (argumentsList[0] === "verify" &&
      (argumentsList.length === 3 || argumentsList.length === 5) &&
      argumentsList.slice(1).every(nonemptyString) &&
      (argumentsList.length === 3 || argumentsList[3] === "--expected-sha256")) {
    return {
      command: "verify",
      evidenceDirectory: argumentsList[2],
      expectedDigest: argumentsList[4],
      manifestFile: argumentsList[1],
    };
  }
  usage();
}

function nonemptyString(value) {
  return typeof value === "string" && Boolean(value);
}

function usage() {
  throw new Error(
    "Usage: node scripts/pilot-gate-evidence.mjs create " +
    "DESCRIPTOR_FILE EVIDENCE_DIRECTORY OUTPUT_MANIFEST\n" +
    "       node scripts/pilot-gate-evidence.mjs verify " +
    "MANIFEST_FILE EVIDENCE_DIRECTORY [--expected-sha256 LOWERCASE_SHA256]",
  );
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runPilotGateEvidence(process.argv.slice(2))
    .then((result) => console.info(JSON.stringify(result)))
    .catch((error) => {
      if (error instanceof Error && error.message.startsWith("Usage:")) console.error(error.message);
      else console.error("VASI pilot-gate evidence operation failed.");
      process.exitCode = 1;
    });
}
