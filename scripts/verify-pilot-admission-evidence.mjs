import process from "node:process";

import { verifyPilotAdmissionEvidenceSet } from "../packages/pilot-admission-evidence/index.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

export async function runPilotAdmissionEvidenceVerification(argumentsList) {
  const {
    dossierFile,
    expectedDigest,
    expectedKeyFingerprint,
    manifestDirectory,
  } = parseArguments(argumentsList);
  return verifyPilotAdmissionEvidenceSet(dossierFile, manifestDirectory, {
    expectedDigest,
    expectedKeyFingerprint,
  });
}

function parseArguments(argumentsList) {
  if (
    !Array.isArray(argumentsList) ||
    ![2, 4, 6].includes(argumentsList.length) ||
    argumentsList.some((value) => typeof value !== "string" || !value)
  ) usage();
  const [dossierFile, manifestDirectory, ...options] = argumentsList;
  const parsed = { dossierFile, manifestDirectory };
  for (let index = 0; index < options.length; index += 2) {
    const option = options[index];
    const value = options[index + 1];
    if (option === "--expected-sha256" && parsed.expectedDigest === undefined) {
      parsed.expectedDigest = value;
    } else if (
      option === "--expected-key-fingerprint" && parsed.expectedKeyFingerprint === undefined
    ) {
      parsed.expectedKeyFingerprint = value;
    } else {
      usage();
    }
  }
  return parsed;
}

function usage() {
  throw new Error(
    "Usage: node scripts/verify-pilot-admission-evidence.mjs DOSSIER_FILE " +
    "MANIFEST_DIRECTORY [--expected-sha256 LOWERCASE_SHA256] " +
    "[--expected-key-fingerprint LOWERCASE_SHA256]",
  );
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runPilotAdmissionEvidenceVerification(process.argv.slice(2))
    .then((result) => console.info(JSON.stringify(result)))
    .catch((error) => {
      if (error instanceof Error && error.message.startsWith("Usage:")) console.error(error.message);
      else console.error("VASI pilot-admission evidence verification failed.");
      process.exitCode = 1;
    });
}
