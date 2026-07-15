import process from "node:process";

import { verifyReadinessDossierFile } from "../packages/readiness-dossier/index.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

export async function runReadinessDossierVerification(argumentsList) {
  const { expectedDigest, expectedKeyFingerprint, filename } = parseArguments(argumentsList);
  return verifyReadinessDossierFile(filename, { expectedDigest, expectedKeyFingerprint });
}

function parseArguments(argumentsList) {
  if (!Array.isArray(argumentsList) || !argumentsList.length ||
      argumentsList.length > 5 || argumentsList.length % 2 !== 1) usage();
  const [filename, ...options] = argumentsList;
  if (typeof filename !== "string" || !filename) usage();
  const parsed = { filename };
  for (let index = 0; index < options.length; index += 2) {
    const option = options[index];
    const value = options[index + 1];
    if (typeof value !== "string" || !value) usage();
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
    "Usage: node scripts/verify-readiness-dossier.mjs FILE " +
    "[--expected-sha256 LOWERCASE_SHA256] [--expected-key-fingerprint LOWERCASE_SHA256]",
  );
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runReadinessDossierVerification(process.argv.slice(2))
    .then((result) => console.info(JSON.stringify(result)))
    .catch((error) => {
      if (error instanceof Error && error.message.startsWith("Usage:")) console.error(error.message);
      else console.error("VASI readiness dossier verification failed.");
      process.exitCode = 1;
    });
}
