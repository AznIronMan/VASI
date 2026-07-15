import process from "node:process";

import { verifyReadinessDossierFile } from "../packages/readiness-dossier/index.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

export async function runReadinessDossierVerification(argumentsList) {
  const { expectedDigest, filename } = parseArguments(argumentsList);
  return verifyReadinessDossierFile(filename, { expectedDigest });
}

function parseArguments(argumentsList) {
  if (!Array.isArray(argumentsList) || !argumentsList.length || argumentsList.length > 3) usage();
  const [filename, option, expectedDigest] = argumentsList;
  if (typeof filename !== "string" || !filename ||
      (argumentsList.length === 3 && option !== "--expected-sha256") ||
      (argumentsList.length !== 1 && argumentsList.length !== 3)) usage();
  return { expectedDigest, filename };
}

function usage() {
  throw new Error(
    "Usage: node scripts/verify-readiness-dossier.mjs FILE [--expected-sha256 LOWERCASE_SHA256]",
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
