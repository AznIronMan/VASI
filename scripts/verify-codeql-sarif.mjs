import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { isDirectExecution } from "./direct-execution.mjs";

const MAX_SARIF_FILES = 16;
const MAX_SARIF_BYTES = 64 * 1024 * 1024;
const HIGH_SECURITY_SEVERITY = 7;

export async function verifyCodeQLSarifDirectory(directory) {
  if (typeof directory !== "string" || !path.isAbsolute(directory)) {
    throw new Error("CodeQL SARIF directory must be an absolute path");
  }

  const directoryMetadata = await lstat(directory);
  if (directoryMetadata.isSymbolicLink() || !directoryMetadata.isDirectory()) {
    throw new Error("CodeQL SARIF input must be a physical directory");
  }

  const entries = await readdir(directory, { withFileTypes: true });
  if (entries.some((entry) => entry.isSymbolicLink() || !entry.isFile())) {
    throw new Error("CodeQL SARIF directory contains an unsupported entry");
  }
  const sarifFiles = entries
    .filter((entry) => entry.name.endsWith(".sarif"))
    .map((entry) => entry.name)
    .sort();
  if (!sarifFiles.length || sarifFiles.length > MAX_SARIF_FILES) {
    throw new Error("CodeQL SARIF file count is outside the assurance bound");
  }
  if (sarifFiles.length !== entries.length) {
    throw new Error("CodeQL SARIF directory contains an unexpected file");
  }

  let bytes = 0;
  let highOrCriticalResults = 0;
  let maximumSecuritySeverity = 0;
  let results = 0;
  let runs = 0;

  for (const filename of sarifFiles) {
    const absolute = path.join(directory, filename);
    let sarif;
    const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    try {
      const before = await handle.stat();
      if (!before.isFile()) throw new Error("CodeQL SARIF input must contain only physical files");
      bytes += before.size;
      if (bytes > MAX_SARIF_BYTES) {
        throw new Error("CodeQL SARIF input exceeds the assurance size bound");
      }
      const contents = await handle.readFile();
      const after = await handle.stat();
      if (
        contents.length !== before.size || before.dev !== after.dev || before.ino !== after.ino ||
        before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
      ) {
        throw new Error("CodeQL SARIF input changed while it was read");
      }
      sarif = JSON.parse(contents.toString("utf8"));
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error("CodeQL SARIF input is not valid JSON");
      throw error;
    } finally {
      await handle.close();
    }
    if (sarif?.version !== "2.1.0" || !Array.isArray(sarif?.runs) || !sarif.runs.length) {
      throw new Error("CodeQL SARIF input does not use the supported schema");
    }

    for (const run of sarif.runs) {
      runs += 1;
      const rules = run?.tool?.driver?.rules;
      const runResults = run?.results;
      if (!Array.isArray(rules) || !Array.isArray(runResults)) {
        throw new Error("CodeQL SARIF run is missing rules or results");
      }
      const severityByRuleId = new Map();
      for (const rule of rules) {
        const ruleId = rule?.id;
        const rawSeverity = rule?.properties?.["security-severity"];
        if (typeof ruleId !== "string" || !ruleId || severityByRuleId.has(ruleId)) {
          throw new Error("CodeQL SARIF rule identity is invalid");
        }
        if (rawSeverity === undefined) continue;
        const severity = typeof rawSeverity === "number" ? rawSeverity : Number(rawSeverity);
        if (!Number.isFinite(severity) || severity < 0 || severity > 10) {
          throw new Error("CodeQL SARIF rule security severity is invalid");
        }
        severityByRuleId.set(ruleId, severity);
      }

      for (const result of runResults) {
        results += 1;
        const ruleId = result?.ruleId ?? result?.rule?.id;
        if (typeof ruleId !== "string" || !severityByRuleId.has(ruleId)) {
          throw new Error("CodeQL SARIF result has no classified security severity");
        }
        const severity = severityByRuleId.get(ruleId);
        maximumSecuritySeverity = Math.max(maximumSecuritySeverity, severity);
        if (severity >= HIGH_SECURITY_SEVERITY) highOrCriticalResults += 1;
      }
    }
  }

  if (highOrCriticalResults) {
    throw new Error("CodeQL SARIF contains high or critical security results");
  }

  return {
    files: sarifFiles.length,
    highOrCriticalResults,
    maximumSecuritySeverity,
    results,
    runs,
    schema: "vasi-codeql-sarif-verification/v1",
    status: "pass",
  };
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  if (process.argv.length !== 3) {
    console.error("Usage: node scripts/verify-codeql-sarif.mjs ABSOLUTE_SARIF_DIRECTORY");
    process.exitCode = 1;
  } else {
    verifyCodeQLSarifDirectory(process.argv[2])
      .then((result) => console.info(JSON.stringify(result)))
      .catch(() => {
        console.error("VASI CodeQL SARIF verification failed.");
        process.exitCode = 1;
      });
  }
}
