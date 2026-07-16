import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { verifyCodeQLSarifDirectory } from "./verify-codeql-sarif.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const verifier = path.join(root, "scripts", "verify-codeql-sarif.mjs");
const temporaryDirectories = [];

function codeQLSarif(severity = "6.5", results = [{ ruleId: "js/example" }]) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "CodeQL",
          rules: [{
            id: "js/example",
            properties: { "security-severity": severity },
          }],
        },
      },
      results,
    }],
  };
}

async function sarifDirectory(sarif = codeQLSarif()) {
  const directory = await mkdtemp(path.join(tmpdir(), "vasi-codeql-sarif-"));
  temporaryDirectories.push(directory);
  await writeFile(path.join(directory, "javascript.sarif"), JSON.stringify(sarif), { mode: 0o600 });
  return directory;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("CodeQL SARIF verifier", () => {
  it("accepts only classified findings below high severity", async () => {
    const directory = await sarifDirectory();
    await expect(verifyCodeQLSarifDirectory(directory)).resolves.toEqual({
      files: 1,
      highOrCriticalResults: 0,
      maximumSecuritySeverity: 6.5,
      results: 1,
      runs: 1,
      schema: "vasi-codeql-sarif-verification/v1",
      status: "pass",
    });
  });

  it.each(["7.0", 9.8])("rejects a security severity of %s", async (severity) => {
    const directory = await sarifDirectory(codeQLSarif(severity));
    await expect(verifyCodeQLSarifDirectory(directory)).rejects.toThrow(
      "CodeQL SARIF contains high or critical security results",
    );
  });

  it("rejects unclassified, malformed, and unexpected inputs", async () => {
    const unclassifiedSarif = codeQLSarif();
    delete unclassifiedSarif.runs[0].tool.driver.rules[0].properties["security-severity"];
    const unclassified = await sarifDirectory(unclassifiedSarif);
    await expect(verifyCodeQLSarifDirectory(unclassified)).rejects.toThrow(
      "CodeQL SARIF result has no classified security severity",
    );

    const malformed = await sarifDirectory();
    await writeFile(path.join(malformed, "javascript.sarif"), "not-json", { mode: 0o600 });
    await expect(verifyCodeQLSarifDirectory(malformed)).rejects.toThrow(
      "CodeQL SARIF input is not valid JSON",
    );

    const unexpected = await sarifDirectory();
    await writeFile(path.join(unexpected, "extra.txt"), "unexpected", { mode: 0o600 });
    await expect(verifyCodeQLSarifDirectory(unexpected)).rejects.toThrow(
      "CodeQL SARIF directory contains an unexpected file",
    );
  });

  it("rejects symlinked directories and files", async () => {
    const physical = await sarifDirectory();
    const parent = await mkdtemp(path.join(tmpdir(), "vasi-codeql-links-"));
    temporaryDirectories.push(parent);
    const linkedDirectory = path.join(parent, "linked-directory");
    await symlink(physical, linkedDirectory, "dir");
    await expect(verifyCodeQLSarifDirectory(linkedDirectory)).rejects.toThrow(
      "CodeQL SARIF input must be a physical directory",
    );

    const linkedFileDirectory = path.join(parent, "linked-file-directory");
    await mkdir(linkedFileDirectory);
    await symlink(path.join(physical, "javascript.sarif"), path.join(linkedFileDirectory, "javascript.sarif"));
    await expect(verifyCodeQLSarifDirectory(linkedFileDirectory)).rejects.toThrow(
      "CodeQL SARIF directory contains an unsupported entry",
    );
  });

  it("emits only aggregate facts on success and a generic error on failure", async () => {
    const clean = await sarifDirectory(codeQLSarif("0.0", []));
    const success = spawnSync(process.execPath, [verifier, clean], { encoding: "utf8", timeout: 5_000 });
    expect(success.status).toBe(0);
    expect(JSON.parse(success.stdout)).toEqual(expect.objectContaining({
      highOrCriticalResults: 0,
      schema: "vasi-codeql-sarif-verification/v1",
      status: "pass",
    }));
    expect(success.stdout).not.toContain("js/example");
    expect(success.stderr).toBe("");

    const high = await sarifDirectory(codeQLSarif("7.0"));
    const failure = spawnSync(process.execPath, [verifier, high], { encoding: "utf8", timeout: 5_000 });
    expect(failure.status).toBe(1);
    expect(failure.stdout).toBe("");
    expect(failure.stderr.trim()).toBe("VASI CodeQL SARIF verification failed.");
    expect(failure.stderr).not.toContain("js/example");
  });

  it("remains import-safe", () => {
    const result = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(verifier).href)});`,
    ], { encoding: "utf8", timeout: 5_000 });
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });
});
