import { spawnSync } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { readinessExportJSON } from "../packages/readiness-dossier/index.mjs";
import { createReadinessExportFixture } from "../packages/readiness-dossier/test-fixture.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const verifier = path.join(root, "scripts", "verify-readiness-dossier.mjs");
const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("readiness dossier verifier CLI", () => {
  it("runs through physical and selected-release paths with privacy-bounded output", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-readiness-cli-"));
    temporaryDirectories.push(temporary);
    const file = path.join(temporary, "dossier.json");
    const selector = path.join(temporary, "current");
    const exported = createReadinessExportFixture("json");
    await writeFile(file, readinessExportJSON(exported), { mode: 0o600 });
    await symlink(root, selector, "dir");

    for (const entrypoint of [verifier, path.join(selector, "scripts", "verify-readiness-dossier.mjs")]) {
      const result = spawnSync(process.execPath, [
        entrypoint, file, "--expected-sha256", exported.dossierHash,
      ], { encoding: "utf8", timeout: 5_000 });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual(expect.objectContaining({
        dossierSha256: exported.dossierHash,
        expectedDigest: "matched",
        schema: "vasi-readiness-dossier-verification/v1",
        status: "pass",
      }));
      expect(result.stdout).not.toContain(exported.dossier.tenant.name);
      expect(result.stdout).not.toContain(exported.dossier.tenant.id);
      expect(result.stderr).toBe("");
    }
  });

  it("fails with one generic error and no exported facts", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "vasi-readiness-cli-fail-"));
    temporaryDirectories.push(temporary);
    const file = path.join(temporary, "dossier.json");
    const exported = createReadinessExportFixture("json");
    const text = readinessExportJSON(exported).replace("Example Company", "Private Changed Company");
    await writeFile(file, text, { mode: 0o600 });
    const result = spawnSync(process.execPath, [verifier, file], { encoding: "utf8", timeout: 5_000 });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr.trim()).toBe("VASI readiness dossier verification failed.");
    expect(result.stderr).not.toContain("Private Changed Company");
    expect(result.stderr).not.toContain(exported.dossier.tenant.id);
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
