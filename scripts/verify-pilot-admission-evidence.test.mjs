import { spawnSync } from "node:child_process";
import { rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { createPilotAdmissionEvidenceFixture } from "../packages/pilot-admission-evidence/test-fixture.mjs";
import { runPilotAdmissionEvidenceVerification } from "./verify-pilot-admission-evidence.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "scripts", "verify-pilot-admission-evidence.mjs");
const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("pilot-admission evidence CLI", () => {
  it("verifies complete artifacts through physical and selected-release paths with aggregate-only output", async () => {
    const fixture = await trackedFixture();
    const selector = path.join(fixture.root, "current");
    await symlink(root, selector, "dir");
    const argumentsList = [
      fixture.dossierFile,
      fixture.manifestDirectory,
      "--artifact-root",
      fixture.artifactDirectoryRoot,
      "--expected-sha256",
      fixture.exported.dossierHash,
      "--expected-key-fingerprint",
      fixture.exported.attestation.signingKeys[0].fingerprint,
    ];

    for (const entrypoint of [cli, path.join(selector, "scripts", "verify-pilot-admission-evidence.mjs")]) {
      const result = spawnSync(process.execPath, [entrypoint, ...argumentsList], {
        encoding: "utf8",
        timeout: 5_000,
      });
      expect(result).toMatchObject({ status: 0, stderr: "" });
      expect(JSON.parse(result.stdout)).toMatchObject({
        admissionEvidence: "matched",
        artifactBytes: 208,
        artifacts: 8,
        artifactVerification: "matched",
        evidencePackages: 8,
        expectedDigest: "matched",
        expectedKeyFingerprint: "matched",
        status: "pass",
      });
      expect(result.stdout).not.toContain(fixture.exported.dossier.tenant.name);
      expect(result.stdout).not.toContain("review-package:");
      expect(result.stdout).not.toContain("assessment.json");
      expect(result.stdout).not.toContain(fixture.root);
    }
    await expect(runPilotAdmissionEvidenceVerification(argumentsList)).resolves.toMatchObject({
      admissionEvidence: "matched",
      artifactVerification: "matched",
      status: "pass",
    });

    await expect(runPilotAdmissionEvidenceVerification([
      fixture.dossierFile,
      fixture.manifestDirectory,
    ])).resolves.toMatchObject({
      artifactVerification: "not_performed",
      schema: "vasi-pilot-admission-evidence-verification/v1",
      status: "pass",
    });
  });

  it("fails with one generic message and no dossier or evidence facts", async () => {
    const fixture = await trackedFixture();
    const result = spawnSync(process.execPath, [
      cli,
      fixture.dossierFile,
      fixture.manifestDirectory,
      "--expected-key-fingerprint",
      "0".repeat(64),
    ], { encoding: "utf8", timeout: 5_000 });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("VASI pilot-admission evidence verification failed.\n");
    expect(result.stderr).not.toContain(fixture.root);
    expect(result.stderr).not.toContain(fixture.exported.dossier.tenant.name);
    expect(result.stderr).not.toContain(fixture.exported.attestation.signingKeys[0].fingerprint);

    const artifactFile = path.join(
      fixture.artifactDirectoryRoot,
      "exact_release",
      "assessment.json",
    );
    await writeFile(artifactFile, "{\"assessment\":\"changed\"}\n", { mode: 0o600 });
    const artifactFailure = spawnSync(process.execPath, [
      cli,
      fixture.dossierFile,
      fixture.manifestDirectory,
      "--artifact-root",
      fixture.artifactDirectoryRoot,
    ], { encoding: "utf8", timeout: 5_000 });
    expect(artifactFailure.status).toBe(1);
    expect(artifactFailure.stdout).toBe("");
    expect(artifactFailure.stderr).toBe("VASI pilot-admission evidence verification failed.\n");
    expect(artifactFailure.stderr).not.toContain(fixture.root);
    expect(artifactFailure.stderr).not.toContain("assessment.json");
  });

  it("remains import-safe and rejects malformed or duplicate options", async () => {
    const imported = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(cli).href)});`,
    ], { encoding: "utf8", timeout: 5_000 });
    expect(imported).toMatchObject({ status: 0, stderr: "", stdout: "" });

    const usage = spawnSync(process.execPath, [cli], { encoding: "utf8", timeout: 5_000 });
    expect(usage.status).toBe(1);
    expect(usage.stdout).toBe("");
    expect(usage.stderr).toContain("Usage: node scripts/verify-pilot-admission-evidence.mjs");

    const fixture = await trackedFixture();
    await expect(runPilotAdmissionEvidenceVerification([
      fixture.dossierFile,
      fixture.manifestDirectory,
      "--expected-sha256",
      fixture.exported.dossierHash,
      "--expected-sha256",
      fixture.exported.dossierHash,
    ])).rejects.toThrow(/^Usage:/);
  });
});

async function trackedFixture(options) {
  const fixture = await createPilotAdmissionEvidenceFixture(options);
  temporaryDirectories.push(fixture.root);
  return fixture;
}
