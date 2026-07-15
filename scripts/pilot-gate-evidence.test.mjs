import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  PILOT_GATE_CHECKLISTS,
  PILOT_GATE_DESCRIPTOR_SCHEMA,
  pilotGateDescriptorJSON,
} from "../packages/pilot-gate-evidence/index.mjs";
import { runPilotGateEvidence } from "./pilot-gate-evidence.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "scripts", "pilot-gate-evidence.mjs");
const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("pilot-gate evidence CLI", () => {
  it("creates and independently verifies an aggregate-only package result", async () => {
    const fixture = await createFixture();
    const created = runCLI([
      "create", fixture.descriptorFile, fixture.evidenceDirectory, fixture.manifestFile,
    ]);
    expect(created.status).toBe(0);
    expect(created.stderr).toBe("");
    const creation = JSON.parse(created.stdout);
    expect(creation).toMatchObject({ artifacts: 1, checklistItems: 5, status: "pass" });
    expect(created.stdout).not.toContain("assessment.json");

    const verified = runCLI([
      "verify", fixture.manifestFile, fixture.evidenceDirectory,
      "--expected-sha256", creation.packageSha256,
    ]);
    expect(verified.status).toBe(0);
    expect(JSON.parse(verified.stdout)).toEqual({ ...creation, expectedDigest: "matched" });
    await expect(runPilotGateEvidence([
      "verify", fixture.manifestFile, fixture.evidenceDirectory,
      "--expected-sha256", creation.packageSha256,
    ])).resolves.toMatchObject({ expectedDigest: "matched", status: "pass" });
  });

  it("uses one generic operational failure without disclosing inputs", async () => {
    const fixture = await createFixture();
    await chmod(fixture.descriptorFile, 0o640);
    const result = runCLI([
      "create", fixture.descriptorFile, fixture.evidenceDirectory, fixture.manifestFile,
    ]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("VASI pilot-gate evidence operation failed.\n");
    expect(result.stderr).not.toContain(fixture.root);
    await expect(readFile(fixture.manifestFile)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("is import-safe and executes through a selected-release path", async () => {
    const imported = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(cli).href)});`,
    ], { encoding: "utf8", timeout: 5_000 });
    expect(imported).toMatchObject({ status: 0, stderr: "", stdout: "" });

    const fixture = await createFixture();
    const selector = path.join(fixture.root, "current");
    await symlink(root, selector, "dir");
    const selectedCLI = path.join(selector, "scripts", "pilot-gate-evidence.mjs");
    const usage = spawnSync(process.execPath, [selectedCLI], { encoding: "utf8", timeout: 5_000 });
    expect(usage.status).toBe(1);
    expect(usage.stdout).toBe("");
    expect(usage.stderr).toContain("Usage: node scripts/pilot-gate-evidence.mjs create");
  });
});

async function createFixture() {
  const temporary = await realpath(await mkdtemp(path.join(tmpdir(), "vasi-pilot-gate-cli-")));
  temporaryDirectories.push(temporary);
  await chmod(temporary, 0o700);
  const descriptorDirectory = path.join(temporary, "descriptor");
  const evidenceDirectory = path.join(temporary, "evidence");
  const outputDirectory = path.join(temporary, "output");
  for (const directory of [descriptorDirectory, evidenceDirectory, outputDirectory]) {
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
  }
  const descriptor = {
    artifacts: [{ id: "assessment", mediaType: "application/json", path: "assessment.json" }],
    checklist: PILOT_GATE_CHECKLISTS.exact_release.map((id) => ({
      artifactIds: ["assessment"],
      exceptionReference: null,
      id,
      outcome: "satisfied",
    })),
    evidenceReference: "review-package:release-001",
    gateId: "exact_release",
    reviewedAt: "2026-07-15T20:00:00.000Z",
    reviewerReference: "reviewer:release-owner-001",
    schema: PILOT_GATE_DESCRIPTOR_SCHEMA,
    scopeReference: "scope:release-001",
  };
  const descriptorFile = path.join(descriptorDirectory, "descriptor.json");
  const manifestFile = path.join(outputDirectory, "manifest.json");
  await writeFile(descriptorFile, pilotGateDescriptorJSON(descriptor), { mode: 0o600 });
  await writeFile(
    path.join(evidenceDirectory, "assessment.json"),
    "{\"assurance\":\"passed\"}\n",
    { mode: 0o600 },
  );
  return { descriptorFile, evidenceDirectory, manifestFile, root: temporary };
}

function runCLI(argumentsList) {
  return spawnSync(process.execPath, [cli, ...argumentsList], {
    encoding: "utf8",
    timeout: 5_000,
  });
}
