import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createPilotGateEvidenceManifest,
  createPilotGateEvidenceManifestFile,
  MAXIMUM_PILOT_GATE_ARTIFACT_BYTES,
  PILOT_GATE_CHECKLISTS,
  PILOT_GATE_DESCRIPTOR_SCHEMA,
  PilotGateEvidenceError,
  pilotGateAdmissionEvidence,
  pilotGateDescriptorJSON,
  validatePilotGateDescriptor,
  validatePilotGateManifest,
  verifyPilotGateEvidenceManifest,
  verifyPilotGateEvidenceManifestFile,
} from "./index.mjs";

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("pilot-gate evidence packages", () => {
  it("creates deterministic canonical manifests and verifies aggregate results", async () => {
    const fixture = await createFixture("isolation_integrity");
    const secondOutputDirectory = path.join(fixture.root, "output-second");
    const secondManifestFile = path.join(secondOutputDirectory, "manifest.json");
    await privateDirectory(secondOutputDirectory);

    const first = await createPilotGateEvidenceManifestFile(
      fixture.descriptorFile,
      fixture.evidenceDirectory,
      fixture.manifestFile,
    );
    const second = await createPilotGateEvidenceManifestFile(
      fixture.descriptorFile,
      fixture.evidenceDirectory,
      secondManifestFile,
    );
    const manifest = JSON.parse(await readFile(fixture.manifestFile, "utf8"));

    expect(await readFile(fixture.manifestFile)).toEqual(await readFile(secondManifestFile));
    expect(second).toEqual(first);
    expect(first).toEqual({
      artifacts: 2,
      checklistItems: 4,
      exceptions: 0,
      expectedDigest: "not_supplied",
      gateId: "isolation_integrity",
      packageSha256: manifest.packageDigest,
      schema: "vasi-pilot-gate-evidence-verification/v1",
      status: "pass",
      totalBytes: 38,
    });
    await expect(verifyPilotGateEvidenceManifestFile(
      fixture.manifestFile,
      fixture.evidenceDirectory,
      { expectedDigest: manifest.packageDigest },
    )).resolves.toEqual({ ...first, expectedDigest: "matched" });
    expect(pilotGateAdmissionEvidence(manifest)).toEqual({
      evidenceDigest: manifest.packageDigest,
      evidenceReference: "review-package:2026-07-15",
      reviewerReference: "reviewer:independent-001",
    });
  });

  it("defines a complete, closed checklist contract for every admission gate", () => {
    for (const gateId of Object.keys(PILOT_GATE_CHECKLISTS)) {
      const descriptor = descriptorFixture(gateId, {
        artifacts: [{ id: "review", mediaType: "text/plain", path: "review.txt" }],
      });
      expect(validatePilotGateDescriptor(descriptor)).toEqual(descriptor);
      expect(descriptor.checklist.map(({ id }) => id)).toEqual(PILOT_GATE_CHECKLISTS[gateId]);
    }
  });

  it("records accepted exceptions without exposing their records", async () => {
    const fixture = await createFixture("privacy_legal", {
      exceptionIndex: 3,
    });
    const manifest = await createPilotGateEvidenceManifest(
      fixture.descriptor,
      fixture.evidenceDirectory,
    );
    const result = await verifyPilotGateEvidenceManifest(manifest, fixture.evidenceDirectory);
    expect(result).toMatchObject({ exceptions: 1, status: "pass" });
    expect(JSON.stringify(result)).not.toContain("exception:retention-review-001");
  });

  it("rejects malformed descriptors and incomplete or misleading checklist assertions", () => {
    const valid = descriptorFixture("privacy_legal");
    const mutations = [
      (value) => { value.unknown = true; },
      (value) => { value.schema = "vasi-pilot-gate-evidence-descriptor/v2"; },
      (value) => { value.gateId = "unknown"; },
      (value) => { value.reviewedAt = "2026-07-15"; },
      (value) => { value.scopeReference = "https://example.test/scope"; },
      (value) => { value.artifacts.reverse(); },
      (value) => { value.artifacts[1].id = value.artifacts[0].id; },
      (value) => { value.artifacts[1].path = value.artifacts[0].path; },
      (value) => { value.artifacts[0].mediaType = "image/png"; },
      (value) => { value.artifacts[0].path = "../assessment.json"; },
      (value) => { value.artifacts[0].path = "customer-secret.json"; },
      (value) => { value.artifacts[0].path = "assessment.txt"; },
      (value) => { value.checklist.pop(); },
      (value) => { value.checklist.reverse(); },
      (value) => { value.checklist[0].artifactIds = ["missing"]; },
      (value) => { value.checklist[0].artifactIds = ["review", "assessment"]; },
      (value) => { value.checklist[0].artifactIds = ["assessment", "assessment"]; },
      (value) => { value.checklist[0].outcome = "failed"; },
      (value) => { value.checklist[0].exceptionReference = "exception:unexpected"; },
      (value) => {
        value.checklist[0].outcome = "accepted_exception";
        value.checklist[0].exceptionReference = null;
      },
      (value) => {
        value.checklist.forEach((item) => { item.artifactIds = ["assessment"]; });
      },
    ];

    for (const mutate of mutations) {
      const changed = structuredClone(valid);
      mutate(changed);
      expectFailure(() => validatePilotGateDescriptor(changed));
    }
  });

  it("rejects manifest field, digest, expected-digest, and artifact-content tampering", async () => {
    const fixture = await createFixture("accessibility");
    await createPilotGateEvidenceManifestFile(
      fixture.descriptorFile,
      fixture.evidenceDirectory,
      fixture.manifestFile,
    );
    const manifest = JSON.parse(await readFile(fixture.manifestFile, "utf8"));

    for (const mutate of [
      (value) => { value.packageDigest = "0".repeat(64); },
      (value) => { value.artifacts[0].sha256 = "0".repeat(64); },
      (value) => { value.artifacts[0].bytes += 1; },
      (value) => { value.limitations[0] = "Certified by VASI."; },
      (value) => { value.unknown = true; },
    ]) {
      const changed = structuredClone(manifest);
      mutate(changed);
      expectFailure(() => validatePilotGateManifest(changed));
    }
    await expect(verifyPilotGateEvidenceManifest(
      manifest,
      fixture.evidenceDirectory,
      { expectedDigest: "0".repeat(64) },
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);

    await writeFile(
      path.join(fixture.evidenceDirectory, "assessment.json"),
      "{\"finding\":\"changed\"}\n",
      { mode: 0o600 },
    );
    await expect(verifyPilotGateEvidenceManifest(manifest, fixture.evidenceDirectory))
      .rejects.toBeInstanceOf(PilotGateEvidenceError);
  });

  it("requires exact canonical descriptor and manifest presentation", async () => {
    const fixture = await createFixture("capacity_support");
    await writeFile(
      fixture.descriptorFile,
      pilotGateDescriptorJSON(fixture.descriptor).replace("\n", "\r\n"),
      { mode: 0o600 },
    );
    await expect(createPilotGateEvidenceManifestFile(
      fixture.descriptorFile,
      fixture.evidenceDirectory,
      fixture.manifestFile,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);

    await writeFile(fixture.descriptorFile, pilotGateDescriptorJSON(fixture.descriptor), { mode: 0o600 });
    await createPilotGateEvidenceManifestFile(
      fixture.descriptorFile,
      fixture.evidenceDirectory,
      fixture.manifestFile,
    );
    const canonical = await readFile(fixture.manifestFile, "utf8");
    await writeFile(fixture.manifestFile, canonical.replace("\n", "\r\n"), { mode: 0o600 });
    await expect(verifyPilotGateEvidenceManifestFile(
      fixture.manifestFile,
      fixture.evidenceDirectory,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);
  });

  it("rejects extra, linked, permissive, oversized, and overlapping filesystem inputs", async () => {
    await expectFilesystemFailure(async (fixture) => {
      await writeFile(path.join(fixture.evidenceDirectory, "extra.txt"), "extra\n", { mode: 0o600 });
    });
    await expectFilesystemFailure(async (fixture) => {
      const target = path.join(fixture.root, "outside.json");
      await writeFile(target, "{}\n", { mode: 0o600 });
      await rm(path.join(fixture.evidenceDirectory, "assessment.json"));
      await symlink(target, path.join(fixture.evidenceDirectory, "assessment.json"));
    });
    await expectFilesystemFailure(async (fixture) => {
      const artifact = path.join(fixture.evidenceDirectory, "assessment.json");
      const target = path.join(fixture.root, "hardlink.json");
      await link(artifact, target);
    });
    await expectFilesystemFailure(async (fixture) => {
      await chmod(path.join(fixture.evidenceDirectory, "assessment.json"), 0o640);
    });
    await expectFilesystemFailure(async (fixture) => {
      await chmod(fixture.evidenceDirectory, 0o750);
    });
    await expectFilesystemFailure(async (fixture) => {
      await truncate(
        path.join(fixture.evidenceDirectory, "assessment.json"),
        MAXIMUM_PILOT_GATE_ARTIFACT_BYTES + 1,
      );
    });

    const descriptorLinkFixture = await createFixture("exact_release");
    const descriptorLink = path.join(descriptorLinkFixture.descriptorDirectory, "descriptor-link.json");
    await symlink(descriptorLinkFixture.descriptorFile, descriptorLink);
    await expect(createPilotGateEvidenceManifestFile(
      descriptorLink,
      descriptorLinkFixture.evidenceDirectory,
      descriptorLinkFixture.manifestFile,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);

    const descriptorModeFixture = await createFixture("exact_release");
    await chmod(descriptorModeFixture.descriptorDirectory, 0o750);
    await expect(createPilotGateEvidenceManifestFile(
      descriptorModeFixture.descriptorFile,
      descriptorModeFixture.evidenceDirectory,
      descriptorModeFixture.manifestFile,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);

    const outputModeFixture = await createFixture("exact_release");
    await chmod(outputModeFixture.outputDirectory, 0o750);
    await expect(createPilotGateEvidenceManifestFile(
      outputModeFixture.descriptorFile,
      outputModeFixture.evidenceDirectory,
      outputModeFixture.manifestFile,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);

    const outputFixture = await createFixture("exact_release");
    await writeFile(outputFixture.manifestFile, "occupied\n", { mode: 0o600 });
    await expect(createPilotGateEvidenceManifestFile(
      outputFixture.descriptorFile,
      outputFixture.evidenceDirectory,
      outputFixture.manifestFile,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);
    await expect(createPilotGateEvidenceManifestFile(
      outputFixture.descriptorFile,
      outputFixture.evidenceDirectory,
      path.join(outputFixture.evidenceDirectory, "manifest.json"),
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);

    const manifestLinkFixture = await createFixture("exact_release");
    await createPilotGateEvidenceManifestFile(
      manifestLinkFixture.descriptorFile,
      manifestLinkFixture.evidenceDirectory,
      manifestLinkFixture.manifestFile,
    );
    const manifestLink = path.join(manifestLinkFixture.outputDirectory, "manifest-link.json");
    await symlink(manifestLinkFixture.manifestFile, manifestLink);
    await expect(verifyPilotGateEvidenceManifestFile(
      manifestLink,
      manifestLinkFixture.evidenceDirectory,
    )).rejects.toBeInstanceOf(PilotGateEvidenceError);
  });
});

async function createFixture(gateId, { exceptionIndex = -1 } = {}) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "vasi-pilot-gate-evidence-")));
  temporaryDirectories.push(root);
  await chmod(root, 0o700);
  const descriptorDirectory = path.join(root, "descriptor");
  const evidenceDirectory = path.join(root, "evidence");
  const outputDirectory = path.join(root, "output");
  await Promise.all([
    privateDirectory(descriptorDirectory),
    privateDirectory(evidenceDirectory),
    privateDirectory(outputDirectory),
  ]);
  const descriptor = descriptorFixture(gateId, { exceptionIndex });
  const descriptorFile = path.join(descriptorDirectory, "descriptor.json");
  const manifestFile = path.join(outputDirectory, "manifest.json");
  await Promise.all([
    writeFile(descriptorFile, pilotGateDescriptorJSON(descriptor), { mode: 0o600 }),
    writeFile(path.join(evidenceDirectory, "assessment.json"), "{\"result\":\"reviewed\"}\n", { mode: 0o600 }),
    writeFile(path.join(evidenceDirectory, "review.txt"), "review complete\n", { mode: 0o600 }),
  ]);
  return {
    descriptor,
    descriptorDirectory,
    descriptorFile,
    evidenceDirectory,
    manifestFile,
    outputDirectory,
    root,
  };
}

function descriptorFixture(gateId, { artifacts, exceptionIndex = -1 } = {}) {
  const normalizedArtifacts = artifacts ?? [
    { id: "assessment", mediaType: "application/json", path: "assessment.json" },
    { id: "review", mediaType: "text/plain", path: "review.txt" },
  ];
  return {
    artifacts: normalizedArtifacts,
    checklist: PILOT_GATE_CHECKLISTS[gateId].map((id, index) => ({
      artifactIds: normalizedArtifacts.map((artifact) => artifact.id),
      exceptionReference: index === exceptionIndex ? "exception:retention-review-001" : null,
      id,
      outcome: index === exceptionIndex ? "accepted_exception" : "satisfied",
    })),
    evidenceReference: "review-package:2026-07-15",
    gateId,
    reviewedAt: "2026-07-15T20:00:00.000Z",
    reviewerReference: "reviewer:independent-001",
    schema: PILOT_GATE_DESCRIPTOR_SCHEMA,
    scopeReference: "scope:pilot-release-001",
  };
}

async function expectFilesystemFailure(mutate) {
  const fixture = await createFixture("exact_release");
  await mutate(fixture);
  await expect(createPilotGateEvidenceManifestFile(
    fixture.descriptorFile,
    fixture.evidenceDirectory,
    fixture.manifestFile,
  )).rejects.toBeInstanceOf(PilotGateEvidenceError);
  await expect(readFile(fixture.manifestFile)).rejects.toMatchObject({ code: "ENOENT" });
}

async function privateDirectory(directory) {
  await mkdir(directory, { mode: 0o700 });
  await chmod(directory, 0o700);
}

function expectFailure(operation) {
  expect(operation).toThrow(PilotGateEvidenceError);
}
