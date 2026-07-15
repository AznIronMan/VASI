import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { verifyPilotGateManifestText } from "../../src/lib/pilot-gate-manifest-import.ts";
import {
  createPilotGateEvidenceManifest,
  PILOT_GATE_CHECKLISTS,
  PILOT_GATE_DESCRIPTOR_SCHEMA,
  pilotGateManifestJSON,
} from "./index.mjs";

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) =>
    rm(directory, { force: true, recursive: true })
  ));
});

describe("pilot-gate evidence browser interoperability", () => {
  it("accepts an exact offline-library manifest through the browser-local verifier", async () => {
    const root = await realpath(await mkdtemp(path.join(tmpdir(), "vasi-pilot-gate-browser-")));
    temporaryDirectories.push(root);
    const evidenceDirectory = path.join(root, "evidence");
    await mkdir(evidenceDirectory, { mode: 0o700 });
    await writeFile(path.join(evidenceDirectory, "release.txt"), "exact release evidence\n", { mode: 0o600 });
    const manifest = await createPilotGateEvidenceManifest({
      artifacts: [{ id: "release", mediaType: "text/plain", path: "release.txt" }],
      checklist: PILOT_GATE_CHECKLISTS.exact_release.map((id) => ({
        artifactIds: ["release"],
        exceptionReference: null,
        id,
        outcome: "satisfied",
      })),
      evidenceReference: "evidence:release-001",
      gateId: "exact_release",
      reviewedAt: "2026-07-15T20:00:00.000Z",
      reviewerReference: "reviewer:release-owner-001",
      schema: PILOT_GATE_DESCRIPTOR_SCHEMA,
      scopeReference: "scope:release-001",
    }, evidenceDirectory);

    await expect(verifyPilotGateManifestText(
      pilotGateManifestJSON(manifest),
      "exact_release",
    )).resolves.toMatchObject({
      approval: {
        evidenceDigest: manifest.packageDigest,
        evidenceReference: "evidence:release-001",
        reviewerReference: "reviewer:release-owner-001",
      },
      artifacts: 1,
      checklistItems: 5,
      exceptions: 0,
      gateId: "exact_release",
      packageSha256: manifest.packageDigest,
    });
  });
});
