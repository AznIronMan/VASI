import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import pilotGateContract from "../../config/pilot-gate-evidence-contract.json";

import {
  PilotGateManifestImportError,
  verifyPilotGateManifestFile,
  verifyPilotGateManifestText,
} from "@/lib/pilot-gate-manifest-import";
import type { TenantAdmissionGateId } from "@/lib/owner-types";

describe("browser-local pilot-gate manifest import", () => {
  it("verifies the shared canonical contract and returns admission fields plus aggregates only", async () => {
    const manifest = await manifestFixture("privacy_legal", { exceptionIndex: 3 });
    const result = await verifyPilotGateManifestText(canonicalJSON(manifest), "privacy_legal");

    expect(result).toEqual({
      approval: {
        evidenceDigest: manifest.packageDigest,
        evidenceReference: "review-package:2026-07-15",
        reviewerReference: "reviewer:independent-001",
      },
      artifacts: 2,
      checklistItems: 6,
      exceptions: 1,
      gateId: "privacy_legal",
      packageSha256: manifest.packageDigest,
      reviewedAt: "2026-07-15T20:00:00.000Z",
      totalBytes: 38,
    });
    const disclosed = JSON.stringify(result);
    for (const privateValue of [
      "assessment.json",
      "review.txt",
      "exception:accepted-001",
      "scope:pilot-001",
    ]) expect(disclosed).not.toContain(privateValue);
  });

  it("rejects a manifest for a different admission gate", async () => {
    const manifest = await manifestFixture("accessibility");
    await expectFailure(canonicalJSON(manifest), "privacy_legal");
  });

  it("rejects structural, checklist, limitation, reference, and digest tampering", async () => {
    const valid = await manifestFixture("identity_delivery");
    const mutations: Array<(value: Record<string, unknown>) => void> = [
      (value) => { value.schema = "vasi-pilot-gate-evidence-manifest/v2"; },
      (value) => { value.unknown = true; },
      (value) => { (value.limitations as string[])[0] = "VASI approved this gate."; },
      (value) => { value.reviewerReference = "https://reviewer.example.test"; },
      (value) => { value.reviewedAt = "2026-07-15"; },
      (value) => { (value.artifacts as Array<Record<string, unknown>>)[0].bytes = 0; },
      (value) => { (value.artifacts as Array<Record<string, unknown>>)[0].sha256 = "A".repeat(64); },
      (value) => { (value.artifacts as Array<Record<string, unknown>>)[0].path = "customer-secret.json"; },
      (value) => { (value.artifacts as Array<Record<string, unknown>>).reverse(); },
      (value) => { (value.artifacts as Array<Record<string, unknown>>)[1].id = "assessment"; },
      (value) => { (value.checklist as unknown[]).pop(); },
      (value) => { (value.checklist as unknown[]).reverse(); },
      (value) => {
        (value.checklist as Array<Record<string, unknown>>)[0].artifactIds = ["missing"];
      },
      (value) => {
        (value.checklist as Array<Record<string, unknown>>)[0].outcome = "failed";
      },
      (value) => {
        (value.checklist as Array<Record<string, unknown>>)[0].exceptionReference = "exception:unexpected";
      },
      (value) => {
        (value.checklist as Array<Record<string, unknown>>).forEach((item) => {
          item.artifactIds = ["assessment"];
        });
      },
    ];

    for (const mutate of mutations) {
      const changed = structuredClone(valid) as unknown as Record<string, unknown>;
      mutate(changed);
      await expectFailure(await resign(changed), "identity_delivery");
    }

    const digestTamper = structuredClone(valid);
    digestTamper.packageDigest = "0".repeat(64);
    await expectFailure(canonicalJSON(digestTamper), "identity_delivery");
  });

  it("requires exact canonical JSON presentation", async () => {
    const manifest = await manifestFixture("capacity_support");
    const canonical = canonicalJSON(manifest);
    await expectFailure(canonical.replace("\n", "\r\n"), "capacity_support");
    await expectFailure(JSON.stringify(manifest), "capacity_support");
    await expectFailure(`${canonical} `, "capacity_support");
  });

  it("reads one bounded strict-UTF-8 local file without using its name", async () => {
    const manifest = await manifestFixture("exact_release");
    const bytes = new TextEncoder().encode(canonicalJSON(manifest));
    const result = await verifyPilotGateManifestFile({
      arrayBuffer: async () => bytes.slice().buffer,
      size: bytes.byteLength,
    }, "exact_release");
    expect(result.packageSha256).toBe(manifest.packageDigest);

    let oversizedRead = false;
    await expect(verifyPilotGateManifestFile({
      arrayBuffer: async () => {
        oversizedRead = true;
        return new ArrayBuffer(0);
      },
      size: pilotGateContract.limits.manifestBytes + 1,
    }, "exact_release")).rejects.toEqual(new PilotGateManifestImportError());
    expect(oversizedRead).toBe(false);

    for (const file of [
      { arrayBuffer: async () => new Uint8Array([0xc3, 0x28]).buffer, size: 2 },
      { arrayBuffer: async () => new Uint8Array([0x7b]).buffer, size: 2 },
      { arrayBuffer: async () => new TextEncoder().encode("{}\0\n").buffer, size: 4 },
    ]) {
      await expect(verifyPilotGateManifestFile(file, "exact_release"))
        .rejects.toEqual(new PilotGateManifestImportError());
    }
  });

  it("uses one generic failure for every rejected local input", async () => {
    for (const text of ["", "{}\n", "not-json\n", "{\"packageDigest\":\"secret\"}\n"]) {
      await expect(verifyPilotGateManifestText(text, "exact_release"))
        .rejects.toEqual(new PilotGateManifestImportError());
    }
  });
});

async function manifestFixture(
  gateId: TenantAdmissionGateId,
  { exceptionIndex = -1 } = {},
) {
  const checklist = pilotGateContract.checklists[gateId].map((id, index) => ({
    artifactIds: ["assessment", "review"],
    exceptionReference: index === exceptionIndex ? "exception:accepted-001" : null,
    id,
    outcome: index === exceptionIndex ? "accepted_exception" : "satisfied",
  }));
  return JSON.parse(await resign({
    artifacts: [
      {
        bytes: 20,
        id: "assessment",
        mediaType: "application/json",
        path: "assessment.json",
        sha256: "1".repeat(64),
      },
      {
        bytes: 18,
        id: "review",
        mediaType: "text/plain",
        path: "review.txt",
        sha256: "2".repeat(64),
      },
    ],
    checklist,
    evidenceReference: "review-package:2026-07-15",
    gateId,
    limitations: pilotGateContract.limitations,
    reviewedAt: "2026-07-15T20:00:00.000Z",
    reviewerReference: "reviewer:independent-001",
    schema: pilotGateContract.schemas.manifest,
    scopeReference: "scope:pilot-001",
  }));
}

async function resign(value: Record<string, unknown>) {
  const base = structuredClone(value);
  delete base.packageDigest;
  return canonicalJSON({
    ...base,
    packageDigest: createHash("sha256").update(JSON.stringify(canonicalValue(base))).digest("hex"),
  });
}

async function expectFailure(text: string, gateId: TenantAdmissionGateId) {
  await expect(verifyPilotGateManifestText(text, gateId))
    .rejects.toEqual(new PilotGateManifestImportError());
}

function canonicalJSON(value: unknown) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, canonicalValue(record[key])]));
  }
  return value;
}
