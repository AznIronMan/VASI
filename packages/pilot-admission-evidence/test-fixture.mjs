import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  createPilotGateEvidenceManifest,
  PILOT_GATE_CHECKLISTS,
  PILOT_GATE_DESCRIPTOR_SCHEMA,
  pilotGateAdmissionEvidence,
  pilotGateManifestJSON,
} from "../pilot-gate-evidence/index.mjs";
import {
  readinessExportJSON,
  renderReadinessDossierHTML,
} from "../readiness-dossier/index.mjs";
import { createReadinessExportFixture } from "../readiness-dossier/test-fixture.mjs";
import { TENANT_ADMISSION_GATES } from "../engine-domain/productization.mjs";

export async function createPilotAdmissionEvidenceFixture({
  admitted = true,
  decisionOverrides = {},
  dossierEvidenceMutator,
  format = "json",
  legacy = false,
  manifestOverrides = {},
} = {}) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), "vasi-pilot-admission-")));
  await chmod(root, 0o700);
  const artifactDirectoryRoot = path.join(root, "artifacts");
  const dossierDirectory = path.join(root, "dossier");
  const manifestDirectory = path.join(root, "manifests");
  for (const directory of [artifactDirectoryRoot, dossierDirectory, manifestDirectory]) {
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
  }

  const manifests = [];
  for (const gateId of TENANT_ADMISSION_GATES) {
    const evidenceDirectory = path.join(artifactDirectoryRoot, gateId);
    await mkdir(evidenceDirectory, { mode: 0o700 });
    await chmod(evidenceDirectory, 0o700);
    await writeFile(
      path.join(evidenceDirectory, "assessment.json"),
      "{\"assessment\":\"reviewed\"}\n",
      { mode: 0o600 },
    );
    const override = manifestOverrides[gateId] || {};
    const descriptor = {
      artifacts: [{ id: "assessment", mediaType: "application/json", path: "assessment.json" }],
      checklist: PILOT_GATE_CHECKLISTS[gateId].map((id) => ({
        artifactIds: ["assessment"],
        exceptionReference: null,
        id,
        outcome: "satisfied",
      })),
      evidenceReference: override.evidenceReference || `review-package:${gateId}`,
      gateId,
      reviewedAt: override.reviewedAt || "2026-07-15T19:00:00.000Z",
      reviewerReference: override.reviewerReference || `reviewer:${gateId}`,
      schema: PILOT_GATE_DESCRIPTOR_SCHEMA,
      scopeReference: override.scopeReference || "scope:pilot-001",
    };
    const manifest = await createPilotGateEvidenceManifest(descriptor, evidenceDirectory);
    manifests.push(manifest);
    await writeFile(
      path.join(manifestDirectory, `${gateId}.json`),
      pilotGateManifestJSON(manifest),
      { mode: 0o600 },
    );
  }

  const admissionEvidence = manifests.map((manifest) => ({
    decidedAt: decisionOverrides[manifest.gateId] || "2026-07-15T19:30:00.000Z",
    gateId: manifest.gateId,
    ...pilotGateAdmissionEvidence(manifest),
  }));
  const dossierEvidence = structuredClone(admissionEvidence);
  dossierEvidenceMutator?.(dossierEvidence);
  const exported = createReadinessExportFixture(format, {
    admissionEvidence: admitted ? dossierEvidence : undefined,
    legacy,
  });
  const dossierFile = path.join(dossierDirectory, `dossier.${format}`);
  await writeFile(
    dossierFile,
    format === "json" ? readinessExportJSON(exported) : renderReadinessDossierHTML(exported),
    { mode: 0o600 },
  );
  return {
    admissionEvidence,
    artifactDirectoryRoot,
    dossierDirectory,
    dossierFile,
    exported,
    manifestDirectory,
    manifests,
    root,
  };
}
