import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";

import { TENANT_ADMISSION_GATES } from "../engine-domain/productization.mjs";
import {
  MAXIMUM_PILOT_GATE_MANIFEST_BYTES,
  pilotGateManifestJSON,
  validatePilotGateManifest,
  verifyPilotGateEvidenceManifest,
} from "../pilot-gate-evidence/index.mjs";
import {
  MAXIMUM_READINESS_DOSSIER_BYTES,
  SIGNED_READINESS_EXPORT_SCHEMA,
  validateReadinessExport,
  verifyReadinessDossierBytes,
} from "../readiness-dossier/index.mjs";

export const PILOT_ADMISSION_EVIDENCE_VERIFICATION_SCHEMA =
  "vasi-pilot-admission-evidence-verification/v1";
export const PILOT_ADMISSION_COMPLETE_EVIDENCE_VERIFICATION_SCHEMA =
  "vasi-pilot-admission-evidence-verification/v2";

const expectedManifestNames = Object.freeze(
  TENANT_ADMISSION_GATES.map((gateId) => `${gateId}.json`).sort(),
);
const expectedArtifactDirectoryNames = Object.freeze([...TENANT_ADMISSION_GATES].sort());

export class PilotAdmissionEvidenceVerificationError extends Error {
  constructor(code) {
    super("VASI pilot-admission evidence verification failed.");
    this.code = code;
    this.name = "PilotAdmissionEvidenceVerificationError";
  }
}

export async function verifyPilotAdmissionEvidenceSet(
  dossierFile,
  manifestDirectory,
  {
    artifactDirectoryRoot,
    expectedDigest,
    expectedKeyFingerprint,
    uid = process.getuid?.() ?? 0,
  } = {},
) {
  try {
    if (
      !Number.isSafeInteger(uid) || uid < 0 ||
      [dossierFile, manifestDirectory, artifactDirectoryRoot]
        .filter((value) => value !== undefined)
        .some((value) =>
        typeof value !== "string" || !value || Buffer.byteLength(value) > 4_096 || value.includes("\0")
      )
    ) fail("invalid_input");
    const manifestBoundary = await validatePrivateDirectory(manifestDirectory, uid);
    const dossierPath = path.resolve(dossierFile);
    const dossierDirectory = await validatePrivateDirectory(path.dirname(dossierPath), uid);
    if (isWithinOrEqual(manifestBoundary.path, dossierPath)) fail("overlapping_inputs");
    const artifactBoundary = artifactDirectoryRoot === undefined
      ? null
      : await validateArtifactDirectoryRoot(artifactDirectoryRoot, uid);
    if (
      artifactBoundary && (
        isWithinOrEqual(artifactBoundary.path, dossierPath) ||
        isWithinOrEqual(dossierDirectory.path, artifactBoundary.path) ||
        isWithinOrEqual(dossierDirectory.path, manifestBoundary.path) ||
        isWithinOrEqual(artifactBoundary.path, manifestBoundary.path) ||
        isWithinOrEqual(manifestBoundary.path, artifactBoundary.path)
      )
    ) fail("overlapping_inputs");

    const entries = await readdir(manifestBoundary.path, { withFileTypes: true });
    const names = entries.map((entry) => entry.name).sort();
    if (!sameArray(names, expectedManifestNames) || entries.some((entry) => !entry.isFile())) {
      fail("manifest_inventory_mismatch");
    }

    const manifests = [];
    for (const gateId of TENANT_ADMISSION_GATES) {
      const contents = await readPrivatePhysicalFile(
        path.join(manifestBoundary.path, `${gateId}.json`),
        MAXIMUM_PILOT_GATE_MANIFEST_BYTES,
        uid,
      );
      const manifest = readCanonicalManifest(contents);
      if (manifest.gateId !== gateId) fail("manifest_gate_mismatch");
      manifests.push(manifest);
    }

    const finalManifestEntries = (await readdir(manifestBoundary.path)).sort();
    const finalManifestMetadata = await lstat(manifestBoundary.path, { bigint: true });
    if (
      !sameArray(finalManifestEntries, expectedManifestNames) ||
      !sameMetadata(manifestBoundary.metadata, finalManifestMetadata)
    ) fail("manifest_directory_changed");

    const dossierBytes = await readPrivatePhysicalFile(
      dossierPath,
      MAXIMUM_READINESS_DOSSIER_BYTES,
      uid,
    );
    const finalDossierMetadata = await lstat(dossierDirectory.path, { bigint: true });
    if (!sameMetadata(dossierDirectory.metadata, finalDossierMetadata)) {
      fail("dossier_directory_changed");
    }
    const { exported, verification } = verifiedReadinessExport(dossierBytes, {
      expectedDigest,
      expectedKeyFingerprint,
    });
    verifyAdmissionBindings(exported, manifests);
    const artifactSummary = artifactBoundary
      ? await verifyArtifactDirectories(manifests, artifactBoundary, uid)
      : null;

    return Object.freeze({
      admissionEvidence: "matched",
      ...(artifactSummary
        ? { artifactBytes: artifactSummary.bytes, artifacts: artifactSummary.artifacts }
        : {}),
      artifactVerification: artifactSummary ? "matched" : "not_performed",
      certificateSeal: verification.certificateSeal,
      dossierSha256: verification.dossierSha256,
      evidencePackages: manifests.length,
      expectedDigest: verification.expectedDigest,
      expectedKeyFingerprint: verification.expectedKeyFingerprint,
      format: verification.format,
      integrityKeyFingerprint: verification.integrityKeyFingerprint,
      integritySeal: verification.integritySeal,
      presentation: verification.presentation,
      schema: artifactSummary
        ? PILOT_ADMISSION_COMPLETE_EVIDENCE_VERIFICATION_SCHEMA
        : PILOT_ADMISSION_EVIDENCE_VERIFICATION_SCHEMA,
      scopeBinding: "consistent",
      status: "pass",
      temporalBinding: "ordered",
    });
  } catch (error) {
    if (error instanceof PilotAdmissionEvidenceVerificationError) throw error;
    fail("verification_unavailable");
  }
}

async function validateArtifactDirectoryRoot(directory, uid) {
  const boundary = await validatePrivateDirectory(directory, uid);
  const entries = await readdir(boundary.path, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort();
  if (
    !sameArray(names, expectedArtifactDirectoryNames) ||
    entries.some((entry) => !entry.isDirectory())
  ) fail("artifact_directory_inventory_mismatch");
  return boundary;
}

async function verifyArtifactDirectories(manifests, boundary, uid) {
  let artifacts = 0;
  let bytes = 0;
  for (let index = 0; index < TENANT_ADMISSION_GATES.length; index += 1) {
    const gateId = TENANT_ADMISSION_GATES[index];
    const manifest = manifests[index];
    const verification = await verifyPilotGateEvidenceManifest(
      manifest,
      path.join(boundary.path, gateId),
      { expectedDigest: manifest.packageDigest, uid },
    );
    artifacts += verification.artifacts;
    bytes += verification.totalBytes;
  }
  const entries = await readdir(boundary.path, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort();
  const metadata = await lstat(boundary.path, { bigint: true });
  if (
    !sameArray(names, expectedArtifactDirectoryNames) ||
    entries.some((entry) => !entry.isDirectory()) ||
    !sameMetadata(boundary.metadata, metadata)
  ) fail("artifact_directory_changed");
  return Object.freeze({ artifacts, bytes });
}

function readCanonicalManifest(contents) {
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(contents);
    if (text.includes("\0")) fail("invalid_manifest_text");
    value = JSON.parse(text);
  } catch (error) {
    if (error instanceof PilotAdmissionEvidenceVerificationError) throw error;
    fail("invalid_manifest_json");
  }
  const manifest = validatePilotGateManifest(value);
  if (pilotGateManifestJSON(manifest) !== text) fail("noncanonical_manifest");
  return manifest;
}

function verifiedReadinessExport(contents, options) {
  const verification = verifyReadinessDossierBytes(contents, options);
  if (verification.integritySeal !== "verified") fail("unsigned_dossier");
  let text;
  let exported;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(contents);
    if (verification.format === "json") {
      exported = JSON.parse(text);
    } else {
      const matches = [...text.matchAll(
        /<script type="application\/json" id="vasi-readiness-export">([^<]*)<\/script>/g,
      )];
      if (matches.length !== 1) fail("invalid_dossier_embedding");
      exported = JSON.parse(matches[0][1]);
    }
  } catch (error) {
    if (error instanceof PilotAdmissionEvidenceVerificationError) throw error;
    fail("invalid_dossier");
  }
  validateReadinessExport(exported);
  if (exported.schema !== SIGNED_READINESS_EXPORT_SCHEMA) fail("unsigned_dossier");
  return Object.freeze({ exported, verification });
}

function verifyAdmissionBindings(exported, manifests) {
  const { admission } = exported.dossier;
  if (
    admission.status !== "admitted" ||
    manifests.length !== TENANT_ADMISSION_GATES.length ||
    admission.gates.length !== TENANT_ADMISSION_GATES.length
  ) fail("admission_not_complete");

  const scopes = new Set(manifests.map((manifest) => manifest.scopeReference));
  if (scopes.size !== 1) fail("inconsistent_scope");

  const revisionCreatedAt = timestamp(admission.revisionCreatedAt);
  const capturedAt = timestamp(exported.capturedAt);
  if (revisionCreatedAt > capturedAt) fail("invalid_admission_time");

  for (let index = 0; index < TENANT_ADMISSION_GATES.length; index += 1) {
    const gateId = TENANT_ADMISSION_GATES[index];
    const gate = admission.gates[index];
    const manifest = manifests[index];
    if (
      gate.id !== gateId || manifest.gateId !== gateId || gate.state !== "approved" ||
      gate.evidenceDigest !== manifest.packageDigest ||
      gate.evidenceReference !== manifest.evidenceReference ||
      gate.reviewerReference !== manifest.reviewerReference
    ) fail("admission_evidence_mismatch");
    const reviewedAt = timestamp(manifest.reviewedAt);
    const decidedAt = timestamp(gate.decidedAt);
    if (reviewedAt > decidedAt || decidedAt > revisionCreatedAt || decidedAt > capturedAt) {
      fail("invalid_evidence_time");
    }
  }
}

async function readPrivatePhysicalFile(filename, maximumBytes, uid) {
  const resolved = path.resolve(filename);
  const owners = new Set([0, uid]);
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() || before.size < 1n || before.size > BigInt(maximumBytes) ||
      before.nlink !== 1n || (Number(before.mode) & 0o7777) !== 0o600 ||
      !owners.has(Number(before.uid)) || await realpath(resolved) !== resolved
    ) fail("invalid_physical_file");
    const contents = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (contents.length !== Number(before.size) || !sameMetadata(before, after)) {
      fail("physical_file_changed");
    }
    return contents;
  } finally {
    await handle.close();
  }
}

async function validatePrivateDirectory(directory, uid) {
  const resolved = path.resolve(directory);
  const metadata = await lstat(resolved, { bigint: true });
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() ||
    (Number(metadata.mode) & 0o7777) !== 0o700 ||
    !new Set([0, uid]).has(Number(metadata.uid)) || await realpath(resolved) !== resolved
  ) fail("invalid_private_directory");
  return Object.freeze({ metadata, path: resolved });
}

function timestamp(value) {
  const result = Date.parse(value);
  if (!Number.isFinite(result)) fail("invalid_timestamp");
  return result;
}

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameMetadata(left, right) {
  return ["dev", "ino", "mode", "nlink", "size", "uid", "gid", "mtimeNs"]
    .every((name) => left[name] === right[name]);
}

function isWithinOrEqual(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function fail(code) {
  throw new PilotAdmissionEvidenceVerificationError(code);
}
