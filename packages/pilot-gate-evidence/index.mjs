import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { TextDecoder } from "node:util";

export const PILOT_GATE_DESCRIPTOR_SCHEMA = "vasi-pilot-gate-evidence-descriptor/v1";
export const PILOT_GATE_MANIFEST_SCHEMA = "vasi-pilot-gate-evidence-manifest/v1";
export const PILOT_GATE_VERIFICATION_SCHEMA = "vasi-pilot-gate-evidence-verification/v1";
export const MAXIMUM_PILOT_GATE_DESCRIPTOR_BYTES = 262_144;
export const MAXIMUM_PILOT_GATE_MANIFEST_BYTES = 1_048_576;
export const MAXIMUM_PILOT_GATE_ARTIFACTS = 64;
export const MAXIMUM_PILOT_GATE_ARTIFACT_BYTES = 16 * 1024 * 1024;
export const MAXIMUM_PILOT_GATE_TOTAL_BYTES = 128 * 1024 * 1024;

export const PILOT_GATE_LIMITATIONS = Object.freeze([
  "This manifest proves the integrity and completeness of the indexed local files; it does not establish that a review was sufficient or correct.",
  "VASI does not ingest, copy, upload, interpret, certify, or approve the indexed evidence artifacts.",
  "Opaque references identify separately controlled scope, reviewer, and records; they do not prove identity, authority, independence, or legal capacity.",
  "A satisfied checklist item or accepted exception records the review package assertion only; the accountable admission owner must make the gate decision.",
  "The manifest SHA-256 detects changes to the canonical manifest and artifact digests; it is not a digital signature, trusted timestamp, or certificate opinion.",
]);

export const PILOT_GATE_CHECKLISTS = Object.freeze({
  exact_release: Object.freeze([
    "source_assurance",
    "image_assurance",
    "build_test_conformance",
    "backup_settings_migrations",
    "rollback_readiness",
  ]),
  isolation_integrity: Object.freeze([
    "first_party_isolation_tamper",
    "public_private_tenant_scope",
    "independent_penetration_assessment",
    "finding_disposition",
  ]),
  identity_delivery: Object.freeze([
    "approved_identity_providers",
    "callback_and_origin_policy",
    "mfa_or_conditional_access",
    "authentication_mail",
    "tenant_delivery_path",
    "account_recovery_support",
  ]),
  privacy_legal: Object.freeze([
    "notice_and_consent_language",
    "field_and_disclosure_inventory",
    "data_request_process",
    "retention_and_hold_policy",
    "jurisdiction_analysis",
    "electronic_act_analysis",
  ]),
  accessibility: Object.freeze([
    "automated_accessibility",
    "keyboard_navigation",
    "screen_reader",
    "zoom_and_reflow",
    "motion_and_animation",
    "media_alternatives",
    "supported_browser_device",
  ]),
  malware_content: Object.freeze([
    "content_risk_classification",
    "scanner_or_trusted_source_policy",
    "external_media_policy",
    "content_owner_acceptance",
    "outage_and_retry_policy",
  ]),
  recovery_custody: Object.freeze([
    "disposable_recovery_drill",
    "rpo_and_rto",
    "encrypted_off_host_custody",
    "key_rotation_and_revocation",
    "break_glass_process",
    "certificate_tsa_hsm_decision",
  ]),
  capacity_support: Object.freeze([
    "pilot_owner_users_scenarios",
    "concurrency_and_volume_limits",
    "load_evidence",
    "alert_destination_and_escalation",
    "incident_contacts",
    "support_hours",
    "rollback_and_stop_criteria",
  ]),
});

const mediaExtensions = Object.freeze({
  "application/json": ".json",
  "application/pdf": ".pdf",
  "application/zip": ".zip",
  "text/csv": ".csv",
  "text/html": ".html",
  "text/markdown": ".md",
  "text/plain": ".txt",
});
const artifactFilename = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const identifier = /^[a-z][a-z0-9_-]{0,63}$/;
const opaqueReference = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const forbiddenArtifactName = /(?:^|[._-])(?:credential|credentials|env|private|secret|settings|token)(?:[._-]|$)|VASI\.settings/i;

export class PilotGateEvidenceError extends Error {
  constructor(code) {
    super("VASI pilot-gate evidence verification failed.");
    this.code = code;
    this.name = "PilotGateEvidenceError";
  }
}

export function validatePilotGateDescriptor(value) {
  const descriptor = exactObject(value, "descriptor", [
    "artifacts",
    "checklist",
    "evidenceReference",
    "gateId",
    "reviewedAt",
    "reviewerReference",
    "schema",
    "scopeReference",
  ]);
  if (descriptor.schema !== PILOT_GATE_DESCRIPTOR_SCHEMA) fail("unsupported_descriptor_schema");
  const requiredChecklist = PILOT_GATE_CHECKLISTS[descriptor.gateId];
  if (!requiredChecklist) fail("unsupported_gate");
  const artifacts = validateDescriptorArtifacts(descriptor.artifacts);
  const artifactIds = new Set(artifacts.map((artifact) => artifact.id));
  const checklist = validateChecklist(descriptor.checklist, requiredChecklist, artifactIds);
  const referencedArtifacts = new Set(checklist.flatMap((item) => item.artifactIds));
  if (referencedArtifacts.size !== artifacts.length) fail("unreferenced_artifact");
  return Object.freeze({
    artifacts: Object.freeze(artifacts),
    checklist: Object.freeze(checklist),
    evidenceReference: reference(descriptor.evidenceReference, "evidence_reference"),
    gateId: descriptor.gateId,
    reviewedAt: canonicalTimestamp(descriptor.reviewedAt),
    reviewerReference: reference(descriptor.reviewerReference, "reviewer_reference"),
    schema: PILOT_GATE_DESCRIPTOR_SCHEMA,
    scopeReference: reference(descriptor.scopeReference, "scope_reference"),
  });
}

export function pilotGateDescriptorJSON(value) {
  return prettyCanonicalJSON(validatePilotGateDescriptor(value));
}

export function validatePilotGateManifest(value) {
  const manifest = exactObject(value, "manifest", [
    "artifacts",
    "checklist",
    "evidenceReference",
    "gateId",
    "limitations",
    "packageDigest",
    "reviewedAt",
    "reviewerReference",
    "schema",
    "scopeReference",
  ]);
  if (manifest.schema !== PILOT_GATE_MANIFEST_SCHEMA) fail("unsupported_manifest_schema");
  if (!sameArray(manifest.limitations, PILOT_GATE_LIMITATIONS)) fail("invalid_limitations");
  if (!Array.isArray(manifest.artifacts) || !manifest.artifacts.length ||
      manifest.artifacts.length > MAXIMUM_PILOT_GATE_ARTIFACTS) fail("invalid_artifacts");
  const artifacts = manifest.artifacts.map((value) => {
    const artifact = exactObject(value, "manifest artifact", [
      "bytes", "id", "mediaType", "path", "sha256",
    ]);
    if (!Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 ||
        artifact.bytes > MAXIMUM_PILOT_GATE_ARTIFACT_BYTES) fail("invalid_artifact_size");
    return Object.freeze({
      bytes: artifact.bytes,
      id: artifact.id,
      mediaType: artifact.mediaType,
      path: artifact.path,
      sha256: sha256(artifact.sha256, "artifact_digest"),
    });
  });
  const totalBytes = artifacts.reduce((sum, artifact) => sum + artifact.bytes, 0);
  if (totalBytes > MAXIMUM_PILOT_GATE_TOTAL_BYTES) fail("evidence_size_exceeded");
  const descriptor = validatePilotGateDescriptor({
    artifacts: artifacts.map(({ id, mediaType, path: artifactPath }) => ({
      id,
      mediaType,
      path: artifactPath,
    })),
    checklist: manifest.checklist,
    evidenceReference: manifest.evidenceReference,
    gateId: manifest.gateId,
    reviewedAt: manifest.reviewedAt,
    reviewerReference: manifest.reviewerReference,
    schema: PILOT_GATE_DESCRIPTOR_SCHEMA,
    scopeReference: manifest.scopeReference,
  });
  const normalized = {
    artifacts: Object.freeze(artifacts),
    checklist: descriptor.checklist,
    evidenceReference: descriptor.evidenceReference,
    gateId: descriptor.gateId,
    limitations: PILOT_GATE_LIMITATIONS,
    reviewedAt: descriptor.reviewedAt,
    reviewerReference: descriptor.reviewerReference,
    schema: PILOT_GATE_MANIFEST_SCHEMA,
    scopeReference: descriptor.scopeReference,
  };
  const packageDigest = sha256(manifest.packageDigest, "package_digest");
  if (digestCanonical(normalized) !== packageDigest) fail("package_digest_mismatch");
  return Object.freeze({ ...normalized, packageDigest });
}

export function pilotGateManifestJSON(value) {
  return prettyCanonicalJSON(validatePilotGateManifest(value));
}

export function pilotGateAdmissionEvidence(value) {
  const manifest = validatePilotGateManifest(value);
  return Object.freeze({
    evidenceDigest: manifest.packageDigest,
    evidenceReference: manifest.evidenceReference,
    reviewerReference: manifest.reviewerReference,
  });
}

export async function createPilotGateEvidenceManifest(
  descriptorValue,
  evidenceDirectory,
  { uid = process.getuid?.() ?? 0 } = {},
) {
  try {
    const descriptor = validatePilotGateDescriptor(descriptorValue);
    const artifacts = await inspectEvidenceDirectory(evidenceDirectory, descriptor.artifacts, uid);
    const base = {
      artifacts,
      checklist: descriptor.checklist,
      evidenceReference: descriptor.evidenceReference,
      gateId: descriptor.gateId,
      limitations: PILOT_GATE_LIMITATIONS,
      reviewedAt: descriptor.reviewedAt,
      reviewerReference: descriptor.reviewerReference,
      schema: PILOT_GATE_MANIFEST_SCHEMA,
      scopeReference: descriptor.scopeReference,
    };
    return validatePilotGateManifest({ ...base, packageDigest: digestCanonical(base) });
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    fail("evidence_unavailable");
  }
}

export async function createPilotGateEvidenceManifestFile(
  descriptorFile,
  evidenceDirectory,
  outputFile,
  { uid = process.getuid?.() ?? 0 } = {},
) {
  try {
    const descriptorPath = path.resolve(descriptorFile);
    const descriptor = await readCanonicalJSONFile(
      descriptorPath,
      MAXIMUM_PILOT_GATE_DESCRIPTOR_BYTES,
      uid,
      pilotGateDescriptorJSON,
    );
    const evidenceRoot = await validatePrivateDirectory(evidenceDirectory, uid);
    const output = path.resolve(outputFile);
    const outputDirectory = path.dirname(output);
    await validatePrivateDirectory(outputDirectory, uid);
    if (isWithin(evidenceRoot.path, descriptorPath) || isWithin(evidenceRoot.path, output) ||
        output === descriptorPath) {
      fail("unsafe_output_path");
    }
    await requireAbsent(output);
    const manifest = await createPilotGateEvidenceManifest(descriptor, evidenceRoot.path, { uid });
    await writePhysicalFile(output, pilotGateManifestJSON(manifest), uid);
    return verificationResult(manifest);
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    fail("creation_unavailable");
  }
}

export async function verifyPilotGateEvidenceManifest(
  manifestValue,
  evidenceDirectory,
  { expectedDigest, uid = process.getuid?.() ?? 0 } = {},
) {
  try {
    const manifest = validatePilotGateManifest(manifestValue);
    if (expectedDigest !== undefined && sha256(expectedDigest, "expected_digest") !== manifest.packageDigest) {
      fail("expected_digest_mismatch");
    }
    const artifacts = await inspectEvidenceDirectory(evidenceDirectory, manifest.artifacts, uid);
    for (let index = 0; index < artifacts.length; index += 1) {
      const actual = artifacts[index];
      const expected = manifest.artifacts[index];
      if (actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) {
        fail("artifact_mismatch");
      }
    }
    return verificationResult(manifest, expectedDigest !== undefined);
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    fail("verification_unavailable");
  }
}

export async function verifyPilotGateEvidenceManifestFile(
  manifestFile,
  evidenceDirectory,
  options = {},
) {
  try {
    const uid = options.uid ?? process.getuid?.() ?? 0;
    const evidenceRoot = await validatePrivateDirectory(evidenceDirectory, uid);
    const manifestPath = path.resolve(manifestFile);
    if (isWithin(evidenceRoot.path, manifestPath)) fail("unsafe_manifest_path");
    const manifest = await readCanonicalJSONFile(
      manifestPath,
      MAXIMUM_PILOT_GATE_MANIFEST_BYTES,
      uid,
      pilotGateManifestJSON,
    );
    return verifyPilotGateEvidenceManifest(manifest, evidenceRoot.path, { ...options, uid });
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    fail("verification_unavailable");
  }
}

function validateDescriptorArtifacts(value) {
  if (!Array.isArray(value) || !value.length || value.length > MAXIMUM_PILOT_GATE_ARTIFACTS) {
    fail("invalid_artifacts");
  }
  const seenIds = new Set();
  const seenPaths = new Set();
  const artifacts = value.map((entry) => {
    const artifact = exactObject(entry, "descriptor artifact", ["id", "mediaType", "path"]);
    if (!identifier.test(artifact.id) || seenIds.has(artifact.id)) fail("invalid_artifact_id");
    if (!Object.hasOwn(mediaExtensions, artifact.mediaType)) fail("unsupported_artifact_media_type");
    if (!artifactFilename.test(artifact.path) || artifact.path.startsWith(".") ||
        forbiddenArtifactName.test(artifact.path) || seenPaths.has(artifact.path) ||
        path.extname(artifact.path).toLowerCase() !== mediaExtensions[artifact.mediaType]) {
      fail("invalid_artifact_path");
    }
    seenIds.add(artifact.id);
    seenPaths.add(artifact.path);
    return Object.freeze({ id: artifact.id, mediaType: artifact.mediaType, path: artifact.path });
  });
  if (artifacts.map((artifact) => artifact.id).join("\0") !==
      artifacts.map((artifact) => artifact.id).sort().join("\0")) {
    fail("noncanonical_artifact_order");
  }
  return artifacts;
}

function validateChecklist(value, required, artifactIds) {
  if (!Array.isArray(value) || value.length !== required.length) fail("incomplete_checklist");
  return value.map((entry, index) => {
    const item = exactObject(entry, "checklist item", [
      "artifactIds", "exceptionReference", "id", "outcome",
    ]);
    if (item.id !== required[index]) fail("invalid_checklist_order");
    if (!Array.isArray(item.artifactIds) || !item.artifactIds.length ||
        item.artifactIds.length > MAXIMUM_PILOT_GATE_ARTIFACTS ||
        item.artifactIds.some((artifactId) => !identifier.test(artifactId) || !artifactIds.has(artifactId)) ||
        new Set(item.artifactIds).size !== item.artifactIds.length ||
        item.artifactIds.join("\0") !== [...item.artifactIds].sort().join("\0")) {
      fail("invalid_checklist_artifacts");
    }
    if (item.outcome !== "satisfied" && item.outcome !== "accepted_exception") {
      fail("invalid_checklist_outcome");
    }
    const exceptionReference = item.outcome === "accepted_exception"
      ? reference(item.exceptionReference, "exception_reference")
      : item.exceptionReference === null
        ? null
        : fail("unexpected_exception_reference");
    return Object.freeze({
      artifactIds: Object.freeze([...item.artifactIds]),
      exceptionReference,
      id: item.id,
      outcome: item.outcome,
    });
  });
}

async function inspectEvidenceDirectory(directory, expectedArtifacts, uid) {
  const boundary = await validatePrivateDirectory(directory, uid);
  const expectedNames = expectedArtifacts.map((artifact) => artifact.path).sort();
  const entries = await readdir(boundary.path, { withFileTypes: true });
  const actualNames = entries.map((entry) => entry.name).sort();
  if (!sameArray(actualNames, expectedNames) || entries.some((entry) => !entry.isFile())) {
    fail("evidence_inventory_mismatch");
  }
  const artifacts = [];
  let totalBytes = 0;
  for (const expected of expectedArtifacts) {
    const physical = await readPhysicalFile(
      path.join(boundary.path, expected.path),
      MAXIMUM_PILOT_GATE_ARTIFACT_BYTES,
      uid,
    );
    totalBytes += physical.contents.length;
    if (totalBytes > MAXIMUM_PILOT_GATE_TOTAL_BYTES) fail("evidence_size_exceeded");
    artifacts.push(Object.freeze({
      bytes: physical.contents.length,
      id: expected.id,
      mediaType: expected.mediaType,
      path: expected.path,
      sha256: digest(physical.contents),
    }));
  }
  const finalEntries = (await readdir(boundary.path)).sort();
  const finalMetadata = await lstat(boundary.path, { bigint: true });
  if (!sameArray(finalEntries, expectedNames) || !sameMetadata(boundary.metadata, finalMetadata)) {
    fail("evidence_changed");
  }
  return Object.freeze(artifacts);
}

async function readCanonicalJSONFile(filename, maximumBytes, uid, canonicalizer) {
  await validatePrivateDirectory(path.dirname(path.resolve(filename)), uid);
  const physical = await readPhysicalFile(filename, maximumBytes, uid);
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(physical.contents);
    if (text.includes("\0")) fail("invalid_json_encoding");
    value = JSON.parse(text);
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    fail("invalid_json");
  }
  if (canonicalizer(value) !== text) fail("noncanonical_json");
  return value;
}

async function readPhysicalFile(filename, maximumBytes, uid) {
  const resolved = path.resolve(filename);
  const owners = new Set([0, uid]);
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximumBytes) ||
        before.nlink !== 1n || (Number(before.mode) & 0o7777) !== 0o600 ||
        !owners.has(Number(before.uid)) || await realpath(resolved) !== resolved) {
      fail("invalid_physical_file");
    }
    const contents = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (contents.length !== Number(before.size) || !sameMetadata(before, after)) fail("physical_file_changed");
    return Object.freeze({ contents, metadata: before, path: resolved });
  } finally {
    await handle.close();
  }
}

async function validatePrivateDirectory(directory, uid) {
  const resolved = path.resolve(directory);
  const metadata = await lstat(resolved, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      (Number(metadata.mode) & 0o7777) !== 0o700 ||
      !new Set([0, uid]).has(Number(metadata.uid)) || await realpath(resolved) !== resolved) {
    fail("invalid_private_directory");
  }
  return Object.freeze({ metadata, path: resolved });
}

async function writePhysicalFile(filename, contents, uid) {
  let handle;
  let created = false;
  let succeeded = false;
  try {
    handle = await open(
      filename,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0),
      0o600,
    );
    created = true;
    await handle.writeFile(contents);
    await handle.sync();
    await handle.close();
    handle = undefined;
    const written = await readPhysicalFile(filename, MAXIMUM_PILOT_GATE_MANIFEST_BYTES, uid);
    if (!written.contents.equals(Buffer.from(contents))) fail("manifest_write_mismatch");
    succeeded = true;
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    fail("manifest_write_failed");
  } finally {
    await handle?.close().catch(() => undefined);
    if (created && !succeeded) await rm(filename, { force: true }).catch(() => undefined);
  }
}

async function requireAbsent(filename) {
  try {
    await lstat(filename);
    fail("output_exists");
  } catch (error) {
    if (error instanceof PilotGateEvidenceError) throw error;
    if (error?.code !== "ENOENT") fail("output_unavailable");
  }
}

function verificationResult(manifest, expectedDigest = false) {
  return Object.freeze({
    artifacts: manifest.artifacts.length,
    checklistItems: manifest.checklist.length,
    exceptions: manifest.checklist.filter((item) => item.outcome === "accepted_exception").length,
    expectedDigest: expectedDigest ? "matched" : "not_supplied",
    gateId: manifest.gateId,
    packageSha256: manifest.packageDigest,
    schema: PILOT_GATE_VERIFICATION_SCHEMA,
    status: "pass",
    totalBytes: manifest.artifacts.reduce((sum, artifact) => sum + artifact.bytes, 0),
  });
}

function exactObject(value, name, keys) {
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) {
    fail(`invalid_${name.replaceAll(" ", "_")}`);
  }
  return value;
}

function reference(value, name) {
  if (typeof value !== "string" || !opaqueReference.test(value)) fail(`invalid_${name}`);
  return value;
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") fail("invalid_reviewed_at");
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail("invalid_reviewed_at");
  return value;
}

function sha256(value, name) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) fail(`invalid_${name}`);
  return value;
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function digestCanonical(value) {
  return digest(JSON.stringify(canonicalValue(value)));
}

function prettyCanonicalJSON(value) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

function sameArray(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameMetadata(left, right) {
  return ["dev", "ino", "mode", "nlink", "size", "uid", "gid", "mtimeNs"]
    .every((name) => left[name] === right[name]);
}

function isWithin(parent, child) {
  const relative = path.relative(parent, child);
  return Boolean(relative) && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function fail(code) {
  throw new PilotGateEvidenceError(code);
}
