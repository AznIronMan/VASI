import pilotGateContract from "../../config/pilot-gate-evidence-contract.json";

import type { TenantAdmissionGateId } from "@/lib/owner-types";

const artifactFilename = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const identifier = /^[a-z][a-z0-9_-]{0,63}$/;
const opaqueReference = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const forbiddenArtifactName = /(?:^|[._-])(?:credential|credentials|env|private|secret|settings|token)(?:[._-]|$)|VASI\.settings/i;
const manifestKeys = [
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
] as const;
const artifactKeys = ["bytes", "id", "mediaType", "path", "sha256"] as const;
const checklistKeys = ["artifactIds", "exceptionReference", "id", "outcome"] as const;
const importFailure = Symbol("pilot-gate-manifest-import-failure");

type LocalManifestFile = Pick<File, "arrayBuffer" | "size">;
type UnknownObject = Record<string, unknown>;

type NormalizedArtifact = Readonly<{
  bytes: number;
  id: string;
  mediaType: string;
  path: string;
  sha256: string;
}>;

type NormalizedChecklistItem = Readonly<{
  artifactIds: readonly string[];
  exceptionReference: string | null;
  id: string;
  outcome: "accepted_exception" | "satisfied";
}>;

export type PilotGateManifestImport = Readonly<{
  approval: Readonly<{
    evidenceDigest: string;
    evidenceReference: string;
    reviewerReference: string;
  }>;
  artifacts: number;
  checklistItems: number;
  exceptions: number;
  gateId: TenantAdmissionGateId;
  packageSha256: string;
  reviewedAt: string;
  totalBytes: number;
}>;

export class PilotGateManifestImportError extends Error {
  constructor() {
    super("The offline evidence manifest could not be verified locally.");
    this.name = "PilotGateManifestImportError";
  }
}

export async function verifyPilotGateManifestFile(
  file: LocalManifestFile,
  expectedGateId: TenantAdmissionGateId,
): Promise<PilotGateManifestImport> {
  try {
    if (!Number.isSafeInteger(file.size) || file.size < 1 ||
        file.size > pilotGateContract.limits.manifestBytes) fail();
    const contents = new Uint8Array(await file.arrayBuffer());
    if (contents.byteLength !== file.size) fail();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(contents);
    if (text.includes("\0")) fail();
    return await verifyPilotGateManifestText(text, expectedGateId);
  } catch {
    throw new PilotGateManifestImportError();
  }
}

export async function verifyPilotGateManifestText(
  text: string,
  expectedGateId: TenantAdmissionGateId,
): Promise<PilotGateManifestImport> {
  try {
    if (!text.length || text.length > pilotGateContract.limits.manifestBytes ||
        new TextEncoder().encode(text).byteLength > pilotGateContract.limits.manifestBytes ||
        text.includes("\0")) fail();
    const manifest = exactObject(JSON.parse(text), manifestKeys);
    if (manifest.schema !== pilotGateContract.schemas.manifest) fail();
    if (!sameArray(manifest.limitations, pilotGateContract.limitations)) fail();

    const gateId = requiredGateId(manifest.gateId);
    if (gateId !== expectedGateId) fail();
    const artifacts = normalizeArtifacts(manifest.artifacts);
    const artifactIds = new Set(artifacts.map((artifact) => artifact.id));
    const checklist = normalizeChecklist(manifest.checklist, gateId, artifactIds);
    if (new Set(checklist.flatMap((item) => item.artifactIds)).size !== artifacts.length) fail();

    const evidenceReference = requiredReference(manifest.evidenceReference);
    const reviewedAt = requiredTimestamp(manifest.reviewedAt);
    const reviewerReference = requiredReference(manifest.reviewerReference);
    const scopeReference = requiredReference(manifest.scopeReference);
    const packageDigest = requiredSha256(manifest.packageDigest);
    const normalized = {
      artifacts,
      checklist,
      evidenceReference,
      gateId,
      limitations: pilotGateContract.limitations,
      reviewedAt,
      reviewerReference,
      schema: pilotGateContract.schemas.manifest,
      scopeReference,
    };
    if (await digestCanonical(normalized) !== packageDigest) fail();
    if (prettyCanonicalJSON({ ...normalized, packageDigest }) !== text) fail();

    return Object.freeze({
      approval: Object.freeze({
        evidenceDigest: packageDigest,
        evidenceReference,
        reviewerReference,
      }),
      artifacts: artifacts.length,
      checklistItems: checklist.length,
      exceptions: checklist.filter((item) => item.outcome === "accepted_exception").length,
      gateId,
      packageSha256: packageDigest,
      reviewedAt,
      totalBytes: artifacts.reduce((sum, artifact) => sum + artifact.bytes, 0),
    });
  } catch {
    throw new PilotGateManifestImportError();
  }
}

function normalizeArtifacts(value: unknown): readonly NormalizedArtifact[] {
  if (!Array.isArray(value) || !value.length || value.length > pilotGateContract.limits.artifacts) fail();
  const ids = new Set<string>();
  const paths = new Set<string>();
  let totalBytes = 0;
  const artifacts = value.map((entry): NormalizedArtifact => {
    const artifact = exactObject(entry, artifactKeys);
    if (!Number.isSafeInteger(artifact.bytes) || Number(artifact.bytes) < 1 ||
        Number(artifact.bytes) > pilotGateContract.limits.artifactBytes) fail();
    if (typeof artifact.id !== "string" || !identifier.test(artifact.id) || ids.has(artifact.id)) fail();
    if (typeof artifact.mediaType !== "string" ||
        !Object.hasOwn(pilotGateContract.mediaExtensions, artifact.mediaType)) fail();
    if (typeof artifact.path !== "string" || !artifactFilename.test(artifact.path) ||
        artifact.path.startsWith(".") || forbiddenArtifactName.test(artifact.path) ||
        paths.has(artifact.path)) fail();
    const expectedExtension = (pilotGateContract.mediaExtensions as Record<string, string>)[artifact.mediaType];
    const actualExtension = artifact.path.slice(artifact.path.lastIndexOf(".")).toLowerCase();
    if (actualExtension !== expectedExtension) fail();
    ids.add(artifact.id);
    paths.add(artifact.path);
    totalBytes += Number(artifact.bytes);
    return Object.freeze({
      bytes: Number(artifact.bytes),
      id: artifact.id,
      mediaType: artifact.mediaType,
      path: artifact.path,
      sha256: requiredSha256(artifact.sha256),
    });
  });
  if (totalBytes > pilotGateContract.limits.totalBytes) fail();
  if (artifacts.map(({ id }) => id).join("\0") !==
      artifacts.map(({ id }) => id).sort().join("\0")) fail();
  return Object.freeze(artifacts);
}

function normalizeChecklist(
  value: unknown,
  gateId: TenantAdmissionGateId,
  artifactIds: ReadonlySet<string>,
): readonly NormalizedChecklistItem[] {
  const required = (pilotGateContract.checklists as Record<string, readonly string[]>)[gateId];
  if (!Array.isArray(value) || value.length !== required.length) fail();
  return Object.freeze(value.map((entry, index): NormalizedChecklistItem => {
    const item = exactObject(entry, checklistKeys);
    if (item.id !== required[index]) fail();
    if (!Array.isArray(item.artifactIds) || !item.artifactIds.length ||
        item.artifactIds.length > pilotGateContract.limits.artifacts ||
        item.artifactIds.some((artifactId) => typeof artifactId !== "string" ||
          !identifier.test(artifactId) || !artifactIds.has(artifactId)) ||
        new Set(item.artifactIds).size !== item.artifactIds.length ||
        item.artifactIds.join("\0") !== [...item.artifactIds].sort().join("\0")) fail();
    if (item.outcome !== "satisfied" && item.outcome !== "accepted_exception") fail();
    const exceptionReference = item.outcome === "accepted_exception"
      ? requiredReference(item.exceptionReference)
      : item.exceptionReference === null
        ? null
        : fail();
    return Object.freeze({
      artifactIds: Object.freeze(item.artifactIds as string[]),
      exceptionReference,
      id: required[index],
      outcome: item.outcome,
    });
  }));
}

function exactObject(value: unknown, keys: readonly string[]): UnknownObject {
  if (!value || Array.isArray(value) || typeof value !== "object" ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) fail();
  return value as UnknownObject;
}

function requiredGateId(value: unknown): TenantAdmissionGateId {
  if (typeof value !== "string" || !Object.hasOwn(pilotGateContract.checklists, value)) fail();
  return value as TenantAdmissionGateId;
}

function requiredReference(value: unknown): string {
  if (typeof value !== "string" || !opaqueReference.test(value)) fail();
  return value;
}

function requiredTimestamp(value: unknown): string {
  if (typeof value !== "string") fail();
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) fail();
  return value;
}

function requiredSha256(value: unknown): string {
  if (typeof value !== "string" || !sha256Pattern.test(value)) fail();
  return value;
}

async function digestCanonical(value: unknown) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) fail();
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(canonicalValue(value))));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function prettyCanonicalJSON(value: unknown) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [
      key,
      canonicalValue((value as UnknownObject)[key]),
    ]));
  }
  return value;
}

function sameArray(left: unknown, right: readonly string[]) {
  return Array.isArray(left) && left.length === right.length &&
    left.every((value, index) => value === right[index]);
}

function fail(): never {
  throw importFailure;
}
