export type ReadinessDossierVerificationResult = {
  certificateSeal: "not_present" | "verified";
  dossierSha256: string;
  expectedDigest: "matched" | "not_supplied";
  expectedKeyFingerprint: "matched" | "not_supplied";
  format: "html" | "json";
  integrityKeyFingerprint: string | null;
  integritySeal: "not_present" | "verified";
  presentation: "exact" | "not_applicable";
  schema: "vasi-readiness-dossier-verification/v2";
  status: "pass";
};

export class ReadinessDossierVerificationError extends Error {
  code: string;
}

export const MAXIMUM_READINESS_DOSSIER_BYTES: number;
export const READINESS_ATTESTATION_SCHEMA: "vasi-tenant-readiness-attestation/v1";
export const READINESS_DOSSIER_SEAL_PROFILE: "vasi-readiness-dossier-seal/v1";
export const READINESS_DOSSIER_VERIFICATION_SCHEMA: "vasi-readiness-dossier-verification/v2";
export const READINESS_DOSSIER_LIMITATIONS: readonly string[];
export const SIGNED_READINESS_EXPORT_SCHEMA: "vasi-tenant-readiness-export/v2";
export function createReadinessAttestation(value: {
  auditEventHash: string;
  capturedAt: string;
  dossierHash: string;
  format: "html" | "json";
  signingKeys: Array<{ fingerprint: string; keyId: string; role: "certificate" | "vasi_integrity" }>;
}): Record<string, unknown>;
export function validateReadinessExport(value: unknown): Record<string, unknown>;
export function hashReadinessDossier(value: unknown): string;
export function readinessExportJSON(value: unknown): string;
export function renderReadinessDossierHTML(value: unknown): string;
export function verifyReadinessDossierBytes(
  value: Uint8Array,
  options?: { expectedDigest?: string; expectedKeyFingerprint?: string },
): ReadinessDossierVerificationResult;
export function verifyReadinessDossierFile(
  filename: string,
  options?: { expectedDigest?: string; expectedKeyFingerprint?: string },
): Promise<ReadinessDossierVerificationResult>;
