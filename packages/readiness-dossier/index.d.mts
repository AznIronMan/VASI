export type ReadinessDossierVerificationResult = {
  dossierSha256: string;
  expectedDigest: "matched" | "not_supplied";
  format: "html" | "json";
  presentation: "exact" | "not_applicable";
  schema: "vasi-readiness-dossier-verification/v1";
  status: "pass";
};

export class ReadinessDossierVerificationError extends Error {
  code: string;
}

export const MAXIMUM_READINESS_DOSSIER_BYTES: number;
export const READINESS_DOSSIER_VERIFICATION_SCHEMA: "vasi-readiness-dossier-verification/v1";
export const READINESS_DOSSIER_LIMITATIONS: readonly string[];
export function validateReadinessExport(value: unknown): Record<string, unknown>;
export function hashReadinessDossier(value: unknown): string;
export function readinessExportJSON(value: unknown): string;
export function renderReadinessDossierHTML(value: unknown): string;
export function verifyReadinessDossierBytes(
  value: Uint8Array,
  options?: { expectedDigest?: string },
): ReadinessDossierVerificationResult;
export function verifyReadinessDossierFile(
  filename: string,
  options?: { expectedDigest?: string },
): Promise<ReadinessDossierVerificationResult>;
