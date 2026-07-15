export function createReadinessExportFixture(
  format?: "html" | "json",
  options?: {
    admissionEvidence?: Array<{
      decidedAt?: string;
      evidenceDigest: string;
      evidenceReference: string;
      gateId: string;
      reviewerReference: string;
    }>;
    certificateChainPEM?: string;
    certificatePrivateKeyPEM?: string;
    legacy?: boolean;
    tenantName?: string;
  },
): unknown;
