export function createReadinessExportFixture(
  format?: "html" | "json",
  options?: {
    certificateChainPEM?: string;
    certificatePrivateKeyPEM?: string;
    legacy?: boolean;
    tenantName?: string;
  },
): unknown;
