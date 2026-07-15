export type AdminAuditChainRow = {
  action: string;
  actorSessionId: string | null;
  actorUserId: string | null;
  canonicalPayload: string;
  commandId: string;
  createdAt: Date | string;
  eventHash: string;
  id: string;
  ipAddress: string | null;
  metadata: Record<string, unknown>;
  phase: "event" | "started" | "succeeded" | "failed" | "ambiguous";
  previousHash: string;
  requestId: string;
  sequence: number | string;
  targetUserId: string | null;
  userAgent: string | null;
};

export const ADMIN_AUDIT_GENESIS_HASH: string;
export function verifyAdminAuditChain(
  rows: AdminAuditChainRow[],
  head: { lastHash: string; lastSequence: number | string },
): {
  count: number;
  firstFailure: { code: string; sequence: number } | null;
  headMatches: boolean;
  lastHash: string;
  lastSequence: number;
  valid: boolean;
};
export function evaluateGatewayOperationalReadiness(
  snapshot: {
    audit: { failureCode: string | null; valid: boolean };
    commands: { ambiguous24Hours: number; incomplete: number; oldestIncompleteSeconds: number };
    database: { queryMilliseconds: number };
    migrations: { applied: number; expected: number; valid?: boolean };
  },
  thresholds: { maximumDatabaseQueryMilliseconds: number; maximumIncompleteCommandSeconds: number },
): { failures: readonly string[]; status: "fail" | "pass"; warnings: readonly string[] };
