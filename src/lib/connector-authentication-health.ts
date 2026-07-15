import { authProviderIds, type AuthProviderId } from "@/lib/auth-providers";
import { database } from "@/lib/database";

export const connectorAuthenticationProvenance = {
  attributedSessionBackfill: "attributed_session_backfill/v1",
  federatedSession: "federated_session/v1",
  legacyAccountActivityEstimate: "account_updated_at_estimate/v1",
} as const;

export type ConnectorAuthenticationProvenance =
  (typeof connectorAuthenticationProvenance)[keyof typeof connectorAuthenticationProvenance];

export type ConnectorAuthenticationRecordResult =
  | "account_not_found"
  | "incomplete_attribution"
  | "ignored"
  | "recorded";

type AttributedSession = {
  authenticationAccountId?: unknown;
  authenticationMethod?: unknown;
  authenticationProvider?: unknown;
  createdAt?: unknown;
  userId?: unknown;
};

type Query = (
  sql: string,
  values: unknown[],
) => Promise<{ rowCount: number | null }>;

export async function recordConnectorAuthentication(
  session: AttributedSession,
  query: Query = (sql, values) => database.query(sql, values),
): Promise<ConnectorAuthenticationRecordResult> {
  if (session.authenticationMethod !== "federated") return "ignored";

  const provider = providerValue(session.authenticationProvider);
  if (!provider) return "ignored";

  const accountId = stringValue(session.authenticationAccountId);
  const userId = stringValue(session.userId);
  const authenticatedAt = dateValue(session.createdAt);
  if (!accountId || !userId || !authenticatedAt) return "incomplete_attribution";

  const result = await query(
    `update "account"
     set "lastAuthenticatedAt" = case
           when "lastAuthenticationProvenance" = $5
             then $4::timestamptz
           else greatest(
             coalesce("lastAuthenticatedAt", $4::timestamptz),
             $4::timestamptz
           )
         end,
         "lastAuthenticationProvenance" = $6
     where "id" = (
       select "id"
       from "account"
       where "userId" = $1
         and "providerId" = $2
         and "accountId" = $3
       order by "updatedAt" desc, "id" asc
       limit 1
     )`,
    [
      userId,
      provider,
      accountId,
      authenticatedAt,
      connectorAuthenticationProvenance.legacyAccountActivityEstimate,
      connectorAuthenticationProvenance.federatedSession,
    ],
  );

  return result.rowCount === 1 ? "recorded" : "account_not_found";
}

function providerValue(value: unknown): AuthProviderId | undefined {
  return typeof value === "string" && authProviderIds.includes(value as AuthProviderId)
    ? (value as AuthProviderId)
    : undefined;
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function dateValue(value: unknown) {
  if (!(value instanceof Date) && typeof value !== "string" && typeof value !== "number") {
    return undefined;
  }
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : undefined;
}
