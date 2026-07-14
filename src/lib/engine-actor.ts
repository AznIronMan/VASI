import { database } from "@/lib/database";
import type { EngineActor } from "@/lib/engine-client";

type SessionIdentity = {
  session: { createdAt: Date | string; id: string };
  user: { email: string; id: string; role?: string | null };
};

export async function buildEngineActor(
  session: SessionIdentity,
  requestHeaders: Pick<Headers, "get">,
): Promise<EngineActor> {
  const provider = await database.query<{ accountId: string; providerId: string }>(
    `select "accountId", "providerId" from "account"
     where "userId" = $1
     order by "updatedAt" desc
     limit 1`,
    [session.user.id],
  );
  const providerId = provider.rows[0]?.providerId;
  const roles = String(session.user.role || "user")
    .split(",")
    .map((role) => role.trim())
    .filter(Boolean);

  return {
    authenticatedAt: Math.floor(new Date(session.session.createdAt).getTime() / 1000),
    authentication: {
      method: providerId === "credential" ? "password" : providerId || "vsign-session",
      provider: providerId && providerId !== "credential" ? providerId : undefined,
      providerSubject: providerId && providerId !== "credential"
        ? bounded(provider.rows[0]?.accountId)
        : undefined,
    },
    email: session.user.email.toLowerCase(),
    gatewaySessionId: session.session.id,
    principalId: session.user.id,
    requestContext: {
      acceptLanguage: bounded(requestHeaders.get("accept-language")),
      clientHints: clientHints(requestHeaders),
      ipAddress: bounded(
        requestHeaders.get("x-forwarded-for")?.split(",")[0]?.trim() ||
          requestHeaders.get("x-real-ip"),
      ),
      userAgent: bounded(requestHeaders.get("user-agent")),
    },
    roles,
    subject: session.user.id,
  };
}

function clientHints(headers: Pick<Headers, "get">) {
  const parts = [
    ["brands", headers.get("sec-ch-ua")],
    ["mobile", headers.get("sec-ch-ua-mobile")],
    ["platform", headers.get("sec-ch-ua-platform")],
  ]
    .filter((entry): entry is [string, string] => Boolean(entry[1]))
    .map(([name, value]) => `${name}=${value}`);
  return bounded(parts.join(";"));
}

function bounded(value?: string | null) {
  const normalized = value?.trim();
  return normalized ? normalized.slice(0, 512) : undefined;
}
