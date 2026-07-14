import { authorizeAdminHeaders } from "@/lib/admin-access";
import { database } from "@/lib/database";
import { requestEngineIdentity } from "@/lib/engine-client";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authorization = await authorizeAdminHeaders(request.headers);
  if (!authorization.ok) return authorization.response;

  const provider = await database.query<{ providerId: string }>(
    `select "providerId" from "account"
     where "userId" = $1
     order by "updatedAt" desc
     limit 1`,
    [authorization.session.user.id],
  );
  const providerId = provider.rows[0]?.providerId;
  const roles = String(authorization.session.user.role || "")
    .split(",")
    .map((role) => role.trim())
    .filter(Boolean);
  const identity = await requestEngineIdentity({
    authentication: {
      method: providerId === "credential" ? "password" : providerId || "vsign-session",
      provider: providerId && providerId !== "credential" ? providerId : undefined,
    },
    gatewaySessionId: authorization.session.session.id,
    principalId: authorization.session.user.id,
    roles,
    subject: authorization.session.user.id,
  });
  return Response.json(identity, {
    headers: { "cache-control": "no-store" },
  });
}
