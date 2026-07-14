import { authorizeAdminHeaders } from "@/lib/admin-access";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineIdentity } from "@/lib/engine-client";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authorization = await authorizeAdminHeaders(request.headers);
  if (!authorization.ok) return authorization.response;

  const identity = await requestEngineIdentity(
    await buildEngineActor(authorization.session, request.headers),
  );
  return Response.json(identity, {
    headers: { "cache-control": "no-store" },
  });
}
