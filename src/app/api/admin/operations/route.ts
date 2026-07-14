import { authorizeAdminHeaders } from "@/lib/admin-access";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { OperationalSnapshot } from "@/lib/operational-readiness";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authorization = await authorizeAdminHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const result = await requestEngineAction<OperationalSnapshot>(
    await buildEngineActor(authorization.session, request.headers),
    { method: "GET", path: "/v1/admin/operations" },
  );
  return gatewayEngineResponse(result);
}
