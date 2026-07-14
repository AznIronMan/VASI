import { authorizeAdminMutation } from "@/lib/admin-access";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { AdminTenantAdmission } from "@/lib/owner-types";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;
  const body = await request.json().catch(() => undefined);
  const result = await requestEngineAction<AdminTenantAdmission>(
    await buildEngineActor(authorization.session, request.headers),
    { body, method: "POST", path: "/v1/admin/tenant-production-stops" },
  );
  return gatewayEngineResponse(result);
}
