import { authorizeAdminMutation } from "@/lib/admin-access";
import { boundedJSONObject } from "@/lib/bounded-json";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { AdminTenantAdmission } from "@/lib/owner-types";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<AdminTenantAdmission>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/admin/tenant-production-stops" },
  );
  return gatewayEngineResponse(result);
}
