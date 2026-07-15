import { authorizeAdminHeaders, authorizeAdminMutation } from "@/lib/admin-access";
import { boundedJSONObject } from "@/lib/bounded-json";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { AdminInstallationProfile } from "@/lib/owner-types";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const authorization = await authorizeAdminHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const result = await requestEngineAction<AdminInstallationProfile>(
    await buildEngineActor(authorization.session, request.headers),
    { method: "GET", path: "/v1/admin/installation-profile" },
  );
  return gatewayEngineResponse(result);
}

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<AdminInstallationProfile>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/admin/installation-profile" },
  );
  return gatewayEngineResponse(result);
}
