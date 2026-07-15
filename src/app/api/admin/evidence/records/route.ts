import { authorizeAdminMutation } from "@/lib/admin-access";
import { boundedJSONObject } from "@/lib/bounded-json";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<unknown>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/owner/records" },
  );
  return gatewayEngineResponse(result);
}
