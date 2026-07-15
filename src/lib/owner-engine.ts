import { buildEngineActor } from "@/lib/engine-actor";
import { boundedJSONObject } from "@/lib/bounded-json";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import { authorizeOwnerHeaders, authorizeOwnerMutation } from "@/lib/owner-access";

export async function ownerEngineQuery<T>(request: Request, path: string) {
  const authorization = await authorizeOwnerHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<T>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path },
  );
  return gatewayEngineResponse(result);
}

export async function ownerEngineMutation<T>(request: Request, path: string) {
  const authorization = await authorizeOwnerMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<T>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path },
  );
  return gatewayEngineResponse(result);
}
