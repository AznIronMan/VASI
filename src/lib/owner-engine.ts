import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import { authorizeOwnerHeaders, authorizeOwnerMutation } from "@/lib/owner-access";

export async function ownerEngineQuery<T>(request: Request, path: string) {
  const authorization = await authorizeOwnerHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const body = await request.json().catch(() => undefined);
  const result = await requestEngineAction<T>(
    await buildEngineActor(authorization.session, request.headers),
    { body, method: "POST", path },
  );
  return gatewayEngineResponse(result);
}

export async function ownerEngineMutation<T>(request: Request, path: string) {
  const authorization = await authorizeOwnerMutation(request);
  if (!authorization.ok) return authorization.response;
  const body = await request.json().catch(() => undefined);
  const result = await requestEngineAction<T>(
    await buildEngineActor(authorization.session, request.headers),
    { body, method: "POST", path },
  );
  return gatewayEngineResponse(result);
}
