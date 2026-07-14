import { authorizeAdminMutation } from "@/lib/admin-access";
import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { IssuedEvidenceRequest } from "@/lib/evidence-types";

export async function POST(request: Request) {
  const authorization = await authorizeAdminMutation(request);
  if (!authorization.ok) return authorization.response;
  const body = await request.json().catch(() => undefined);
  const result = await requestEngineAction<IssuedEvidenceRequest>(
    await buildEngineActor(authorization.session, request.headers),
    { body, method: "POST", path: "/v1/owner/requests" },
  );
  return gatewayEngineResponse(result);
}
