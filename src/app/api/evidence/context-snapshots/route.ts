import { buildEngineActor } from "@/lib/engine-actor";
import { boundedJSONObject } from "@/lib/bounded-json";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import { authorizeParticipantMutation } from "@/lib/participant-access";

export async function POST(request: Request) {
  const authorization = await authorizeParticipantMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<{
    accepted: boolean;
    duplicate: boolean;
    payloadHash: string;
    snapshotId: string;
  }>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/participant/context-snapshots" },
  );
  return gatewayEngineResponse(result);
}
