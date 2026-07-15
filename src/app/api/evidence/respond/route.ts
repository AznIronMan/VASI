import { buildEngineActor } from "@/lib/engine-actor";
import { boundedJSONObject } from "@/lib/bounded-json";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { ParticipantReceipt } from "@/lib/evidence-types";
import { authorizeParticipantMutation } from "@/lib/participant-access";

export async function POST(request: Request) {
  const authorization = await authorizeParticipantMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<ParticipantReceipt>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/participant/respond" },
  );
  return gatewayEngineResponse(result);
}
