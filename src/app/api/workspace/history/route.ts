import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { ParticipantHistoryRecord } from "@/lib/evidence-types";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export async function GET(request: Request) {
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const result = await requestEngineAction<ParticipantHistoryRecord[]>(
    await buildEngineActor(authorization.session, request.headers),
    { method: "GET", path: "/v1/participant/history" },
  );
  return gatewayEngineResponse(result);
}
