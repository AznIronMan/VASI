import { buildEngineActor } from "@/lib/engine-actor";
import { boundedJSONObject } from "@/lib/bounded-json";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { ParticipantDataRequest } from "@/lib/evidence-types";
import {
  authorizeParticipantHeaders,
  authorizeParticipantMutation,
} from "@/lib/participant-access";

export async function GET(request: Request) {
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const result = await requestEngineAction<ParticipantDataRequest[]>(
    await buildEngineActor(authorization.session, request.headers),
    { method: "GET", path: "/v1/participant/data-requests" },
  );
  return gatewayEngineResponse(result);
}

export async function POST(request: Request) {
  const authorization = await authorizeParticipantMutation(request);
  if (!authorization.ok) return authorization.response;
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const result = await requestEngineAction<ParticipantDataRequest>(
    await buildEngineActor(authorization.session, request.headers),
    { body: parsed.value, method: "POST", path: "/v1/participant/data-requests" },
  );
  return gatewayEngineResponse(result);
}
