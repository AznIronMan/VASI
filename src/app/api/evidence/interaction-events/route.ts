import { buildEngineActor } from "@/lib/engine-actor";
import { requestEngineAction } from "@/lib/engine-client";
import { gatewayEngineResponse } from "@/lib/engine-response";
import type { ActivityInteractionSummary } from "@/lib/owner-types";
import { authorizeParticipantMutation } from "@/lib/participant-access";

export async function POST(request: Request) {
  const authorization = await authorizeParticipantMutation(request);
  if (!authorization.ok) return authorization.response;
  const body = await request.json().catch(() => undefined);
  const result = await requestEngineAction<{
    accepted: number;
    duplicate: boolean;
    revision?: number;
    summary?: ActivityInteractionSummary;
    summaryHash?: string;
  }>(
    await buildEngineActor(authorization.session, request.headers),
    { body, method: "POST", path: "/v1/participant/interaction-events" },
  );
  return gatewayEngineResponse(result);
}
