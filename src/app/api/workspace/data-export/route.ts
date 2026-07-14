import { buildEngineActor } from "@/lib/engine-actor";
import { streamEngineParticipantDataExport } from "@/lib/artifact-stream";
import { isCrossSiteRequest } from "@/lib/host-policy";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export async function GET(request: Request) {
  if (isCrossSiteRequest(request.headers)) {
    return Response.json({ error: "Cross-site export requests are not allowed." }, { status: 403 });
  }
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const requestId = new URL(request.url).searchParams.get("requestId") || "";
  return streamEngineParticipantDataExport({
    actor: await buildEngineActor(authorization.session, request.headers),
    requestId,
  });
}
