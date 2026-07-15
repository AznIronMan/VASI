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
  const response = await streamEngineParticipantDataExport({
    actor: await buildEngineActor(authorization.session, request.headers),
    requestId,
  });
  if (response.status === 401) {
    const body = await response.clone().json().catch(() => undefined) as { code?: string } | undefined;
    if (body?.code === "reauthentication_required") {
      return Response.redirect(new URL("/workspace?privacyReauthentication=required", request.url), 303);
    }
  }
  return response;
}
