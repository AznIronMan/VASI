import { buildEngineActor } from "@/lib/engine-actor";
import { streamEngineEvidenceExport } from "@/lib/artifact-stream";
import { isCrossSiteRequest } from "@/lib/host-policy";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export async function GET(request: Request) {
  if (isCrossSiteRequest(request.headers)) {
    return Response.json({ error: "Cross-site export requests are not allowed." }, { status: 403 });
  }
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const url = new URL(request.url);
  return streamEngineEvidenceExport({
    actor: await buildEngineActor(authorization.session, request.headers),
    chunkPath: "/v1/participant/report-chunks",
    openBody: {
      assignmentId: url.searchParams.get("assignmentId") || "",
      format: url.searchParams.get("format") || "html",
    },
    openPath: "/v1/participant/reports",
  });
}
