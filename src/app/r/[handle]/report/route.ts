import { buildEngineActor } from "@/lib/engine-actor";
import { streamEngineEvidenceExport } from "@/lib/artifact-stream";
import { isCrossSiteRequest } from "@/lib/host-policy";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export async function GET(request: Request, { params }: { params: Promise<{ handle: string }> }) {
  if (isCrossSiteRequest(request.headers)) {
    return Response.json({ error: "Cross-site export requests are not allowed." }, { status: 403 });
  }
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const { handle } = await params;
  const format = new URL(request.url).searchParams.get("format") || "html";
  return streamEngineEvidenceExport({
    actor: await buildEngineActor(authorization.session, request.headers),
    chunkPath: "/v1/participant/report-chunks",
    openBody: { format, handle },
    openPath: "/v1/participant/reports",
  });
}
