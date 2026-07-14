import { buildEngineActor } from "@/lib/engine-actor";
import { streamEngineArtifact } from "@/lib/artifact-stream";
import { authorizeParticipantHeaders } from "@/lib/participant-access";

export async function GET(request: Request, {
  params,
}: {
  params: Promise<{ artifactId: string; handle: string }>;
}) {
  const authorization = await authorizeParticipantHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const { artifactId, handle } = await params;
  const url = new URL(request.url);
  const activityId = url.searchParams.get("activityId") || "";
  const disposition = url.searchParams.get("disposition") === "attachment" ? "attachment" : "inline";
  return streamEngineArtifact({
    actor: await buildEngineActor(authorization.session, request.headers),
    chunkPath: "/v1/participant/artifact-read",
    openBody: { activityId, artifactId, disposition, handle },
    openPath: "/v1/participant/artifact-open",
  });
}
