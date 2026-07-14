import { buildEngineActor } from "@/lib/engine-actor";
import { streamEngineArtifact } from "@/lib/artifact-stream";
import { authorizeOwnerHeaders } from "@/lib/owner-access";

export async function GET(request: Request, { params }: { params: Promise<{ artifactId: string }> }) {
  const authorization = await authorizeOwnerHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const { artifactId } = await params;
  const url = new URL(request.url);
  const tenantId = url.searchParams.get("tenantId") || "";
  const disposition = url.searchParams.get("disposition") === "attachment" ? "attachment" : "inline";
  return streamEngineArtifact({
    actor: await buildEngineActor(authorization.session, request.headers),
    chunkPath: "/v1/owner/artifact-read",
    openBody: { artifactId, disposition, tenantId },
    openPath: "/v1/owner/artifact-open",
  });
}
