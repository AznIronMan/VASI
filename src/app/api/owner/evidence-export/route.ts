import { buildEngineActor } from "@/lib/engine-actor";
import { streamEngineEvidenceExport } from "@/lib/artifact-stream";
import { isCrossSiteRequest } from "@/lib/host-policy";
import { authorizeOwnerHeaders } from "@/lib/owner-access";

export async function GET(request: Request) {
  if (isCrossSiteRequest(request.headers)) {
    return Response.json({ error: "Cross-site export requests are not allowed." }, { status: 403 });
  }
  const authorization = await authorizeOwnerHeaders(request.headers);
  if (!authorization.ok) return authorization.response;
  const url = new URL(request.url);
  const kind = url.searchParams.get("kind") || "report";
  return streamEngineEvidenceExport({
    actor: await buildEngineActor(authorization.session, request.headers),
    chunkPath: "/v1/owner/evidence-export-chunks",
    openBody: {
      assignmentId: url.searchParams.get("assignmentId") || "",
      format: kind === "bundle" ? "zip" : url.searchParams.get("format") || "html",
      kind,
      profile: kind === "bundle" ? "full" : url.searchParams.get("profile") || "nontechnical",
      tenantId: url.searchParams.get("tenantId") || "",
    },
    openPath: "/v1/owner/evidence-exports",
  });
}
