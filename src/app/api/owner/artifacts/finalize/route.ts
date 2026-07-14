import { ownerEngineMutation } from "@/lib/owner-engine";
import type { OwnerArtifact } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<OwnerArtifact>(request, "/v1/owner/artifact-finalizations");
}
