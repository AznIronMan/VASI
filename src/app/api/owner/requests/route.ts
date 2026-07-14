import { ownerEngineMutation } from "@/lib/owner-engine";
import type { IssuedEvidenceRequest } from "@/lib/evidence-types";

export async function POST(request: Request) {
  return ownerEngineMutation<IssuedEvidenceRequest>(request, "/v1/owner/requests");
}
