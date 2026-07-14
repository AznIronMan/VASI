import { ownerEngineMutation } from "@/lib/owner-engine";
import type { ParticipantDataRequest } from "@/lib/evidence-types";

export async function POST(request: Request) {
  return ownerEngineMutation<ParticipantDataRequest>(request, "/v1/owner/data-request-reviews");
}
