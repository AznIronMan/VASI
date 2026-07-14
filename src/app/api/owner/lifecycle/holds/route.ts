import { ownerEngineMutation } from "@/lib/owner-engine";
import type { OwnerLegalHold } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<OwnerLegalHold>(request, "/v1/owner/legal-holds");
}
