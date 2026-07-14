import { ownerEngineMutation } from "@/lib/owner-engine";
import type { OwnerMember } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<OwnerMember>(request, "/v1/owner/members");
}
