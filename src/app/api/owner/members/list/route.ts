import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerMember } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerMember[]>(request, "/v1/owner/member-list");
}
