import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerRequest } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerRequest[]>(request, "/v1/owner/request-list");
}
