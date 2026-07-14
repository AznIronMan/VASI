import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerDataRequestReview } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerDataRequestReview[]>(request, "/v1/owner/data-request-review-list");
}
