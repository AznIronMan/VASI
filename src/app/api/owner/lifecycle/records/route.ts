import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerLifecycleRecord } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerLifecycleRecord[]>(request, "/v1/owner/lifecycle-record-list");
}
