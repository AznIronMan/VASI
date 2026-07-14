import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerRetentionPolicy } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerRetentionPolicy[]>(request, "/v1/owner/retention-policy-list");
}
