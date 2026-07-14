import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerIntegration } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerIntegration[]>(request, "/v1/owner/integration-list");
}
