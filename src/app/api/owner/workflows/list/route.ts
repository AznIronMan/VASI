import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerWorkflow } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerWorkflow[]>(request, "/v1/owner/workflow-list");
}
