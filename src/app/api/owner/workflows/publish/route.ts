import { ownerEngineMutation } from "@/lib/owner-engine";
import type { PublishedWorkflow } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<PublishedWorkflow>(request, "/v1/owner/workflow-publications");
}
