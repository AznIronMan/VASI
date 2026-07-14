import { ownerEngineMutation } from "@/lib/owner-engine";
import type { OwnerIntegration } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<OwnerIntegration>(request, "/v1/owner/integrations");
}
