import { ownerEngineMutation } from "@/lib/owner-engine";
import type { OwnerRetentionPolicy } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<OwnerRetentionPolicy>(request, "/v1/owner/retention-policies");
}
