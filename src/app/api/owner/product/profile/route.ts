import { ownerEngineMutation } from "@/lib/owner-engine";
import type { OwnerTenantProfile } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineMutation<OwnerTenantProfile>(request, "/v1/owner/tenant-profiles");
}
