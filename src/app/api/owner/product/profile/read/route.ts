import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerTenantProfile } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerTenantProfile>(request, "/v1/owner/tenant-profile-read");
}
