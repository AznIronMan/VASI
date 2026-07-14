import { ownerEngineQuery } from "@/lib/owner-engine";
import type { OwnerTenantUsage } from "@/lib/owner-types";

export async function POST(request: Request) {
  return ownerEngineQuery<OwnerTenantUsage>(request, "/v1/owner/tenant-usage");
}
