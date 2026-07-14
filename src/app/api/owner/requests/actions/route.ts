import { ownerEngineMutation } from "@/lib/owner-engine";

export async function POST(request: Request) {
  return ownerEngineMutation<unknown>(request, "/v1/owner/request-actions");
}
