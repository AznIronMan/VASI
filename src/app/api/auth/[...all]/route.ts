import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@/lib/auth";
import { isRequestForOrigin } from "@/lib/host-policy";
import { resolveServerEnvironment } from "@/lib/server-environment";

const handlers = toNextJsHandler(auth);
const { adminOrigin } = resolveServerEnvironment();

function isRestrictedAdminEndpoint(request: Request) {
  return new URL(request.url).pathname.startsWith("/api/auth/admin/");
}

function isAllowed(request: Request) {
  return !isRestrictedAdminEndpoint(request) ||
    isRequestForOrigin(request.headers, adminOrigin);
}

export async function GET(request: Request) {
  if (!isAllowed(request)) return new Response(null, { status: 404 });
  return handlers.GET(request);
}

export async function POST(request: Request) {
  if (!isAllowed(request)) return new Response(null, { status: 404 });
  return handlers.POST(request);
}
