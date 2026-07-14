import { toNextJsHandler } from "better-auth/next-js";

import { getAuth } from "@/lib/auth";
import { isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

function isRestrictedAdminEndpoint(request: Request) {
  return new URL(request.url).pathname.startsWith("/api/auth/admin/");
}

async function isAllowed(request: Request) {
  if (!isRestrictedAdminEndpoint(request)) return true;
  const { adminOrigin } = resolveServerSettings(await getRuntimeSettings());
  return isRequestForOrigin(request.headers, adminOrigin);
}

async function handle(request: Request, method: "GET" | "POST") {
  if (!(await isAllowed(request))) return new Response(null, { status: 404 });
  const handlers = toNextJsHandler(await getAuth());
  return handlers[method](request);
}

export function GET(request: Request) {
  return handle(request, "GET");
}

export function POST(request: Request) {
  return handle(request, "POST");
}
