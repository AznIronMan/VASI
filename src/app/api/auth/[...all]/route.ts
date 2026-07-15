import { toNextJsHandler } from "better-auth/next-js";

import { getAuth } from "@/lib/auth";
import { boundedRequestBody } from "@/lib/bounded-json";
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
  if (!(await isAllowed(request))) return noStoreAuthenticationResponse(new Response(null, { status: 404 }));
  if (method === "POST") {
    const bounded = await boundedRequestBody(request);
    if (!bounded.ok) return noStoreAuthenticationResponse(bounded.response);
    request = bounded.request;
  }
  const handlers = toNextJsHandler(await getAuth());
  return noStoreAuthenticationResponse(await handlers[method](request));
}

function noStoreAuthenticationResponse(response: Response) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
}

export function GET(request: Request) {
  return handle(request, "GET");
}

export function POST(request: Request) {
  return handle(request, "POST");
}
