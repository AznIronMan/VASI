import { randomUUID } from "node:crypto";

import { requestEngineAction, type EngineActor } from "@/lib/engine-client";
import { hasExpectedMutationOrigin, isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";

const attempts = new Map<string, { count: number; expiresAt: number }>();
const WINDOW_MILLISECONDS = 60_000;
const WINDOW_LIMIT = 20;

export async function POST(request: Request) {
  const settings = await getRuntimeSettings();
  const { baseURL } = resolveServerSettings(settings);
  if (!isRequestForOrigin(request.headers, baseURL)) return new Response(null, { status: 404 });
  if (!hasExpectedMutationOrigin(request.headers, baseURL)) {
    return Response.json({ error: "Invalid request origin." }, { status: 403 });
  }
  const client = clientAddress(request.headers);
  if (!acceptAttempt(client)) {
    return Response.json(
      { error: "Too many verification attempts. Try again shortly." },
      { headers: { "cache-control": "no-store", "retry-after": "60" }, status: 429 },
    );
  }
  const payload = await request.json().catch(() => undefined);
  const fingerprint = typeof payload?.fingerprint === "string"
    ? payload.fingerprint.trim().toLowerCase()
    : "";
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) {
    return Response.json(
      { error: "Enter a 64-character VASI manifest fingerprint." },
      { headers: { "cache-control": "no-store" }, status: 400 },
    );
  }
  const actor: EngineActor = {
    authentication: { method: "public_manifest_verification", provenance: "gateway/v1" },
    gatewaySessionId: randomUUID(),
    principalId: "vasi-public-verifier",
    requestContext: {
      acceptLanguage: bounded(request.headers.get("accept-language")),
      ipAddress: bounded(client),
      userAgent: bounded(request.headers.get("user-agent")),
    },
    roles: ["verification"],
    subject: "vasi-public-verifier",
  };
  const result = await requestEngineAction<Record<string, unknown>>(actor, {
    body: { fingerprint },
    method: "POST",
    path: "/v1/public/verification",
  });
  return Response.json(result.body || { error: "Verification is temporarily unavailable." }, {
    headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
    status: result.status || 502,
  });
}

function acceptAttempt(key: string) {
  const now = Date.now();
  for (const [candidate, state] of attempts) {
    if (state.expiresAt <= now) attempts.delete(candidate);
  }
  const state = attempts.get(key);
  if (!state) {
    attempts.set(key, { count: 1, expiresAt: now + WINDOW_MILLISECONDS });
    return true;
  }
  state.count += 1;
  return state.count <= WINDOW_LIMIT;
}

function clientAddress(headers: Headers) {
  return headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    headers.get("x-real-ip")?.trim() || "unknown";
}

function bounded(value?: string | null) {
  const normalized = value?.trim();
  return normalized ? normalized.slice(0, 512) : undefined;
}
