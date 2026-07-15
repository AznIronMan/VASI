import { randomUUID } from "node:crypto";

import { boundedJSONObject } from "@/lib/bounded-json";
import { resolveTrustedClientAddress } from "@/lib/client-address";
import { requestEngineAction, type EngineActor } from "@/lib/engine-client";
import { hasExpectedMutationOrigin, isRequestForOrigin } from "@/lib/host-policy";
import { getRuntimeSettings } from "@/lib/runtime-settings";
import { resolveServerSettings } from "@/lib/server-settings";
import { consumePublicVerificationRateLimit } from "@/lib/public-verification-rate-limit";

export async function POST(request: Request) {
  const settings = await getRuntimeSettings();
  const { authSecret, baseURL, trustedProxyCIDRs } = resolveServerSettings(settings);
  if (!isRequestForOrigin(request.headers, baseURL)) return new Response(null, { status: 404 });
  if (!hasExpectedMutationOrigin(request.headers, baseURL)) {
    return Response.json({ error: "Invalid request origin." }, { status: 403 });
  }
  const client = resolveTrustedClientAddress(request.headers, trustedProxyCIDRs);
  let rateLimit;
  try {
    rateLimit = await consumePublicVerificationRateLimit({
      address: client,
      authSecret,
    });
  } catch {
    console.error(JSON.stringify({ event: "public_verification_rate_limit_unavailable" }));
    return Response.json(
      { error: "Verification is temporarily unavailable." },
      { headers: { "cache-control": "no-store", "retry-after": "60" }, status: 503 },
    );
  }
  if (!rateLimit.accepted) {
    return Response.json(
      { error: "Too many verification attempts. Try again shortly." },
      {
        headers: {
          "cache-control": "no-store",
          "retry-after": String(rateLimit.retryAfterSeconds),
        },
        status: 429,
      },
    );
  }
  const parsed = await boundedJSONObject(request);
  if (!parsed.ok) return parsed.response;
  const payload = parsed.value;
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
      ipAddress: client,
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

function bounded(value?: string | null) {
  const normalized = value?.trim();
  return normalized ? normalized.slice(0, 512) : undefined;
}
