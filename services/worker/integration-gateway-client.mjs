import { randomUUID } from "node:crypto";

import { canonicalJSON, signServiceRequest } from "../../packages/engine-crypto/index.mjs";

export function createIntegrationGatewayClient(settings, dependencies = {}) {
  const origin = internalOrigin(settings.ENGINE_INTEGRATION_GATEWAY_ORIGIN);
  const secret = required(settings, "ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET");
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET must contain at least 32 bytes.");
  }
  const fetchImplementation = dependencies.fetch || fetch;
  return async (job) => {
    const command = {
      attempt: Number(job.attempt),
      capability: "notification.delivery",
      idempotencyKey: job.idempotencyKey,
      jobId: job.id,
      payload: job.payload,
      schema: "vasi-integration-delivery/v1",
      tenantId: job.tenantId,
    };
    const body = Buffer.from(canonicalJSON(command), "utf8");
    const requestId = randomUUID();
    const serviceId = "vasi-worker";
    const timestamp = Math.floor(Date.now() / 1_000);
    const path = "/v1/deliver";
    const signature = signServiceRequest({
      body,
      method: "POST",
      path,
      requestId,
      serviceId,
      timestamp,
    }, secret);
    const response = await fetchImplementation(new URL(path, origin), {
      body,
      headers: {
        "content-type": "application/json",
        "x-vasi-request-id": requestId,
        "x-vasi-service": serviceId,
        "x-vasi-signature": signature,
        "x-vasi-timestamp": String(timestamp),
      },
      method: "POST",
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw deliveryError("integration_gateway_rejected");
    return validateResponse(await response.json());
  };
}

function validateResponse(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") throw deliveryError("integration_gateway_invalid_response");
  if (!["delivered", "failed", "suppressed"].includes(value.outcome)) {
    throw deliveryError("integration_gateway_invalid_response");
  }
  if (typeof value.adapter !== "string" || !/^[a-z0-9_-]{1,64}$/.test(value.adapter)) {
    throw deliveryError("integration_gateway_invalid_response");
  }
  return Object.freeze({
    adapter: value.adapter,
    errorCode: typeof value.errorCode === "string" ? value.errorCode : undefined,
    outcome: value.outcome,
    responseMetadata: value.responseMetadata && typeof value.responseMetadata === "object"
      ? value.responseMetadata
      : {},
  });
}

function internalOrigin(value) {
  const url = new URL(required({ ENGINE_INTEGRATION_GATEWAY_ORIGIN: value }, "ENGINE_INTEGRATION_GATEWAY_ORIGIN"));
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("ENGINE_INTEGRATION_GATEWAY_ORIGIN must be an internal HTTP(S) origin.");
  }
  return url;
}

function required(settings, name) {
  const value = settings[name];
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  return value.trim();
}

function deliveryError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
