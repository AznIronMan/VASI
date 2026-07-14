import { randomUUID } from "node:crypto";

import { canonicalJSON, signServiceRequest } from "../../packages/engine-crypto/index.mjs";

export function createArtifactScanClient(settings, dependencies = {}) {
  const origin = internalOrigin(settings.ENGINE_INTEGRATION_GATEWAY_ORIGIN);
  const secret = required(settings, "ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET");
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET must contain at least 32 bytes.");
  }
  const fetchImplementation = dependencies.fetch || fetch;
  const newId = dependencies.randomUUID || randomUUID;
  return async (artifact) => {
    const command = {
      artifactId: artifact.id,
      byteLength: artifact.byteLength,
      capability: "document.malware_scan",
      mediaType: artifact.mediaType,
      scanRequestId: newId(),
      schema: "vasi-artifact-scan/v1",
      sha256: artifact.sha256,
      tenantId: artifact.tenantId,
    };
    const body = Buffer.from(canonicalJSON(command), "utf8");
    const requestId = newId();
    const serviceId = "vasi-engine";
    const timestamp = Math.floor((dependencies.now?.() || Date.now()) / 1_000);
    const path = "/v1/scan";
    const signature = signServiceRequest({
      body,
      method: "POST",
      path,
      requestId,
      serviceId,
      timestamp,
    }, secret);
    let response;
    try {
      response = await fetchImplementation(new URL(path, origin), {
        body,
        headers: {
          "content-type": "application/json",
          "x-vasi-request-id": requestId,
          "x-vasi-service": serviceId,
          "x-vasi-signature": signature,
          "x-vasi-timestamp": String(timestamp),
        },
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(305_000),
      });
    } catch {
      throw scanClientError("integration_gateway_unavailable");
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw scanClientError("integration_gateway_rejected");
    }
    let value;
    try {
      value = await boundedJSON(response, 16_384);
    } catch {
      throw scanClientError("integration_gateway_invalid_response");
    }
    return validateResponse(value);
  };
}

function validateResponse(value) {
  const input = strictObject(value, [
    "adapter", "adapterVersion", "attemptId", "bindingRevisionId", "errorCode", "outcome",
    "responseMetadata", "scanRequestId", "verdict",
  ]);
  if (!["completed", "failed"].includes(input.outcome)) {
    throw scanClientError("integration_gateway_invalid_response");
  }
  const adapter = token(input.adapter, 64);
  const adapterVersion = token(input.adapterVersion, 32);
  const attemptId = token(input.attemptId, 512);
  const bindingRevisionId = input.bindingRevisionId === undefined ? undefined : token(input.bindingRevisionId, 512);
  const errorCode = input.errorCode === undefined ? undefined : token(input.errorCode, 64);
  const scanRequestId = token(input.scanRequestId, 512);
  const verdict = input.verdict === undefined ? undefined : token(input.verdict, 32);
  if (
    (input.outcome === "completed" && !["clean", "malicious", "suspicious"].includes(verdict)) ||
    (input.outcome === "failed" && (verdict !== undefined || !errorCode))
  ) {
    throw scanClientError("integration_gateway_invalid_response");
  }
  const metadata = strictObject(input.responseMetadata, [
    "reasonCode", "scanner", "scannerVersion", "signatureSet",
  ]);
  return Object.freeze({
    adapter,
    adapterVersion,
    attemptId,
    bindingRevisionId,
    errorCode,
    outcome: input.outcome,
    responseMetadata: Object.freeze(Object.fromEntries(Object.entries(metadata).map(([key, entry]) => [
      key,
      safeText(entry, key === "signatureSet" ? 160 : key === "reasonCode" ? 64 : 80),
    ]))),
    scanRequestId,
    verdict,
  });
}

async function boundedJSON(response, maximumBytes) {
  if (!response.body) throw new Error("missing_body");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error("response_limit");
    }
    chunks.push(Buffer.from(value));
  }
  return JSON.parse(Buffer.concat(chunks, total).toString("utf8"));
}

function strictObject(value, allowedKeys) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw scanClientError("integration_gateway_invalid_response");
  }
  if (Object.keys(value).some((key) => !allowedKeys.includes(key))) {
    throw scanClientError("integration_gateway_invalid_response");
  }
  return value;
}

function token(value, maximum) {
  if (typeof value !== "string" || value.length > maximum || !/^[A-Za-z0-9._:-]+$/.test(value)) {
    throw scanClientError("integration_gateway_invalid_response");
  }
  return value;
}

function safeText(value, maximum) {
  if (typeof value !== "string") throw scanClientError("integration_gateway_invalid_response");
  const normalized = value.normalize("NFC").trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw scanClientError("integration_gateway_invalid_response");
  }
  return normalized;
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

function scanClientError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}
