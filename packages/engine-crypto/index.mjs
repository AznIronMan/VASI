import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function bodyDigest(body = Buffer.alloc(0)) {
  return createHash("sha256").update(body).digest("hex");
}

export function canonicalServiceRequest({
  body,
  method,
  path,
  requestId,
  serviceId,
  timestamp,
}) {
  return [
    String(timestamp),
    requestId,
    serviceId,
    method.toUpperCase(),
    path,
    bodyDigest(body),
  ].join("\n");
}

export function signServiceRequest(request, secret) {
  return createHmac("sha256", secret)
    .update(canonicalServiceRequest(request))
    .digest("base64url");
}

export function verifyServiceRequest(request, secret, signature) {
  if (typeof signature !== "string" || !signature) return false;
  const expected = Buffer.from(signServiceRequest(request, secret), "utf8");
  const supplied = Buffer.from(signature, "utf8");
  return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}
