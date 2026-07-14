import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

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

export function canonicalJSON(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function hashCanonicalJSON(value) {
  return sha256Hex(canonicalJSON(value));
}

export function createIntegritySeal({ keyId, manifest, privateJWK }) {
  const manifestBytes = Buffer.from(canonicalJSON(manifest), "utf8");
  const privateKey = createPrivateKey({ format: "jwk", key: privateJWK });
  const publicJWK = createPublicKey(privateKey).export({ format: "jwk" });
  return Object.freeze({
    algorithm: "Ed25519",
    keyId,
    manifestHash: sha256Hex(manifestBytes),
    profile: "vasi-integrity-seal/v1",
    publicJWK,
    signature: sign(null, manifestBytes, privateKey).toString("base64url"),
  });
}

export function verifyIntegritySeal(manifest, seal) {
  try {
    if (
      seal?.algorithm !== "Ed25519" ||
      seal?.profile !== "vasi-integrity-seal/v1" ||
      typeof seal.signature !== "string"
    ) {
      return false;
    }
    const manifestBytes = Buffer.from(canonicalJSON(manifest), "utf8");
    if (sha256Hex(manifestBytes) !== seal.manifestHash) return false;
    const publicKey = createPublicKey({ format: "jwk", key: seal.publicJWK });
    return verify(null, manifestBytes, publicKey, Buffer.from(seal.signature, "base64url"));
  } catch {
    return false;
  }
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Canonical VASI JSON accepts only safe integers.");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    const object = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) object[key] = canonicalValue(value[key]);
    }
    return object;
  }
  throw new Error("The value cannot be represented as canonical VASI JSON.");
}
