import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  randomBytes,
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

export function encryptJSONEnvelope(value, secret) {
  const key = envelopeKey(secret);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(canonicalJSON(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Object.freeze({
    algorithm: "A256GCM",
    ciphertext: ciphertext.toString("base64url"),
    iv: iv.toString("base64url"),
    schema: "vasi-encrypted-envelope/v1",
    tag: cipher.getAuthTag().toString("base64url"),
  });
}

export function decryptJSONEnvelope(envelope, secret) {
  if (
    envelope?.schema !== "vasi-encrypted-envelope/v1" ||
    envelope?.algorithm !== "A256GCM"
  ) {
    throw new Error("The encrypted VASI envelope is invalid.");
  }
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      envelopeKey(secret),
      Buffer.from(envelope.iv, "base64url"),
    );
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
      decipher.final(),
    ]);
    return JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("The encrypted VASI envelope could not be authenticated.");
  }
}

function envelopeKey(secret) {
  if (typeof secret !== "string") throw new Error("The VASI envelope secret is invalid.");
  const key = Buffer.from(secret, "base64url");
  if (key.length !== 32) throw new Error("The VASI envelope secret must contain 32 bytes.");
  return key;
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
