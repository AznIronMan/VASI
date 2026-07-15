import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
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
  return createDetachedIntegritySeal({
    keyId,
    payload: manifest,
    privateJWK,
    profile: "vasi-integrity-seal/v1",
  });
}

export function createDetachedIntegritySeal({ keyId, payload, privateJWK, profile }) {
  const manifestBytes = Buffer.from(canonicalJSON(payload), "utf8");
  const privateKey = createPrivateKey({ format: "jwk", key: privateJWK });
  const publicJWK = createPublicKey(privateKey).export({ format: "jwk" });
  return Object.freeze({
    algorithm: "Ed25519",
    keyId,
    manifestHash: sha256Hex(manifestBytes),
    profile: sealProfile(profile),
    publicJWK,
    signature: sign(null, manifestBytes, privateKey).toString("base64url"),
  });
}

export function verifyIntegritySeal(manifest, seal) {
  return verifyDetachedIntegritySeal(manifest, seal, ["vasi-integrity-seal/v1"]);
}

export function verifyDetachedIntegritySeal(payload, seal, allowedProfiles) {
  try {
    if (
      seal?.algorithm !== "Ed25519" ||
      !allowedProfiles.includes(seal?.profile) ||
      typeof seal.signature !== "string"
    ) {
      return false;
    }
    const manifestBytes = Buffer.from(canonicalJSON(payload), "utf8");
    if (sha256Hex(manifestBytes) !== seal.manifestHash) return false;
    const publicKey = createPublicKey({ format: "jwk", key: seal.publicJWK });
    return verify(null, manifestBytes, publicKey, Buffer.from(seal.signature, "base64url"));
  } catch {
    return false;
  }
}

export function createCertificateSeal({ certificateChainPEM, keyId, payload, privateKeyPEM }) {
  const chain = certificateChain(certificateChainPEM);
  const certificate = new X509Certificate(chain[0]);
  const privateKey = createPrivateKey(privateKeyPEM);
  if (!certificate.checkPrivateKey(privateKey)) {
    throw new Error("The certificate seal private key does not match its leaf certificate.");
  }
  const algorithm = certificateAlgorithm(privateKey.asymmetricKeyType);
  const manifestBytes = Buffer.from(canonicalJSON(payload), "utf8");
  return Object.freeze({
    algorithm: algorithm.label,
    certificate: Object.freeze({
      fingerprint256: certificate.fingerprint256.replaceAll(":", "").toLowerCase(),
      issuer: certificate.issuer,
      serialNumber: certificate.serialNumber,
      subject: certificate.subject,
      validFrom: new Date(certificate.validFrom).toISOString(),
      validTo: new Date(certificate.validTo).toISOString(),
    }),
    certificateChain: Object.freeze(chain),
    keyId,
    manifestHash: sha256Hex(manifestBytes),
    profile: "vasi-certificate-seal/v1",
    publicJWK: certificate.publicKey.export({ format: "jwk" }),
    signature: sign(algorithm.node, manifestBytes, privateKey).toString("base64url"),
    validationScope: "leaf_signature_and_key_match",
  });
}

export function verifyCertificateSeal(payload, seal) {
  try {
    if (
      seal?.profile !== "vasi-certificate-seal/v1" ||
      !Array.isArray(seal.certificateChain) ||
      !seal.certificateChain.length ||
      typeof seal.signature !== "string" ||
      seal.validationScope !== "leaf_signature_and_key_match"
    ) return false;
    const certificate = new X509Certificate(seal.certificateChain[0]);
    const expectedFingerprint = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
    const expectedMetadata = {
      fingerprint256: expectedFingerprint,
      issuer: certificate.issuer,
      serialNumber: certificate.serialNumber,
      subject: certificate.subject,
      validFrom: new Date(certificate.validFrom).toISOString(),
      validTo: new Date(certificate.validTo).toISOString(),
    };
    if (
      hashCanonicalJSON(seal.certificate) !== hashCanonicalJSON(expectedMetadata) ||
      hashCanonicalJSON(seal.publicJWK) !==
        hashCanonicalJSON(certificate.publicKey.export({ format: "jwk" }))
    ) return false;
    const manifestBytes = Buffer.from(canonicalJSON(payload), "utf8");
    if (sha256Hex(manifestBytes) !== seal.manifestHash) return false;
    const algorithm = certificateAlgorithm(certificate.publicKey.asymmetricKeyType);
    if (seal.algorithm !== algorithm.label) return false;
    return verify(
      algorithm.node,
      manifestBytes,
      certificate.publicKey,
      Buffer.from(seal.signature, "base64url"),
    );
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

function sealProfile(value) {
  if (typeof value !== "string" || !/^vasi-[a-z0-9-]+\/v[1-9][0-9]*$/.test(value)) {
    throw new Error("The VASI seal profile is invalid.");
  }
  return value;
}

function certificateChain(value) {
  if (typeof value !== "string" || value.length > 100_000) {
    throw new Error("The certificate seal chain is invalid.");
  }
  const chain = value.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  if (!chain.length || chain.length > 10) throw new Error("The certificate seal chain is invalid.");
  for (const certificate of chain) new X509Certificate(certificate);
  return chain;
}

function certificateAlgorithm(keyType) {
  if (keyType === "ed25519") return { label: "Ed25519", node: null };
  if (keyType === "rsa" || keyType === "rsa-pss") return { label: "RSA-SHA256", node: "sha256" };
  if (keyType === "ec") return { label: "ECDSA-SHA256", node: "sha256" };
  throw new Error("The certificate seal key algorithm is unsupported.");
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
