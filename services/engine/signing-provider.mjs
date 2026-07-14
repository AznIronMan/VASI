import { randomUUID } from "node:crypto";

import {
  createCertificateSeal,
  createDetachedIntegritySeal,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";

export function createSigningProvider(settings) {
  const privateJWK = parseJWK(settings.EVIDENCE_SEAL_PRIVATE_JWK, "private");
  const publicJWK = parseJWK(settings.EVIDENCE_SEAL_PUBLIC_JWK, "public");
  const keyId = requiredSetting(settings, "EVIDENCE_SEAL_KEY_ID");
  const proof = createDetachedIntegritySeal({
    keyId,
    payload: { keyId, schema: "vasi-seal-key-check/v1" },
    privateJWK,
    profile: "vasi-integrity-seal/v1",
  });
  if (hashCanonicalJSON(proof.publicJWK) !== hashCanonicalJSON(publicJWK)) {
    throw new Error("The VASI evidence seal private and public keys do not match.");
  }

  const certificate = certificateConfiguration(settings);
  const keyRecords = [Object.freeze({
    algorithm: "Ed25519",
    certificateChain: undefined,
    fingerprint: signingKeyFingerprint({ publicJWK }),
    keyId,
    metadata: { profile: "vasi-integrity-seal/v1", provider: "local_jwk" },
    publicJWK,
    sealRole: "vasi_integrity",
  })];
  if (certificate) {
    const certificateProof = createCertificateSeal({
      certificateChainPEM: certificate.chain,
      keyId: certificate.keyId,
      payload: { keyId: certificate.keyId, schema: "vasi-certificate-key-check/v1" },
      privateKeyPEM: certificate.privateKey,
    });
    keyRecords.push(Object.freeze({
      algorithm: certificateProof.algorithm,
      certificateChain: certificateProof.certificateChain,
      fingerprint: signingKeyFingerprint({
        certificateChain: certificateProof.certificateChain,
        publicJWK: certificateProof.publicJWK,
      }),
      keyId: certificate.keyId,
      metadata: {
        certificate: certificateProof.certificate,
        profile: certificateProof.profile,
        provider: "local_x509",
        validationScope: certificateProof.validationScope,
      },
      publicJWK: certificateProof.publicJWK,
      sealRole: "certificate",
    }));
  }

  function sign(payload, profile) {
    const seals = [{
      ...createDetachedIntegritySeal({ keyId, payload, privateJWK, profile }),
      role: "vasi_integrity",
    }];
    if (certificate) {
      seals.push({
        ...createCertificateSeal({
          certificateChainPEM: certificate.chain,
          keyId: certificate.keyId,
          payload,
          privateKeyPEM: certificate.privateKey,
        }),
        role: "certificate",
      });
    }
    return Object.freeze(seals.map((seal) => Object.freeze(seal)));
  }

  return Object.freeze({
    keyRecords: Object.freeze(keyRecords),
    primaryPublicJWK: publicJWK,
    signBundleIndex(index) {
      return sign(index, "vasi-bundle-seal/v1");
    },
    signManifest(manifest) {
      return sign(manifest, "vasi-integrity-seal/v1");
    },
  });
}

export async function ensureSigningKeys(client, provider) {
  for (const key of provider.keyRecords) {
    const inserted = await client.query(
      `insert into "vasi_engine"."evidence_seal_key"
        ("keyId", "sealRole", "algorithm", "publicJwk", "certificateChain", "fingerprint", "metadata")
       values ($1, $2, $3, $4, $5, $6, $7)
       on conflict ("keyId") do nothing returning "keyId"`,
      [
        key.keyId,
        key.sealRole,
        key.algorithm,
        key.publicJWK || null,
        key.certificateChain ? JSON.stringify(key.certificateChain) : null,
        key.fingerprint,
        key.metadata,
      ],
    );
    if (inserted.rowCount) {
      await client.query(
        `insert into "vasi_engine"."evidence_seal_key_status_event"
          ("id", "keyId", "status", "reason", "recordedByPrincipalId")
         values ($1, $2, 'active', 'registered by the configured signing provider', 'vasi-engine')`,
        [randomUUID(), key.keyId],
      );
    }
    const existing = await client.query(
      `select "sealRole", "algorithm", "fingerprint"
       from "vasi_engine"."evidence_seal_key" where "keyId" = $1`,
      [key.keyId],
    );
    const registered = existing.rows[0];
    if (
      !registered || registered.sealRole !== key.sealRole ||
      registered.algorithm !== key.algorithm || registered.fingerprint !== key.fingerprint
    ) {
      throw new Error(`The registered VASI signing key ${key.keyId} conflicts with runtime custody.`);
    }
  }
}

function certificateConfiguration(settings) {
  const chain = optionalSetting(settings, "EVIDENCE_CERTIFICATE_CHAIN_PEM");
  const privateKey = optionalSetting(settings, "EVIDENCE_CERTIFICATE_PRIVATE_KEY_PEM");
  const keyId = optionalSetting(settings, "EVIDENCE_CERTIFICATE_KEY_ID");
  if (!chain && !privateKey && !keyId) return undefined;
  if (!chain || !privateKey || !keyId) {
    throw new Error("The optional VASI certificate seal requires its key ID, private key, and certificate chain.");
  }
  return Object.freeze({ chain, keyId, privateKey });
}

function parseJWK(value, label) {
  try {
    const parsed = JSON.parse(value);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error();
    return parsed;
  } catch {
    throw new Error(`The VASI evidence seal ${label} JWK is invalid.`);
  }
}

function requiredSetting(settings, key) {
  const value = optionalSetting(settings, key);
  if (!value) throw new Error(`Missing required VASI setting ${key}.`);
  return value;
}

function optionalSetting(settings, key) {
  const value = settings?.[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function signingKeyFingerprint(key) {
  if (!key.publicJWK) throw new Error("The VASI signing key public material is missing.");
  return hashCanonicalJSON({
    certificateChain: key.certificateChain?.length ? key.certificateChain : undefined,
    publicJWK: key.publicJWK,
  });
}
