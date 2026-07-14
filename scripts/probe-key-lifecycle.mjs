import { generateKeyPairSync } from "node:crypto";

import { verifyDetachedIntegritySeal } from "../packages/engine-crypto/index.mjs";
import { createSigningProvider } from "../services/engine/signing-provider.mjs";

const oldProvider = createSigningProvider(settings("assurance-old"));
const newProvider = createSigningProvider(settings("assurance-new"));
const oldRecord = { record: "old", schema: "vasi-key-lifecycle-probe/v1" };
const newRecord = { record: "new", schema: "vasi-key-lifecycle-probe/v1" };
const oldSeal = oldProvider.signManifest(oldRecord)[0];
const newSeal = newProvider.signManifest(newRecord)[0];

assert(verifyDetachedIntegritySeal(oldRecord, oldSeal, ["vasi-integrity-seal/v1"]), "Old-key record did not verify.");
assert(verifyDetachedIntegritySeal(newRecord, newSeal, ["vasi-integrity-seal/v1"]), "New-key record did not verify.");
assert(!verifyDetachedIntegritySeal({ ...oldRecord, record: "altered" }, oldSeal, ["vasi-integrity-seal/v1"]), "Altered old-key record verified.");
expectFailure(() => createSigningProvider(mismatchedSettings()), "do not match");
expectFailure(() => createSigningProvider({
  ...settings("partial-certificate"),
  EVIDENCE_CERTIFICATE_KEY_ID: "missing-certificate-custody",
}), "requires its key ID, private key, and certificate chain");

console.info("VASI evidence-key rotation, historical verification, tamper, mismatch, and partial-custody checks passed.");

function settings(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    EVIDENCE_SEAL_KEY_ID: keyId,
    EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
    EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(publicKey.export({ format: "jwk" })),
  };
}

function mismatchedSettings() {
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  return {
    EVIDENCE_SEAL_KEY_ID: "assurance-mismatch",
    EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(first.privateKey.export({ format: "jwk" })),
    EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(second.publicKey.export({ format: "jwk" })),
  };
}

function expectFailure(operation, message) {
  try {
    operation();
  } catch (error) {
    if (error instanceof Error && error.message.includes(message)) return;
    throw error;
  }
  throw new Error(`Expected key-lifecycle failure containing: ${message}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
