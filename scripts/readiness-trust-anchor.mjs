import process from "node:process";

import {
  loadBootstrapSettings,
  readRuntimeSettings,
} from "./settings-core.mjs";
import {
  createSigningProvider,
  signingKeyFingerprint,
} from "../services/engine/signing-provider.mjs";
import { isDirectExecution } from "./direct-execution.mjs";

export const READINESS_TRUST_ANCHOR_SCHEMA = "vasi-readiness-trust-anchor/v1";

export class ReadinessTrustAnchorError extends Error {
  constructor(code) {
    super("VASI readiness trust anchor unavailable.");
    this.code = code;
    this.name = "ReadinessTrustAnchorError";
  }
}

export async function readReadinessTrustAnchor({
  createProvider = createSigningProvider,
  loadBootstrap = loadBootstrapSettings,
  readSettings = readRuntimeSettings,
} = {}) {
  try {
    const bootstrap = loadBootstrap();
    const settings = await readSettings({ bootstrap, scope: "engine" });
    const provider = createProvider(settings);
    return trustAnchorFromProvider(provider);
  } catch (error) {
    if (error instanceof ReadinessTrustAnchorError) throw error;
    fail("trust_anchor_unavailable");
  }
}

export async function runReadinessTrustAnchor(argumentsList, dependencies) {
  if (!Array.isArray(argumentsList) || argumentsList.length) {
    throw new Error("Usage: node scripts/readiness-trust-anchor.mjs");
  }
  return readReadinessTrustAnchor(dependencies);
}

function trustAnchorFromProvider(provider) {
  if (!provider || !Array.isArray(provider.keyRecords) ||
      provider.keyRecords.length < 1 || provider.keyRecords.length > 2) {
    fail("invalid_signing_provider");
  }
  const integrity = publicKeyRecord(provider.keyRecords[0], "vasi_integrity");
  const certificate = provider.keyRecords.length === 2
    ? publicKeyRecord(provider.keyRecords[1], "certificate")
    : null;
  if (new Set(provider.keyRecords.map((key) => key.keyId)).size !== provider.keyRecords.length) {
    fail("duplicate_signing_key");
  }
  return Object.freeze({
    certificate: certificate && Object.freeze({
      algorithm: certificate.algorithm,
      fingerprint: certificate.fingerprint,
      keyId: certificate.keyId,
      profile: "vasi-certificate-seal/v1",
      validationScope: "leaf_signature_and_key_match",
    }),
    integrity: Object.freeze({
      algorithm: integrity.algorithm,
      fingerprint: integrity.fingerprint,
      keyId: integrity.keyId,
      profile: "vasi-readiness-dossier-seal/v1",
    }),
    schema: READINESS_TRUST_ANCHOR_SCHEMA,
    status: "ready",
  });
}

function publicKeyRecord(value, role) {
  if (
    !value || value.sealRole !== role ||
    typeof value.algorithm !== "string" || !["Ed25519", "ECDSA-SHA256", "RSA-SHA256"].includes(value.algorithm) ||
    typeof value.fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(value.fingerprint) ||
    typeof value.keyId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.keyId)
  ) fail("invalid_signing_key");
  if (role === "vasi_integrity" && value.algorithm !== "Ed25519") fail("invalid_integrity_key");
  if (value.fingerprint !== signingKeyFingerprint(value)) fail("invalid_signing_fingerprint");
  return value;
}

function fail(code) {
  throw new ReadinessTrustAnchorError(code);
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  runReadinessTrustAnchor(process.argv.slice(2))
    .then((result) => console.info(JSON.stringify(result)))
    .catch((error) => {
      if (error instanceof Error && error.message.startsWith("Usage:")) console.error(error.message);
      else console.error("VASI readiness trust anchor unavailable.");
      process.exitCode = 1;
    });
}
