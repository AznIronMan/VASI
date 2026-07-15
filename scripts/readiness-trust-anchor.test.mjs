import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it, vi } from "vitest";

import {
  readReadinessTrustAnchor,
  ReadinessTrustAnchorError,
  runReadinessTrustAnchor,
} from "./readiness-trust-anchor.mjs";
import {
  createSigningProvider,
  signingKeyFingerprint,
} from "../services/engine/signing-provider.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const entrypoint = path.join(root, "scripts", "readiness-trust-anchor.mjs");

describe("readiness signing trust anchor", () => {
  it("returns only the configured public integrity identity", async () => {
    const settings = signingSettings();
    const readSettings = vi.fn(async () => settings);
    const result = await readReadinessTrustAnchor({
      loadBootstrap: () => ({ installationId: "installation-test" }),
      readSettings,
    });
    expect(result).toMatchObject({
      certificate: null,
      integrity: {
        algorithm: "Ed25519",
        fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
        keyId: "readiness-anchor-test",
        profile: "vasi-readiness-dossier-seal/v1",
      },
      schema: "vasi-readiness-trust-anchor/v1",
      status: "ready",
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(settings.EVIDENCE_SEAL_PRIVATE_JWK);
    expect(serialized).not.toContain(settings.EVIDENCE_SEAL_PUBLIC_JWK);
    expect(serialized).not.toContain("publicJWK");
    expect(readSettings).toHaveBeenCalledWith({
      bootstrap: { installationId: "installation-test" },
      scope: "engine",
    });
  });

  it("reports a bounded optional certificate identity without its key material", async () => {
    const provider = createSigningProvider(signingSettings());
    const { publicKey } = generateKeyPairSync("ed25519");
    const certificateRecord = {
      algorithm: "Ed25519",
      certificateChain: ["certificate-public-material"],
      keyId: "readiness-certificate-test",
      publicJWK: publicKey.export({ format: "jwk" }),
      sealRole: "certificate",
    };
    certificateRecord.fingerprint = signingKeyFingerprint(certificateRecord);
    const result = await readReadinessTrustAnchor({
      createProvider: () => ({ keyRecords: [...provider.keyRecords, certificateRecord] }),
      loadBootstrap: () => ({}),
      readSettings: async () => ({}),
    });
    expect(result.certificate).toEqual({
      algorithm: "Ed25519",
      fingerprint: certificateRecord.fingerprint,
      keyId: "readiness-certificate-test",
      profile: "vasi-certificate-seal/v1",
      validationScope: "leaf_signature_and_key_match",
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("certificate-public-material");
    expect(serialized).not.toContain("publicJWK");
  });

  it("fails closed for invalid provider records and unexpected arguments", async () => {
    await expect(readReadinessTrustAnchor({
      createProvider: () => ({ keyRecords: [] }),
      loadBootstrap: () => ({}),
      readSettings: async () => ({}),
    })).rejects.toBeInstanceOf(ReadinessTrustAnchorError);
    await expect(readReadinessTrustAnchor({
      createProvider: () => ({
        keyRecords: [{
          algorithm: "Ed25519",
          fingerprint: "0".repeat(64),
          keyId: "forged-fingerprint",
          publicJWK: { crv: "Ed25519", kty: "OKP", x: "forged" },
          sealRole: "vasi_integrity",
        }],
      }),
      loadBootstrap: () => ({}),
      readSettings: async () => ({}),
    })).rejects.toBeInstanceOf(ReadinessTrustAnchorError);
    await expect(runReadinessTrustAnchor(["unexpected"], {}))
      .rejects.toThrow("Usage: node scripts/readiness-trust-anchor.mjs");
  });

  it("remains import-safe", () => {
    const result = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(entrypoint).href)});`,
    ], { encoding: "utf8", timeout: 5_000 });
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });
});

function signingSettings() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    EVIDENCE_SEAL_KEY_ID: "readiness-anchor-test",
    EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
    EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(publicKey.export({ format: "jwk" })),
  };
}
