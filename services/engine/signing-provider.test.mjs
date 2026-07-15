import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  verifyDetachedIntegritySeal,
} from "../../packages/engine-crypto/index.mjs";
import { createSigningProvider, ensureSigningKeys, initializeSigningKeys } from "./signing-provider.mjs";

describe("replaceable evidence signing provider", () => {
  it("signs manifests and bundle indexes with distinct deterministic profiles", () => {
    const provider = providerFixture();
    const payload = { schema: "vasi-signing-provider-test/v1", value: "bound" };
    const manifestSeal = provider.signManifest(payload)[0];
    const bundleSeal = provider.signBundleIndex(payload)[0];
    const dataExportSeal = provider.signDetached(payload, "vasi-participant-data-export/v1")[0];
    const readinessSeal = provider.signDetached(payload, "vasi-readiness-dossier-seal/v1")[0];
    expect(verifyDetachedIntegritySeal(payload, manifestSeal, ["vasi-integrity-seal/v1"])).toBe(true);
    expect(verifyDetachedIntegritySeal(payload, bundleSeal, ["vasi-bundle-seal/v1"])).toBe(true);
    expect(verifyDetachedIntegritySeal(payload, dataExportSeal, ["vasi-participant-data-export/v1"])).toBe(true);
    expect(verifyDetachedIntegritySeal(payload, readinessSeal, ["vasi-readiness-dossier-seal/v1"])).toBe(true);
    expect(manifestSeal.role).toBe("vasi_integrity");
  });

  it("registers an immutable key and appends its initial active status once", async () => {
    const provider = providerFixture();
    const queries = [];
    const client = {
      async query(sql) {
        queries.push(sql);
        if (sql.includes("on conflict")) return { rowCount: 1, rows: [{ keyId: "test-key" }] };
        if (sql.includes('select "sealRole"')) {
          return {
            rowCount: 1,
            rows: [{ algorithm: "Ed25519", fingerprint: provider.keyRecords[0].fingerprint, sealRole: "vasi_integrity" }],
          };
        }
        return { rowCount: 1, rows: [] };
      },
    };
    await ensureSigningKeys(client, provider);
    expect(queries.some((sql) => sql.includes('"evidence_seal_key_status_event"'))).toBe(true);
  });

  it("registers configured signing custody transactionally during engine startup", async () => {
    const settings = providerSettings("startup-key");
    const queries = [];
    const client = {
      async query(sql) {
        queries.push(sql);
        if (sql.includes("on conflict")) return { rowCount: 1, rows: [{ keyId: "startup-key" }] };
        if (sql.includes('select "sealRole"')) {
          const provider = createSigningProvider(settings);
          return {
            rowCount: 1,
            rows: [{ algorithm: "Ed25519", fingerprint: provider.keyRecords[0].fingerprint, sealRole: "vasi_integrity" }],
          };
        }
        return { rowCount: 1, rows: [] };
      },
      release() { queries.push("release"); },
    };
    await initializeSigningKeys({ connect: async () => client }, settings);
    expect(queries[0]).toBe("begin");
    expect(queries.at(-2)).toBe("commit");
    expect(queries.at(-1)).toBe("release");
  });

  it("fails closed for mismatched integrity keys and partial certificate custody", () => {
    const first = generateKeyPairSync("ed25519");
    const second = generateKeyPairSync("ed25519");
    expect(() => createSigningProvider({
      EVIDENCE_SEAL_KEY_ID: "mismatched-key",
      EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(first.privateKey.export({ format: "jwk" })),
      EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(second.publicKey.export({ format: "jwk" })),
    })).toThrow("do not match");

    const valid = providerSettings("partial-certificate");
    expect(() => createSigningProvider({
      ...valid,
      EVIDENCE_CERTIFICATE_KEY_ID: "certificate-without-custody",
    })).toThrow("requires its key ID, private key, and certificate chain");
  });

  it("rejects a reused key ID whose registered fingerprint conflicts", async () => {
    const provider = providerFixture();
    const client = {
      async query(sql) {
        if (sql.includes("on conflict")) return { rowCount: 0, rows: [] };
        if (sql.includes('select "sealRole"')) {
          return { rowCount: 1, rows: [{ algorithm: "Ed25519", fingerprint: "0".repeat(64), sealRole: "vasi_integrity" }] };
        }
        return { rowCount: 0, rows: [] };
      },
    };
    await expect(ensureSigningKeys(client, provider)).rejects.toThrow("conflicts with runtime custody");
  });
});

function providerFixture() {
  return createSigningProvider(providerSettings("test-key"));
}

function providerSettings(keyId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    EVIDENCE_SEAL_KEY_ID: keyId,
    EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
    EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(publicKey.export({ format: "jwk" })),
  };
}
