import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  verifyDetachedIntegritySeal,
} from "../../packages/engine-crypto/index.mjs";
import { createSigningProvider, ensureSigningKeys } from "./signing-provider.mjs";

describe("replaceable evidence signing provider", () => {
  it("signs manifests and bundle indexes with distinct deterministic profiles", () => {
    const provider = providerFixture();
    const payload = { schema: "vasi-signing-provider-test/v1", value: "bound" };
    const manifestSeal = provider.signManifest(payload)[0];
    const bundleSeal = provider.signBundleIndex(payload)[0];
    expect(verifyDetachedIntegritySeal(payload, manifestSeal, ["vasi-integrity-seal/v1"])).toBe(true);
    expect(verifyDetachedIntegritySeal(payload, bundleSeal, ["vasi-bundle-seal/v1"])).toBe(true);
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
});

function providerFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return createSigningProvider({
    EVIDENCE_SEAL_KEY_ID: "test-key",
    EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
    EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(publicKey.export({ format: "jwk" })),
  });
}
