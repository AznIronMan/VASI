import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createIntegritySeal,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";
import { createEvidenceStore, verifyEvidenceRecord } from "./evidence-store.mjs";

describe("sealed evidence record verification", () => {
  it("validates the ordered event chain and detects event changes", () => {
    const firstData = {
      previousHash: "0".repeat(64),
      schema: "vasi-evidence-event/v1",
      sequence: 1,
      value: "issued",
    };
    const firstHash = hashCanonicalJSON(firstData);
    const secondData = {
      previousHash: firstHash,
      schema: "vasi-evidence-event/v1",
      sequence: 2,
      value: "yes",
    };
    const secondHash = hashCanonicalJSON(secondData);
    const events = [
      { eventData: firstData, eventHash: firstHash, previousHash: firstData.previousHash, sequence: 1 },
      { eventData: secondData, eventHash: secondHash, previousHash: firstHash, sequence: 2 },
    ];
    const manifest = {
      evidence: {
        eventCount: 2,
        eventHashes: [firstHash, secondHash],
        firstSequence: 1,
        headHash: secondHash,
        lastSequence: 2,
      },
      schema: "vasi-evidence-manifest/v1",
    };
    const { privateKey } = generateKeyPairSync("ed25519");
    const seal = createIntegritySeal({
      keyId: "seal-test",
      manifest,
      privateJWK: privateKey.export({ format: "jwk" }),
    });

    expect(verifyEvidenceRecord({ events, manifest, seal })).toBe(true);
    expect(() =>
      verifyEvidenceRecord({
        events: [events[0], { ...events[1], eventData: { ...secondData, value: "no" } }],
        manifest,
        seal,
      }),
    ).toThrow("integrity_check_failed");
  });
});

describe("evidence seal key custody", () => {
  it("refuses a mismatched configured public key", () => {
    const first = generateKeyPairSync("ed25519");
    const second = generateKeyPairSync("ed25519");
    expect(() => createEvidenceStore({}, {
      EVIDENCE_SEAL_KEY_ID: "key-1",
      EVIDENCE_SEAL_PRIVATE_JWK: JSON.stringify(first.privateKey.export({ format: "jwk" })),
      EVIDENCE_SEAL_PUBLIC_JWK: JSON.stringify(second.publicKey.export({ format: "jwk" })),
    })).toThrow("do not match");
  });
});
