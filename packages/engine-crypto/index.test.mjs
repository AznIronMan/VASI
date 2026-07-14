import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  canonicalJSON,
  createIntegritySeal,
  signServiceRequest,
  verifyIntegritySeal,
  verifyServiceRequest,
} from "./index.mjs";

const request = {
  body: Buffer.from('{"test":true}'),
  method: "POST",
  path: "/v1/whoami",
  requestId: "request-1",
  serviceId: "private-ingress",
  timestamp: 1_700_000_000,
};

describe("engine service request signatures", () => {
  it("authenticates the canonical request", () => {
    const signature = signServiceRequest(request, "a secure internal secret");
    expect(verifyServiceRequest(request, "a secure internal secret", signature)).toBe(true);
  });

  it("rejects a signature moved to another route", () => {
    const signature = signServiceRequest(request, "a secure internal secret");
    expect(
      verifyServiceRequest(
        { ...request, path: "/healthz" },
        "a secure internal secret",
        signature,
      ),
    ).toBe(false);
  });
});

describe("canonical evidence and integrity seals", () => {
  it("orders object keys recursively and rejects non-integer numbers", () => {
    expect(canonicalJSON({ z: 1, a: { y: true, b: "value" } })).toBe(
      '{"a":{"b":"value","y":true},"z":1}',
    );
    expect(() => canonicalJSON({ value: 1.25 })).toThrow("safe integers");
  });

  it("detects manifest tampering", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const manifest = { schema: "vasi-evidence-manifest/v1", value: "yes" };
    const seal = createIntegritySeal({
      keyId: "test-key",
      manifest,
      privateJWK: privateKey.export({ format: "jwk" }),
    });

    expect(verifyIntegritySeal(manifest, seal)).toBe(true);
    expect(verifyIntegritySeal({ ...manifest, value: "no" }, seal)).toBe(false);
  });
});
