import { describe, expect, it, vi } from "vitest";

import { verifyServiceRequest } from "../../packages/engine-crypto/index.mjs";
import { createArtifactScanClient } from "./integration-gateway-scan-client.mjs";

describe("engine artifact scan client", () => {
  it("sends only the narrow signed, digest-bound scan command", async () => {
    const secret = "g".repeat(48);
    const ids = ["scan-request-1", "service-request-1"];
    const fetchMock = vi.fn(async (url, options) => {
      const body = Buffer.from(options.body);
      const request = {
        body,
        method: options.method,
        path: url.pathname,
        requestId: options.headers["x-vasi-request-id"],
        serviceId: options.headers["x-vasi-service"],
        timestamp: Number(options.headers["x-vasi-timestamp"]),
      };
      expect(verifyServiceRequest(request, secret, options.headers["x-vasi-signature"])).toBe(true);
      const parsed = JSON.parse(body.toString("utf8"));
      expect(parsed).toEqual({
        artifactId: "artifact-1",
        byteLength: 123,
        capability: "document.malware_scan",
        mediaType: "application/pdf",
        scanRequestId: "scan-request-1",
        schema: "vasi-artifact-scan/v1",
        sha256: "a".repeat(64),
        tenantId: "tenant-1",
      });
      expect(JSON.stringify(parsed)).not.toMatch(/filename|credential|bytes|secret/i);
      return new Response(JSON.stringify({
        adapter: "https_malware_scanner",
        adapterVersion: "1",
        attemptId: "attempt-1",
        bindingRevisionId: "binding-1",
        outcome: "completed",
        responseMetadata: { scanner: "Proof scanner", scannerVersion: "1" },
        scanRequestId: "scan-request-1",
        verdict: "clean",
      }), { headers: { "content-type": "application/json" }, status: 200 });
    });
    const scan = createArtifactScanClient({
      ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET: secret,
      ENGINE_INTEGRATION_GATEWAY_ORIGIN: "http://integration-gateway:8090",
    }, {
      fetch: fetchMock,
      now: () => 1_700_000_000_000,
      randomUUID: () => ids.shift(),
    });
    await expect(scan({
      byteLength: 123,
      id: "artifact-1",
      mediaType: "application/pdf",
      sha256: "a".repeat(64),
      tenantId: "tenant-1",
    })).resolves.toMatchObject({ outcome: "completed", verdict: "clean" });
  });

  it("rejects malformed success responses and converts transport failure to a bounded code", async () => {
    const settings = {
      ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET: "g".repeat(48),
      ENGINE_INTEGRATION_GATEWAY_ORIGIN: "http://integration-gateway:8090",
    };
    const artifact = {
      byteLength: 1,
      id: "artifact-1",
      mediaType: "text/plain",
      sha256: "a".repeat(64),
      tenantId: "tenant-1",
    };
    const malformed = createArtifactScanClient(settings, {
      fetch: async () => new Response(JSON.stringify({
        adapter: "https_malware_scanner",
        adapterVersion: "1",
        attemptId: "attempt-1",
        outcome: "completed",
        responseMetadata: {},
        scanRequestId: "scan-1",
      }), { status: 200 }),
    });
    await expect(malformed(artifact)).rejects.toMatchObject({ code: "integration_gateway_invalid_response" });
    const unavailable = createArtifactScanClient(settings, { fetch: async () => { throw new Error("private detail"); } });
    await expect(unavailable(artifact)).rejects.toMatchObject({ code: "integration_gateway_unavailable" });
  });
});
