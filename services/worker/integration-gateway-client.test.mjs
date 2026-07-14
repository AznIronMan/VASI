import { describe, expect, it, vi } from "vitest";

import { verifyServiceRequest } from "../../packages/engine-crypto/index.mjs";
import { createIntegrationGatewayClient } from "./integration-gateway-client.mjs";

describe("integration gateway client", () => {
  it("sends only the narrow signed delivery contract", async () => {
    const secret = "g".repeat(48);
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
      expect(Object.keys(parsed).sort()).toEqual([
        "attempt", "capability", "idempotencyKey", "jobId", "payload", "schema", "tenantId",
      ]);
      expect(JSON.stringify(parsed)).not.toContain("credential");
      return {
        json: async () => ({ adapter: "disabled", outcome: "suppressed", responseMetadata: {} }),
        ok: true,
      };
    });
    const dispatch = createIntegrationGatewayClient({
      ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET: secret,
      ENGINE_INTEGRATION_GATEWAY_ORIGIN: "http://integration-gateway:8090",
    }, { fetch: fetchMock });
    await expect(dispatch({
      attempt: 1,
      id: "job-1",
      idempotencyKey: "request-1:issued",
      payload: {
        eventType: "request.completed",
        recipient: "person@example.test",
        requestId: "request-1",
        tenant: { id: "tenant-1", name: "Example" },
        title: "Terms",
      },
      tenantId: "tenant-1",
    })).resolves.toMatchObject({ adapter: "disabled", outcome: "suppressed" });
  });
});
