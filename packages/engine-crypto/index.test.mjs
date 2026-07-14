import { describe, expect, it } from "vitest";

import { signServiceRequest, verifyServiceRequest } from "./index.mjs";

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
