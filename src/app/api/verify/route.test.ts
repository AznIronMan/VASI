import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  engine: vi.fn(),
  limit: vi.fn(),
  settings: vi.fn(),
}));

vi.mock("@/lib/engine-client", () => ({ requestEngineAction: mocks.engine }));
vi.mock("@/lib/public-verification-rate-limit", () => ({
  consumePublicVerificationRateLimit: mocks.limit,
}));
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: mocks.settings }));

import { GATEWAY_JSON_MAXIMUM_BYTES } from "@/lib/bounded-json";
import { POST } from "@/app/api/verify/route";

describe("public fingerprint verification request boundary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.settings.mockResolvedValue({
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "https://vsign.example.test",
      VASI_ADMIN_EMAILS: "admin@example.test",
      VASI_ADMIN_ORIGIN: "https://admin.example.test",
    });
    mocks.limit.mockResolvedValue({ accepted: true, retryAfterSeconds: 60 });
    mocks.engine.mockResolvedValue({ body: { valid: true }, status: 200 });
  });

  it("rejects an oversized JSON body before invoking the private engine", async () => {
    const response = await POST(request(JSON.stringify({
      fingerprint: "a".repeat(GATEWAY_JSON_MAXIMUM_BYTES),
    }), "192.0.2.1"));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: "The request body is too large." });
    expect(mocks.engine).not.toHaveBeenCalled();
  });

  it("rejects a malformed body without exposing parser details", async () => {
    const response = await POST(request("{not-json", "192.0.2.2"));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Invalid request." });
    expect(mocks.engine).not.toHaveBeenCalled();
  });

  it("does not attribute a forged multi-hop chain without configured proxy trust", async () => {
    const response = await POST(request(
      JSON.stringify({ fingerprint: "a".repeat(64) }),
      "198.51.100.44, 192.0.2.8",
    ));

    expect(response.status).toBe(200);
    expect(mocks.limit).toHaveBeenCalledWith({
      address: undefined,
      authSecret: "s".repeat(32),
    });
    expect(mocks.engine).toHaveBeenCalledWith(
      expect.objectContaining({ requestContext: expect.objectContaining({ ipAddress: undefined }) }),
      expect.anything(),
    );
  });

  it("uses the first untrusted hop to the right of a forged forwarding value", async () => {
    mocks.settings.mockResolvedValue({
      BETTER_AUTH_SECRET: "s".repeat(32),
      BETTER_AUTH_URL: "https://vsign.example.test",
      VASI_ADMIN_EMAILS: "admin@example.test",
      VASI_ADMIN_ORIGIN: "https://admin.example.test",
      VASI_TRUSTED_PROXY_CIDRS: "10.0.0.0/8",
    });
    const response = await POST(request(
      JSON.stringify({ fingerprint: "a".repeat(64) }),
      "198.51.100.44, 192.0.2.8, 10.0.0.9",
    ));

    expect(response.status).toBe(200);
    expect(mocks.limit).toHaveBeenCalledWith({
      address: "192.0.2.8",
      authSecret: "s".repeat(32),
    });
  });

  it("returns a durable throttle decision without invoking the private engine", async () => {
    mocks.limit.mockResolvedValue({ accepted: false, retryAfterSeconds: 17 });
    const response = await POST(request(
      JSON.stringify({ fingerprint: "a".repeat(64) }),
      "192.0.2.8",
    ));

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("17");
    expect(mocks.engine).not.toHaveBeenCalled();
  });

  it("fails closed when durable throttle state is unavailable", async () => {
    mocks.limit.mockRejectedValue(new Error("database unavailable"));
    const response = await POST(request(
      JSON.stringify({ fingerprint: "a".repeat(64) }),
      "192.0.2.8",
    ));

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ error: "Verification is temporarily unavailable." });
    expect(mocks.engine).not.toHaveBeenCalled();
  });
});

function request(body: string, address: string) {
  return new Request("https://vsign.example.test/api/verify", {
    body,
    headers: {
      "content-type": "application/json",
      host: "vsign.example.test",
      origin: "https://vsign.example.test",
      "x-forwarded-for": address,
    },
    method: "POST",
  });
}
