import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  engine: vi.fn(),
  settings: vi.fn(),
}));

vi.mock("@/lib/engine-client", () => ({ requestEngineAction: mocks.engine }));
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
