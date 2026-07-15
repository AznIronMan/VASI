import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  limit: vi.fn(),
  recommend: vi.fn(),
  settings: vi.fn(),
}));

vi.mock("@/lib/provider-recommendation", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/provider-recommendation")>();
  return { ...original, recommendProviderForEmail: mocks.recommend };
});
vi.mock("@/lib/provider-recommendation-rate-limit", () => ({
  consumeProviderRecommendationRateLimit: mocks.limit,
}));
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: mocks.settings }));

import { GET } from "@/app/api/auth/provider-recommendation/route";

describe("provider recommendation request boundary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.limit.mockResolvedValue({ accepted: true, retryAfterSeconds: 60 });
    mocks.recommend.mockResolvedValue("google");
    mocks.settings.mockResolvedValue(settings());
  });

  it("conceals the endpoint on every non-public host", async () => {
    const response = await GET(request("person@example.test", {
      host: "admin.example.test",
    }));
    expect(response.status).toBe(404);
    expect(mocks.limit).not.toHaveBeenCalled();
    expect(mocks.recommend).not.toHaveBeenCalled();
  });

  it("rejects cross-site browser traffic and invalid email before throttle state", async () => {
    const crossSite = await GET(request("person@example.test", {
      "sec-fetch-site": "cross-site",
    }));
    expect(crossSite.status).toBe(403);

    const invalid = await GET(request("not-an-email"));
    expect(invalid.status).toBe(400);
    expect(invalid.headers.get("cache-control")).toBe("no-store");
    expect(mocks.limit).not.toHaveBeenCalled();
    expect(mocks.recommend).not.toHaveBeenCalled();
  });

  it("uses strict proxy provenance and returns only configured provider state", async () => {
    const response = await GET(request("person@example.test", {
      "x-forwarded-for": "198.51.100.44, 192.0.2.8",
    }));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mocks.limit).toHaveBeenCalledWith({
      address: undefined,
      authSecret: "s".repeat(32),
    });
    expect(await response.json()).toEqual({
      configured: true,
      label: "Google",
      provider: "google",
    });
  });

  it("keeps obvious consumer providers available without spending the DNS budget", async () => {
    const response = await GET(request("person@gmail.com"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      configured: true,
      label: "Google",
      provider: "google",
    });
    expect(mocks.limit).not.toHaveBeenCalled();
    expect(mocks.recommend).not.toHaveBeenCalled();
  });

  it("selects the first untrusted hop after approved proxies", async () => {
    mocks.settings.mockResolvedValue(settings("10.0.0.0/8"));
    const response = await GET(request("person@example.test", {
      "x-forwarded-for": "198.51.100.44, 192.0.2.8, 10.0.0.9",
    }));
    expect(response.status).toBe(200);
    expect(mocks.limit).toHaveBeenCalledWith({
      address: "192.0.2.8",
      authSecret: "s".repeat(32),
    });
  });

  it("returns a durable denial without performing DNS detection", async () => {
    mocks.limit.mockResolvedValue({ accepted: false, retryAfterSeconds: 17 });
    const response = await GET(request("person@example.test"));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("17");
    expect(mocks.recommend).not.toHaveBeenCalled();
  });

  it("fails closed when durable throttle state is unavailable", async () => {
    mocks.limit.mockRejectedValue(new Error("database unavailable"));
    const response = await GET(request("person@example.test"));
    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(mocks.recommend).not.toHaveBeenCalled();
  });
});

function request(email: string, headers: Record<string, string> = {}) {
  return new Request(
    `https://vsign.example.test/api/auth/provider-recommendation?email=${encodeURIComponent(email)}`,
    { headers: { host: "vsign.example.test", ...headers } },
  );
}

function settings(trustedProxyCIDRs = "") {
  return {
    BETTER_AUTH_SECRET: "s".repeat(32),
    BETTER_AUTH_URL: "https://vsign.example.test",
    GOOGLE_CLIENT_ID: "google-client",
    GOOGLE_CLIENT_SECRET: "google-secret",
    VASI_ADMIN_EMAILS: "admin@example.test",
    VASI_ADMIN_ORIGIN: "https://admin.example.test",
    VASI_TRUSTED_PROXY_CIDRS: trustedProxyCIDRs,
  };
}
