import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  settings: vi.fn(),
}));

vi.mock("@/lib/database", () => ({ database: { query: mocks.query } }));
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: mocks.settings }));

import { buildEngineActor } from "@/lib/engine-actor";

const session = {
  session: {
    authenticationMethod: "federated",
    authenticationProvider: "google",
    authenticationProvenance: "better-auth-context/v1",
    createdAt: "2026-07-15T09:00:00.000Z",
    id: "session-1",
  },
  user: { email: "Person@Example.test", id: "user-1", role: "user" },
};

describe("engine actor address provenance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.query.mockResolvedValue({ rows: [{ accountId: "subject-1", providerId: "google" }] });
    mocks.settings.mockResolvedValue(settings());
  });

  it("omits an ambiguous client-supplied forwarding chain", async () => {
    const actor = await buildEngineActor(session, new Headers({
      "x-forwarded-for": "198.51.100.44, 192.0.2.8",
    }));
    expect(actor.requestContext?.ipAddress).toBeUndefined();
  });

  it("records only the first untrusted address to the right of a forged value", async () => {
    mocks.settings.mockResolvedValue(settings("10.0.0.0/8"));
    const actor = await buildEngineActor(session, new Headers({
      "x-forwarded-for": "198.51.100.44, 192.0.2.8, 10.0.0.9",
    }));
    expect(actor.requestContext?.ipAddress).toBe("192.0.2.8");
  });
});

function settings(trustedProxyCIDRs = "") {
  return {
    BETTER_AUTH_SECRET: "s".repeat(32),
    BETTER_AUTH_URL: "https://vsign.example.test",
    VASI_ADMIN_EMAILS: "admin@example.test",
    VASI_ADMIN_ORIGIN: "https://admin.example.test",
    VASI_TRUSTED_PROXY_CIDRS: trustedProxyCIDRs,
  };
}
