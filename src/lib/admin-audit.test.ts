import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  settings: vi.fn(),
}));

vi.mock("@/lib/database", () => ({ database: { query: mocks.query } }));
vi.mock("@/lib/runtime-settings", () => ({ getRuntimeSettings: mocks.settings }));

import { beginAdminAuditCommand, normalizeAdminAuditMetadata } from "@/lib/admin-audit";

describe("administrator audit metadata", () => {
  it("accepts bounded outcome metadata and returns a detached value", () => {
    const metadata = { outcomeCode: "completed", provider: "google", result: { changed: true } };
    const normalized = normalizeAdminAuditMetadata(metadata);
    expect(normalized).toEqual(metadata);
    expect(normalized).not.toBe(metadata);
  });

  it.each([
    [{ accessToken: "not-recordable" }, "prohibited field"],
    [{ nested: { password: "not-recordable" } }, "prohibited field"],
    [{ value: "x".repeat(513) }, "oversized string"],
    [{ value: Number.MAX_VALUE }, "safe integers"],
    [{ values: Array.from({ length: 101 }, () => 1) }, "oversized list"],
  ])("rejects unsafe metadata %#", (metadata, message) => {
    expect(() => normalizeAdminAuditMetadata(metadata)).toThrow(message);
  });

  it("rejects an oversized encoded object", () => {
    const metadata = Object.fromEntries(
      Array.from({ length: 40 }, (_, index) => [`field${index}`, "x".repeat(300)]),
    );
    expect(() => normalizeAdminAuditMetadata(metadata)).toThrow("too large");
  });
});

describe("administrator audit address provenance", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.query.mockResolvedValue({ rows: [{ eventHash: "a".repeat(64), sequence: "1" }] });
    mocks.settings.mockResolvedValue(settings());
  });

  it("stores no address for an ambiguous forwarding chain", async () => {
    const command = await beginAdminAuditCommand({
      action: "user.test",
      request: request("198.51.100.44, 192.0.2.8"),
      session: { session: { id: "session-1" }, user: { id: "user-1" } },
    });
    expect(command.ipAddress).toBeNull();
    expect(mocks.query.mock.calls[0][1][9]).toBeNull();
  });

  it("stores the first untrusted address after skipping approved proxies", async () => {
    mocks.settings.mockResolvedValue(settings("10.0.0.0/8"));
    const command = await beginAdminAuditCommand({
      action: "user.test",
      request: request("198.51.100.44, 192.0.2.8, 10.0.0.9"),
      session: { session: { id: "session-1" }, user: { id: "user-1" } },
    });
    expect(command.ipAddress).toBe("192.0.2.8");
  });
});

function request(forwarded: string) {
  return new Request("https://admin.example.test/api/admin/test", {
    headers: { "x-forwarded-for": forwarded },
  });
}

function settings(trustedProxyCIDRs = "") {
  return {
    BETTER_AUTH_SECRET: "s".repeat(32),
    BETTER_AUTH_URL: "https://vsign.example.test",
    VASI_ADMIN_EMAILS: "admin@example.test",
    VASI_ADMIN_ORIGIN: "https://admin.example.test",
    VASI_TRUSTED_PROXY_CIDRS: trustedProxyCIDRs,
  };
}
