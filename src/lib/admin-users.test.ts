import { describe, expect, it } from "vitest";

import { resolveConnectorHealth } from "@/lib/admin-users";

describe("connector health", () => {
  const now = new Date("2026-07-13T12:00:00Z").getTime();

  it("uses gray for a connector that is not linked", () => {
    expect(
      resolveConnectorHealth({ configured: true, connected: false, now }),
    ).toBe("disconnected");
  });

  it("uses red when a linked connector is unavailable", () => {
    expect(
      resolveConnectorHealth({
        accountId: "provider-account",
        configured: false,
        connected: true,
        lastAuthenticatedAt: new Date(now),
        now,
      }),
    ).toBe("error");
  });

  it("uses yellow after more than 90 days without authentication", () => {
    expect(
      resolveConnectorHealth({
        accountId: "provider-account",
        configured: true,
        connected: true,
        lastAuthenticatedAt: new Date(now - 91 * 24 * 60 * 60 * 1_000),
        now,
      }),
    ).toBe("stale");
  });

  it("uses green for a recently used healthy connector", () => {
    expect(
      resolveConnectorHealth({
        accountId: "provider-account",
        configured: true,
        connected: true,
        lastAuthenticatedAt: new Date(now - 12 * 24 * 60 * 60 * 1_000),
        now,
      }),
    ).toBe("active");
  });
});
