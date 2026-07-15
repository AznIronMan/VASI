import { describe, expect, it, vi } from "vitest";

import {
  consumePublicVerificationRateLimit,
  PUBLIC_VERIFICATION_RATE_LIMIT,
} from "@/lib/public-verification-rate-limit";

describe("public verification rate limiting", () => {
  it("sends only a keyed digest and the fixed window to PostgreSQL", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [{ count: "1", retryAfterSeconds: "60" }],
    });
    await expect(consumePublicVerificationRateLimit({
      address: "192.0.2.8",
      authSecret: "s".repeat(32),
      client: { query } as never,
    })).resolves.toEqual({ accepted: true, retryAfterSeconds: 60 });

    expect(query).toHaveBeenCalledOnce();
    const [sql, parameters] = query.mock.calls[0];
    expect(sql).toContain('on conflict ("keyDigest") do update');
    expect(sql).toContain('current."count" + 1');
    expect(sql).toContain("limit 100");
    expect(parameters).toEqual([expect.stringMatching(/^[a-f0-9]{64}$/), 60]);
    expect(JSON.stringify(parameters)).not.toContain("192.0.2.8");
  });

  it("denies a count above the fixed limit and rejects invalid database state", async () => {
    const denied = { query: vi.fn().mockResolvedValue({
      rows: [{ count: String(PUBLIC_VERIFICATION_RATE_LIMIT + 1), retryAfterSeconds: "12" }],
    }) } as never;
    await expect(consumePublicVerificationRateLimit({
      address: undefined,
      authSecret: "s".repeat(32),
      client: denied,
    })).resolves.toEqual({ accepted: false, retryAfterSeconds: 12 });

    await expect(consumePublicVerificationRateLimit({
      address: "192.0.2.8",
      authSecret: "s".repeat(32),
      client: { query: vi.fn().mockResolvedValue({ rows: [] }) } as never,
    })).rejects.toThrow("state is unavailable");
  });

  it("propagates database failure so callers can fail closed", async () => {
    await expect(consumePublicVerificationRateLimit({
      address: "192.0.2.8",
      authSecret: "s".repeat(32),
      client: { query: vi.fn().mockRejectedValue(new Error("database unavailable")) } as never,
    })).rejects.toThrow("database unavailable");
  });
});
