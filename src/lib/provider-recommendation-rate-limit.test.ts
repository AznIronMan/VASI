import { describe, expect, it, vi } from "vitest";

import {
  consumeProviderRecommendationRateLimit,
  PROVIDER_RECOMMENDATION_CLIENT_LIMIT,
  PROVIDER_RECOMMENDATION_GLOBAL_LIMIT,
} from "@/lib/provider-recommendation-rate-limit";

describe("provider recommendation rate limiting", () => {
  it("atomically sends two opaque buckets and fixed limits to PostgreSQL", async () => {
    const query = vi.fn().mockImplementation((_sql, parameters) => ({ rows: [
      {
        count: "1",
        keyDigest: parameters[0],
        maximum: String(PROVIDER_RECOMMENDATION_CLIENT_LIMIT),
        retryAfterSeconds: "60",
      },
      {
        count: "1",
        keyDigest: parameters[1],
        maximum: String(PROVIDER_RECOMMENDATION_GLOBAL_LIMIT),
        retryAfterSeconds: "60",
      },
    ] }));
    await expect(consumeProviderRecommendationRateLimit({
      address: "192.0.2.8",
      authSecret: "s".repeat(32),
      client: { query } as never,
    })).resolves.toEqual({ accepted: true, retryAfterSeconds: 60 });

    const [sql, parameters] = query.mock.calls[0];
    expect(sql).toContain('on conflict ("keyDigest") do update');
    expect(sql).toContain('from limits cross join observation');
    expect(sql).toContain("limit 100");
    expect(parameters.slice(0, 2)).toEqual([
      expect.stringMatching(/^[a-f0-9]{64}$/),
      expect.stringMatching(/^[a-f0-9]{64}$/),
    ]);
    expect(parameters[0]).not.toBe(parameters[1]);
    expect(parameters.slice(2, 6)).toEqual([30, 600, 60, parameters.slice(0, 2)]);
    expect(JSON.stringify(parameters)).not.toContain("192.0.2.8");
  });

  it("denies when either the client or installation bucket exceeds its limit", async () => {
    const query = vi.fn().mockImplementation((_sql, parameters) => ({ rows: [
      {
        count: "31",
        keyDigest: parameters[0],
        maximum: "30",
        retryAfterSeconds: "12",
      },
      {
        count: "2",
        keyDigest: parameters[1],
        maximum: "600",
        retryAfterSeconds: "59",
      },
    ] }));
    await expect(consumeProviderRecommendationRateLimit({
      authSecret: "s".repeat(32),
      client: { query } as never,
    })).resolves.toEqual({ accepted: false, retryAfterSeconds: 12 });
  });

  it("changes the client bucket but preserves the global bucket across source rotation", async () => {
    const parameters: unknown[][] = [];
    const query = vi.fn().mockImplementation((_sql, values) => {
      parameters.push(values);
      return { rows: [
        { count: "1", keyDigest: values[0], maximum: "30", retryAfterSeconds: "60" },
        { count: "1", keyDigest: values[1], maximum: "600", retryAfterSeconds: "60" },
      ] };
    });
    for (const address of ["192.0.2.8", "198.51.100.9"]) {
      await consumeProviderRecommendationRateLimit({
        address,
        authSecret: "s".repeat(32),
        client: { query } as never,
      });
    }
    expect(parameters[0][0]).not.toBe(parameters[1][0]);
    expect(parameters[0][1]).toBe(parameters[1][1]);
  });

  it("rejects incomplete, duplicate, malformed, and unavailable state", async () => {
    for (const rows of [
      [],
      [{ count: "1", keyDigest: "unexpected", maximum: "30", retryAfterSeconds: "60" }],
    ]) {
      await expect(consumeProviderRecommendationRateLimit({
        authSecret: "s".repeat(32),
        client: { query: vi.fn().mockResolvedValue({ rows }) } as never,
      })).rejects.toThrow(/unavailable|invalid/);
    }
    const duplicateQuery = vi.fn().mockImplementation((_sql, parameters) => ({ rows: [
      { count: "1", keyDigest: parameters[0], maximum: "30", retryAfterSeconds: "60" },
      { count: "1", keyDigest: parameters[0], maximum: "30", retryAfterSeconds: "60" },
    ] }));
    await expect(consumeProviderRecommendationRateLimit({
      authSecret: "s".repeat(32),
      client: { query: duplicateQuery } as never,
    })).rejects.toThrow("state is invalid");

    const malformedQuery = vi.fn().mockImplementation((_sql, parameters) => ({ rows: [
      { count: "not-a-count", keyDigest: parameters[0], maximum: "30", retryAfterSeconds: "60" },
      { count: "1", keyDigest: parameters[1], maximum: "600", retryAfterSeconds: "60" },
    ] }));
    await expect(consumeProviderRecommendationRateLimit({
      authSecret: "s".repeat(32),
      client: { query: malformedQuery } as never,
    })).rejects.toThrow("state is invalid");

    await expect(consumeProviderRecommendationRateLimit({
      authSecret: "s".repeat(32),
      client: { query: vi.fn().mockRejectedValue(new Error("database unavailable")) } as never,
    })).rejects.toThrow("database unavailable");
  });
});
