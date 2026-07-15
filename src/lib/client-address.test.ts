import { describe, expect, it } from "vitest";

import {
  clientAddressRateLimitIdentity,
  parseTrustedProxyCIDRs,
  resolveTrustedClientAddress,
} from "@/lib/client-address";

describe("trusted proxy client addresses", () => {
  it("accepts one validated address when no multi-hop trust is configured", () => {
    expect(resolveTrustedClientAddress(headers("192.0.2.8"), [])).toBe("192.0.2.8");
    expect(resolveTrustedClientAddress(headers("2001:0db8:0:0::1"), [])).toBe("2001:db8::1");
  });

  it("rejects an injected forwarding chain without an explicit proxy trust list", () => {
    expect(resolveTrustedClientAddress(headers("198.51.100.4, 192.0.2.8"), [])).toBeUndefined();
  });

  it("walks a configured proxy chain from right to left", () => {
    expect(resolveTrustedClientAddress(
      headers("203.0.113.7, 198.51.100.23, 10.0.0.9"),
      ["10.0.0.0/8", "198.51.100.0/24"],
    )).toBe("203.0.113.7");
  });

  it("ignores a forged leftmost value once the first untrusted hop is found", () => {
    expect(resolveTrustedClientAddress(
      headers("192.0.2.44, 203.0.113.7, 10.0.0.9"),
      ["10.0.0.0/8"],
    )).toBe("203.0.113.7");
  });

  it("fails closed for malformed, excessive, or fully trusted chains", () => {
    expect(resolveTrustedClientAddress(headers("not-an-ip"), [])).toBeUndefined();
    expect(resolveTrustedClientAddress(headers("192.0.2.8:443"), [])).toBeUndefined();
    expect(resolveTrustedClientAddress(headers(Array(17).fill("192.0.2.8").join(",")), ["10.0.0.0/8"]))
      .toBeUndefined();
    expect(resolveTrustedClientAddress(headers("10.0.0.8, 10.0.0.9"), ["10.0.0.0/8"]))
      .toBeUndefined();
  });

  it("does not fall back to X-Real-IP after an invalid forwarded chain", () => {
    const values = new Headers({
      "x-forwarded-for": "not-an-ip",
      "x-real-ip": "192.0.2.8",
    });
    expect(resolveTrustedClientAddress(values, [])).toBeUndefined();
  });

  it("validates canonical trusted network declarations", () => {
    expect(parseTrustedProxyCIDRs("10.0.0.0/8, 2001:db8::/32"))
      .toEqual(["10.0.0.0/8", "2001:db8::/32"]);
    expect(() => parseTrustedProxyCIDRs("10.0.0.1/8")).toThrow("canonical network address");
    expect(() => parseTrustedProxyCIDRs("not-a-network")).toThrow("Invalid trusted proxy network");
  });

  it("uses a stable IPv6 /64 rate-limit identity and normalizes mapped IPv4", () => {
    expect(clientAddressRateLimitIdentity("2001:db8:abcd:1::1"))
      .toBe(clientAddressRateLimitIdentity("2001:db8:abcd:1:ffff::9"));
    expect(clientAddressRateLimitIdentity("::ffff:192.0.2.8")).toBe("ipv4:192.0.2.8");
    expect(clientAddressRateLimitIdentity(undefined)).toBe("unattributed");
  });
});

function headers(forwarded: string) {
  return new Headers({ "x-forwarded-for": forwarded });
}
