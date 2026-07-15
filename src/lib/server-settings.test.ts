import { describe, expect, it } from "vitest";

import { resolveServerSettings } from "@/lib/server-settings";

const validSettings = {
  BETTER_AUTH_SECRET: "a-secure-production-secret-that-is-long-enough",
  BETTER_AUTH_URL: "https://vsign.example.com",
  VASI_ADMIN_EMAILS: "admin@example.com",
  VASI_ADMIN_ORIGIN: "https://vasi.internal.example",
};

describe("server settings", () => {
  it("requires core settings", () => {
    expect(() => resolveServerSettings({}, false)).toThrow(
      "BETTER_AUTH_SECRET is required in VASI runtime settings.",
    );
  });

  it("rejects short secrets", () => {
    expect(() =>
      resolveServerSettings({ ...validSettings, BETTER_AUTH_SECRET: "too-short" }, false),
    ).toThrow("BETTER_AUTH_SECRET must contain at least 32 characters.");
  });

  it("requires HTTPS production origins", () => {
    expect(() =>
      resolveServerSettings({ ...validSettings, BETTER_AUTH_URL: "http://vsign.example.com" }, true),
    ).toThrow("BETTER_AUTH_URL must use HTTPS in production.");
  });

  it("allows HTTP for local development", () => {
    expect(
      resolveServerSettings(
        {
          ...validSettings,
          BETTER_AUTH_URL: "http://localhost:3000",
          VASI_ADMIN_ORIGIN: "http://localhost:3000",
        },
        false,
      ).baseURL,
    ).toBe("http://localhost:3000");
  });

  it("normalizes and validates the operator allowlist", () => {
    expect(
      resolveServerSettings(
        { ...validSettings, VASI_ADMIN_EMAILS: " One@Example.com,one@example.com,two@example.com " },
        true,
      ).adminEmails,
    ).toEqual(["one@example.com", "two@example.com"]);
  });

  it("validates and returns only canonical trusted proxy networks", () => {
    expect(resolveServerSettings({
      ...validSettings,
      VASI_TRUSTED_PROXY_CIDRS: "10.0.0.0/8, 2001:db8::/32",
    }, true).trustedProxyCIDRs).toEqual(["10.0.0.0/8", "2001:db8::/32"]);
    expect(() => resolveServerSettings({
      ...validSettings,
      VASI_TRUSTED_PROXY_CIDRS: "10.0.0.1/8",
    }, true)).toThrow("canonical network address");
  });
});
