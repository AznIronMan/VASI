import { describe, expect, it } from "vitest";

import { resolveServerEnvironment } from "@/lib/server-environment";

describe("server environment", () => {
  it("provides local-only development defaults", () => {
    const environment = resolveServerEnvironment({ NODE_ENV: "development" });

    expect(environment.baseURL).toBe("http://localhost:3000");
    expect(environment.adminOrigin).toBe("http://localhost:3000");
    expect(environment.adminEmails).toEqual(["admin@localhost"]);
  });

  it("requires core secrets and services in production", () => {
    expect(() => resolveServerEnvironment({ NODE_ENV: "production" })).toThrow(
      "BETTER_AUTH_SECRET is required in production.",
    );
  });

  it("allows non-secret placeholders only while Next.js compiles", () => {
    expect(
      resolveServerEnvironment({
        NODE_ENV: "production",
        NEXT_PHASE: "phase-production-build",
      }).baseURL,
    ).toBe("http://localhost:3000");
  });

  it("rejects short secrets", () => {
    expect(() =>
      resolveServerEnvironment({
        NODE_ENV: "development",
        BETTER_AUTH_SECRET: "too-short",
      }),
    ).toThrow("BETTER_AUTH_SECRET must contain at least 32 characters.");
  });

  it("requires an HTTPS production origin", () => {
    expect(() =>
      resolveServerEnvironment({
        NODE_ENV: "production",
        BETTER_AUTH_SECRET: "a-secure-production-secret-that-is-long-enough",
        BETTER_AUTH_URL: "http://vsign.cnb.llc",
        DATABASE_URL: "postgresql://database/vasi",
        VASI_ADMIN_ORIGIN: "https://admin.internal.example",
        VASI_ADMIN_EMAILS: "admin@example.com",
      }),
    ).toThrow("BETTER_AUTH_URL must use HTTPS in production.");
  });

  it("normalizes and validates the operator allowlist", () => {
    expect(
      resolveServerEnvironment({
        NODE_ENV: "development",
        VASI_ADMIN_EMAILS: " One@Example.com,one@example.com,two@example.com ",
      }).adminEmails,
    ).toEqual(["one@example.com", "two@example.com"]);
  });
});
