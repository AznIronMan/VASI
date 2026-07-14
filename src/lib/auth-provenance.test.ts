import { describe, expect, it } from "vitest";

import { resolveSessionAuthentication } from "@/lib/auth-provenance";

describe("session authentication provenance", () => {
  it("records the provider that created an OAuth session", () => {
    expect(resolveSessionAuthentication({ path: "/callback/microsoft", params: { id: "microsoft" } })).toEqual({
      method: "federated",
      provider: "microsoft",
      provenance: "better-auth-session-create-context/v1",
    });
    expect(resolveSessionAuthentication({ path: "/oauth2/callback/yahoo", params: { providerId: "yahoo" } }).provider).toBe("yahoo");
  });

  it("distinguishes password and verification-created sessions", () => {
    expect(resolveSessionAuthentication({ path: "/sign-in/username" }).method).toBe("password");
    expect(resolveSessionAuthentication({ path: "/verify-email" }).method).toBe("email_verification");
  });

  it("labels missing context instead of guessing from a linked account", () => {
    expect(resolveSessionAuthentication(null)).toEqual({
      method: "session_unspecified",
      provenance: "session-context-unavailable/v1",
    });
  });
});
