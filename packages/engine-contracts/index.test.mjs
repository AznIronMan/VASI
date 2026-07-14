import { describe, expect, it } from "vitest";

import { validateActorAssertionClaims } from "./index.mjs";

const claims = {
  authentication: { method: "microsoft", provider: "microsoft" },
  exp: 1_700_000_060,
  gateway_session_id: "session-1",
  iat: 1_700_000_000,
  jti: "assertion-1",
  roles: ["participant"],
  sub: "user-1",
  tenant_id: "tenant-1",
  vasi_principal_id: "principal-1",
};

describe("actor assertion contract", () => {
  it("normalizes a bounded identity assertion", () => {
    expect(validateActorAssertionClaims(claims, 1_700_000_010)).toMatchObject({
      assertionId: "assertion-1",
      principalId: "principal-1",
      tenantId: "tenant-1",
    });
  });

  it("rejects assertions with an excessive lifetime", () => {
    expect(() =>
      validateActorAssertionClaims({ ...claims, exp: 1_700_001_000 }, 1_700_000_010),
    ).toThrow("lifetime is too long");
  });

  it("rejects missing authentication context", () => {
    expect(() =>
      validateActorAssertionClaims({ ...claims, authentication: undefined }, 1_700_000_010),
    ).toThrow("authentication context is required");
  });
});
