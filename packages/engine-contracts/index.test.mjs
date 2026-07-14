import { describe, expect, it } from "vitest";

import { resolveEngineRoute, validateActorAssertionClaims } from "./index.mjs";

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

describe("private engine routes", () => {
  it("maps only explicit method and path pairs", () => {
    expect(resolveEngineRoute("POST", "/v1/participant/respond")?.action).toBe(
      "participant.respond",
    );
    expect(resolveEngineRoute("GET", "/v1/participant/respond")).toBeUndefined();
    expect(resolveEngineRoute("POST", "/v1/participant/respond/extra")).toBeUndefined();
    expect(resolveEngineRoute("POST", "/v1/owner/evidence-exports")?.action).toBe(
      "record.export.open",
    );
    expect(resolveEngineRoute("POST", "/v1/public/verification")?.action).toBe(
      "verification.lookup",
    );
    expect(resolveEngineRoute("POST", "/v1/owner/legal-holds")?.action).toBe(
      "lifecycle.hold.command",
    );
    expect(resolveEngineRoute("GET", "/v1/participant/data-requests")?.action).toBe(
      "participant.data_request.list",
    );
    expect(resolveEngineRoute("GET", "/v1/admin/operations")?.action).toBe("operations.read");
    expect(resolveEngineRoute("GET", "/v1/admin/tenant-admissions")?.action).toBe(
      "tenant.admission.list",
    );
    expect(resolveEngineRoute("POST", "/v1/admin/tenant-admissions")?.action).toBe(
      "tenant.admission.update",
    );
    expect(resolveEngineRoute("POST", "/v1/participant/context-snapshots")?.action).toBe(
      "participant.context.record",
    );
    expect(resolveEngineRoute("POST", "/v1/admin/operations")).toBeUndefined();
  });
});
