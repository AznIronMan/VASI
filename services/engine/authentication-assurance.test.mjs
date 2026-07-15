import { describe, expect, it } from "vitest";

import { requireAuthenticationAssurance } from "./authentication-assurance.mjs";

describe("private-engine authentication assurance", () => {
  const now = new Date("2026-07-15T00:15:00.000Z");
  const access = {
    authenticationAssurance: { acceptedMethods: ["federated"], maximumAgeSeconds: 900 },
  };

  it("returns only a bounded accepted evaluation", () => {
    expect(requireAuthenticationAssurance(access, {
      authenticatedAt: Math.floor(new Date("2026-07-15T00:10:00.000Z").getTime() / 1_000),
      authentication: {
        method: "federated",
        provider: "google",
        providerSubject: "must-not-appear",
      },
    }, now)).toMatchObject({
      ageSeconds: 300,
      observation: { method: "federated", provider: "google" },
      satisfied: true,
    });
  });

  it("uses distinct bounded denials for method and freshness", () => {
    expect(() => requireAuthenticationAssurance(access, {
      authenticatedAt: Math.floor(now.getTime() / 1_000),
      authentication: { method: "password" },
    }, now)).toThrow(expect.objectContaining({ code: "authentication_method_not_allowed", status: 403 }));
    expect(() => requireAuthenticationAssurance(access, {
      authenticatedAt: Math.floor(new Date("2026-07-14T23:00:00.000Z").getTime() / 1_000),
      authentication: { method: "federated" },
    }, now)).toThrow(expect.objectContaining({ code: "reauthentication_required", status: 401 }));
  });
});
