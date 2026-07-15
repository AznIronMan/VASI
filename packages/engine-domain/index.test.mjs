import { describe, expect, it } from "vitest";

import { authorizeServiceAction } from "./index.mjs";

describe("engine service authorization", () => {
  it("allows the private ingress identity endpoint", () => {
    expect(authorizeServiceAction("vasi-private-ingress", "actor.identity")).toEqual({
      action: "actor.identity",
      serviceId: "vasi-private-ingress",
    });
  });

  it("rejects unknown service identities", () => {
    expect(() => authorizeServiceAction("public-browser", "actor.identity")).toThrow(
      "not authorized",
    );
  });

  it("authorizes explicit export and fingerprint verification actions", () => {
    expect(authorizeServiceAction("vasi-private-ingress", "record.export.open").action).toBe(
      "record.export.open",
    );
    expect(authorizeServiceAction("vasi-private-ingress", "verification.lookup").action).toBe(
      "verification.lookup",
    );
    expect(authorizeServiceAction("vasi-private-ingress", "lifecycle.hold.command").action).toBe(
      "lifecycle.hold.command",
    );
    expect(authorizeServiceAction("vasi-private-ingress", "participant.data_request.create").action).toBe(
      "participant.data_request.create",
    );
    expect(authorizeServiceAction("vasi-private-ingress", "operations.read").action).toBe(
      "operations.read",
    );
    expect(authorizeServiceAction("vasi-private-ingress", "tenant.readiness.export").action).toBe(
      "tenant.readiness.export",
    );
    expect(authorizeServiceAction("vasi-private-ingress", "participant.context.record").action).toBe(
      "participant.context.record",
    );
  });
});
