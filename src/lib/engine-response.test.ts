import { describe, expect, it } from "vitest";

import { friendlyEngineError, gatewayEngineResponse } from "@/lib/engine-response";

describe("engine authentication-assurance responses", () => {
  it("preserves only the safe reauthentication reason codes needed by the participant UI", async () => {
    const stale = gatewayEngineResponse({
      body: { error: "reauthentication_required" },
      status: 401,
    });
    await expect(stale.json()).resolves.toEqual({
      code: "reauthentication_required",
      error: friendlyEngineError("reauthentication_required"),
    });

    const denied = gatewayEngineResponse({
      body: { error: "authentication_method_not_allowed" },
      status: 403,
    });
    await expect(denied.json()).resolves.toEqual({
      code: "authentication_method_not_allowed",
      error: friendlyEngineError("authentication_method_not_allowed"),
    });

    const internal = gatewayEngineResponse({
      body: { error: "authentication_assurance_policy_invalid" },
      status: 500,
    });
    await expect(internal.json()).resolves.toEqual({
      error: "The private VASI engine could not complete the request.",
    });
  });
});
