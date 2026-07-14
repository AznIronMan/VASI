import { describe, expect, it } from "vitest";

import { requesterSnapshot, validateRequesterSnapshot } from "./requester.mjs";

describe("requester evidence snapshot", () => {
  it("normalizes and validates an authenticated issuance actor", () => {
    const snapshot = requesterSnapshot({ email: "Owner@Example.Test", principalId: "owner-1" });
    expect(snapshot).toEqual({
      email: "owner@example.test",
      principalId: "owner-1",
      provenance: "authenticated_actor_at_issuance",
      relationship: "requesting_organization",
      schema: "vasi-requester-snapshot/v1",
    });
    expect(validateRequesterSnapshot(snapshot, "owner-1")).toEqual(snapshot);
  });

  it("rejects missing identities, mismatched principals, and invented provenance", () => {
    expect(() => requesterSnapshot({ principalId: "owner-1" })).toThrow("requester_identity_required");
    expect(() => validateRequesterSnapshot({
      email: "owner@example.test",
      principalId: "owner-1",
      provenance: "current_membership_lookup",
      relationship: "requesting_organization",
      schema: "vasi-requester-snapshot/v1",
    }, "owner-2")).toThrow("requester_snapshot_invalid");
    expect(() => validateRequesterSnapshot({
      ...requesterSnapshot({ email: "owner@example.test", principalId: "owner-1" }),
      currentRoles: ["owner"],
    })).toThrow("requester_snapshot_invalid");
  });
});
