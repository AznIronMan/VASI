import { describe, expect, it } from "vitest";

import {
  evaluateNextActivity,
  hasTenantPermission,
  validateWorkflowDraft,
} from "./workflow.mjs";

function workflow(overrides = {}) {
  return {
    activities: [
      {
        content: { prompt: "Do you agree?", terms: "First exact terms." },
        id: "first",
        responseMode: "yes_no",
        title: "First decision",
        transition: { cases: [{ when: { equals: "no" }, to: null }] },
        type: "terms_response",
      },
      {
        content: { prompt: "Please acknowledge.", terms: "Second exact terms." },
        id: "second",
        responseMode: "acknowledgement",
        title: "Second step",
        type: "terms_response",
      },
    ],
    purpose: "Conformance proof",
    title: "Two-step workflow",
    ...overrides,
  };
}

describe("workflow contracts", () => {
  it("normalizes a deterministic, declarative workflow", () => {
    const result = validateWorkflowDraft(workflow());
    expect(result.document.schema).toBe("vasi-workflow/v1");
    expect(result.document.activities[0].contractVersion).toBe(1);
    expect(result.document.schedule.defaultExpirationDays).toBe(14);
    expect(result.documentHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("evaluates only declared forward response branches", () => {
    const { document } = validateWorkflowDraft(workflow());
    expect(evaluateNextActivity(document, "first", "yes")).toBe("second");
    expect(evaluateNextActivity(document, "first", "no")).toBeNull();
    expect(evaluateNextActivity(document, "second", "acknowledged")).toBeNull();
  });

  it("rejects cycles and executable or unknown tenant fields", () => {
    const cyclic = workflow();
    cyclic.activities[1].transition = { defaultTo: "first" };
    expect(() => validateWorkflowDraft(cyclic)).toThrow(/move forward/);
    expect(() => validateWorkflowDraft({ ...workflow(), javascript: "return true" })).toThrow(/unsupported/);
    expect(() => validateWorkflowDraft({ ...workflow(), activities: [{ ...workflow().activities[0], type: "custom_code" }] })).toThrow(/Unsupported activity/);
  });

  it("maps company roles independently from identity-administrator roles", () => {
    expect(hasTenantPermission(["owner"], "member.manage")).toBe(true);
    expect(hasTenantPermission(["author"], "workflow.manage")).toBe(true);
    expect(hasTenantPermission(["auditor"], "request.manage")).toBe(false);
    expect(hasTenantPermission(["admin"], "workflow.manage")).toBe(false);
  });
});
