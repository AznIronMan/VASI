import { describe, expect, it } from "vitest";

import {
  authenticationAssurancePolicy,
  evaluateNextActivity,
  evaluateAuthenticationAssurance,
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
    expect(hasTenantPermission(["owner"], "lifecycle.manage")).toBe(true);
    expect(hasTenantPermission(["manager"], "data_request.review")).toBe(true);
    expect(hasTenantPermission(["auditor"], "lifecycle.read")).toBe(true);
  });

  it("normalizes provider-neutral authentication assurance and preserves legacy access", () => {
    expect(authenticationAssurancePolicy({ authentication: "verified_email" })).toEqual({
      acceptedMethods: ["any_verified"],
      maximumAgeSeconds: null,
    });
    const { document } = validateWorkflowDraft(workflow({
      access: {
        authentication: "verified_email",
        authenticationAssurance: {
          acceptedMethods: ["password", "federated"],
          maximumAgeSeconds: 900,
        },
        postCompletion: "receipt_only",
      },
    }));
    expect(document.access.authenticationAssurance).toEqual({
      acceptedMethods: ["federated", "password"],
      maximumAgeSeconds: 900,
    });
    expect(() => validateWorkflowDraft(workflow({
      access: {
        authentication: "verified_email",
        authenticationAssurance: { acceptedMethods: ["any_verified", "federated"] },
        postCompletion: "receipt_only",
      },
    }))).toThrow(/methods are invalid/);
  });

  it("evaluates method and authentication freshness without provider coupling", () => {
    const policy = { acceptedMethods: ["federated"], maximumAgeSeconds: 900 };
    const now = new Date("2026-07-15T00:15:00.000Z");
    expect(evaluateAuthenticationAssurance(policy, {
      authenticatedAt: Math.floor(new Date("2026-07-15T00:05:01.000Z").getTime() / 1_000),
      authentication: { method: "federated", provider: "arbitrary-oidc" },
    }, now)).toMatchObject({ ageSeconds: 599, satisfied: true });
    expect(evaluateAuthenticationAssurance(policy, {
      authenticatedAt: Math.floor(now.getTime() / 1_000),
      authentication: { method: "password" },
    }, now)).toMatchObject({
      reason: "authentication_method_not_allowed",
      satisfied: false,
    });
    expect(evaluateAuthenticationAssurance(policy, {
      authenticatedAt: Math.floor(new Date("2026-07-14T23:59:59.000Z").getTime() / 1_000),
      authentication: { method: "federated" },
    }, now)).toMatchObject({ reason: "reauthentication_required", satisfied: false });
    expect(evaluateAuthenticationAssurance(policy, {
      authentication: { method: "federated" },
    }, now)).toMatchObject({ reason: "reauthentication_required", satisfied: false });
    expect(evaluateAuthenticationAssurance(policy, {
      authenticatedAt: Number.MAX_SAFE_INTEGER,
      authentication: { method: "federated" },
    }, now)).toMatchObject({ reason: "reauthentication_required", satisfied: false });
  });

  it("allows only declared rich-activity outcomes in forward branches", () => {
    const rich = workflow({
      activities: [
        {
          content: {
            passingPercent: 80,
            questions: [{
              choices: [{ id: "a", label: "A" }, { id: "b", label: "B" }],
              correctChoiceIds: ["b"],
              id: "question_one",
              prompt: "Choose B.",
              type: "single_choice",
            }],
          },
          id: "test",
          responseMode: "questionnaire",
          title: "Knowledge check",
          transition: { cases: [{ to: null, when: { equals: "failed" } }] },
          type: "questionnaire",
        },
        {
          content: { prompt: "Please acknowledge.", terms: "Completion terms." },
          id: "done",
          responseMode: "acknowledgement",
          title: "Done",
          type: "terms_response",
        },
      ],
    });
    const { document } = validateWorkflowDraft(rich);
    expect(evaluateNextActivity(document, "test", { outcome: "passed" })).toBe("done");
    expect(evaluateNextActivity(document, "test", { outcome: "failed" })).toBeNull();
    rich.activities[0].transition.cases[0].when.equals = "arbitrary";
    expect(() => validateWorkflowDraft(rich)).toThrow(/invalid or duplicate branch/);
  });
});
