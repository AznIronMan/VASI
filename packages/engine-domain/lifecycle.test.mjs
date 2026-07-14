import { describe, expect, it } from "vitest";

import {
  SYSTEM_RETENTION_POLICY,
  calculateRetentionDeadlines,
  normalizeRetentionPolicy,
  participantMatches,
  retentionPolicyHash,
  validateLegalHoldCommand,
  validateParticipantDataRequestReview,
  validateRetentionPolicyMutation,
} from "./lifecycle.mjs";

describe("lifecycle governance domain", () => {
  it("normalizes and hashes independent lifecycle horizons", () => {
    const policy = normalizeRetentionPolicy({
      contentAccess: { daysAfterTerminal: 14, mode: "days_after_terminal" },
      evidence: { archiveAfterDays: 365, deleteAfterDays: 2_555 },
      participantHistory: { daysAfterTerminal: 730 },
      schema: "vasi-retention-policy/v1",
    });
    expect(policy.contentAccess.daysAfterTerminal).toBe(14);
    expect(retentionPolicyHash(policy)).toMatch(/^[a-f0-9]{64}$/);
  });

  it("calculates deadlines from the terminal event without conflating content and evidence", () => {
    const dates = calculateRetentionDeadlines(
      {
        contentAccess: { mode: "request_expiration" },
        evidence: { archiveAfterDays: 10, deleteAfterDays: 20 },
        participantHistory: { daysAfterTerminal: 5 },
        schema: "vasi-retention-policy/v1",
      },
      {
        expiresAt: "2026-02-01T00:00:00.000Z",
        terminalAt: "2026-01-10T00:00:00.000Z",
      },
    );
    expect(dates.contentExpiresAt.toISOString()).toBe("2026-02-01T00:00:00.000Z");
    expect(dates.historyExpiresAt.toISOString()).toBe("2026-01-15T00:00:00.000Z");
    expect(dates.archiveAt.toISOString()).toBe("2026-01-20T00:00:00.000Z");
    expect(dates.deleteAt.toISOString()).toBe("2026-01-30T00:00:00.000Z");
  });

  it("defaults to non-destructive evidence retention", () => {
    expect(SYSTEM_RETENTION_POLICY.evidence.deleteAfterDays).toBeNull();
    expect(SYSTEM_RETENTION_POLICY.participantHistory.daysAfterTerminal).toBeNull();
    expect(calculateRetentionDeadlines(SYSTEM_RETENTION_POLICY, {
      expiresAt: "2026-01-01T00:00:00.000Z",
    }).deleteAt).toBeNull();
  });

  it("rejects deletion before archive and ambiguous content durations", () => {
    expect(() => normalizeRetentionPolicy({
      contentAccess: { mode: "indefinite", daysAfterTerminal: 1 },
      evidence: { archiveAfterDays: 10, deleteAfterDays: 5 },
      participantHistory: { daysAfterTerminal: 30 },
    })).toThrow();
    expect(() => normalizeRetentionPolicy({
      contentAccess: { mode: "request_expiration" },
      evidence: { archiveAfterDays: 10, deleteAfterDays: 5 },
      participantHistory: { daysAfterTerminal: 30 },
    })).toThrow("Evidence deletion cannot precede archival");
  });

  it("validates versioned policy, hold, and reviewed export commands", () => {
    expect(validateRetentionPolicyMutation({
      expectedRevision: 0,
      name: "Tenant_Default",
      policy: SYSTEM_RETENTION_POLICY,
      tenantId: "tenant-1",
    }).name).toBe("tenant_default");
    expect(validateLegalHoldCommand({
      action: "place",
      assignmentId: "assignment-1",
      caseReference: "Matter 24-100",
      commandId: "hold-1",
      reason: "Preserve the record while the matter is open.",
      tenantId: "tenant-1",
    }).action).toBe("place");
    expect(validateParticipantDataRequestReview({
      commandId: "review-1",
      decision: "approve",
      requestId: "request-1",
      tenantId: "tenant-1",
    }).includeTechnicalTelemetry).toBe(true);
  });

  it("matches a participant by bound principal or verified email", () => {
    expect(participantMatches({ principalId: "p1", email: "a@example.test" }, "p1", "b@example.test")).toBe(true);
    expect(participantMatches({ principalId: "p2", email: "A@example.test" }, "p1", "a@example.test")).toBe(true);
    expect(participantMatches({ principalId: "p2", email: "c@example.test" }, "p1", "a@example.test")).toBe(false);
  });
});
