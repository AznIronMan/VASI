import { describe, expect, it } from "vitest";

import { participantHistoryProjection } from "./lifecycle-store.mjs";

const now = new Date("2026-07-14T20:00:00.000Z");

describe("participant transaction history", () => {
  it("projects participant-safe authentication, chronology, outcomes, and delivery state", () => {
    const record = participantHistoryProjection(fixture(), now);

    expect(record.authentication).toEqual({
      authenticatedAt: "2026-07-14T18:59:30.000Z",
      method: "federated",
      observedAt: "2026-07-14T19:05:00.000Z",
      provider: "microsoft",
      provenance: "session_exact",
    });
    expect(record.authentication).not.toHaveProperty("providerSubject");
    expect(record.invitation).toEqual({
      adapter: "microsoft_graph",
      completedAt: "2026-07-14T19:01:01.000Z",
      queuedAt: "2026-07-14T19:00:00.000Z",
      scheduledFor: "2026-07-14T19:00:00.000Z",
      status: "provider_accepted",
    });
    expect(record.activity).toEqual({
      lastActivityAt: "2026-07-14T19:20:00.000Z",
      resolved: 2,
      total: 2,
    });
    expect(record.responses).toEqual([{
      activityId: "approval",
      activityTitle: "Approve the policy",
      outcome: "approved",
      respondedAt: "2026-07-14T19:20:00.000Z",
      responseLabel: "Approved",
    }]);
    expect(record.schedule).toEqual({
      dueAt: "2026-07-20T19:00:00.000Z",
      expiresAt: "2026-07-28T19:00:00.000Z",
      scheduledFor: "2026-07-14T19:00:00.000Z",
    });
    expect(record.statusChangedAt).toBe("2026-07-14T19:30:00.000Z");
    expect(record.lifecycle.contentAvailable).toBe(true);
    expect(record.lifecycle.contentAccessPolicy).toBe("content_always");
  });

  it("reports missing legacy observations without guessing or leaking unbounded fields", () => {
    const input = fixture({
      activityCount: 0,
      authentication: { method: "federated", provider: "google", providerSubject: "must-not-leak" },
      authenticatedAt: null,
      authenticationObservedAt: null,
      resolvedActivityCount: 0,
      accessPolicy: { postCompletion: "receipt_only" },
      contentExpiresAt: "2026-07-28T19:00:00.000Z",
      invitationJobStatus: null,
      legacyRespondedAt: "2026-07-14T19:10:00.000Z",
      legacyResponseMode: "yes_no",
      legacyResponseValue: "yes",
      lastActivityAt: null,
      responses: [],
      status: "in_progress",
    });
    const record = participantHistoryProjection(input, now);

    expect(record.authentication).toEqual({ method: "federated", provider: "google" });
    expect(record.invitation).toEqual({ status: "manual_link_only" });
    expect(record.responses).toEqual([{
      activityId: "legacy_response",
      activityTitle: "Recorded response",
      outcome: "yes_no",
      respondedAt: "2026-07-14T19:10:00.000Z",
      responseLabel: "yes",
    }]);
    expect(record.activity).toEqual({
      lastActivityAt: "2026-07-14T19:10:00.000Z",
      resolved: 0,
      total: 1,
    });
    expect(record.lifecycle.contentAvailable).toBe(true);
    expect(record.statusChangedAt).toBe("2026-07-14T19:05:00.000Z");
  });

  it("fails closed on completed content when the immutable workflow is receipt only", () => {
    const record = participantHistoryProjection(fixture({
      accessPolicy: { postCompletion: "receipt_only" },
    }), now);

    expect(record.lifecycle).toMatchObject({
      contentAccessPolicy: "receipt_only",
      contentAvailable: false,
    });
    expect(record.lifecycle.contentExpiresAt).toBeUndefined();
  });

  it("normalizes assertion Unix seconds and rejects malformed authentication time", () => {
    const seconds = String(Date.parse("2026-07-14T18:59:30.000Z") / 1_000);
    expect(participantHistoryProjection(fixture({ authenticatedAt: seconds }), now).authentication)
      .toMatchObject({ authenticatedAt: "2026-07-14T18:59:30.000Z" });
    expect(participantHistoryProjection(fixture({ authenticatedAt: "1780000000000" }), now).authentication)
      .not.toHaveProperty("authenticatedAt");
    expect(participantHistoryProjection(fixture({ authenticatedAt: "not-a-time" }), now).authentication)
      .not.toHaveProperty("authenticatedAt");
  });
});

function fixture(overrides = {}) {
  return {
    activityCount: 2,
    accessPolicy: { postCompletion: "content_always" },
    archiveAt: null,
    assignmentId: "assignment-1",
    authenticatedAt: "2026-07-14T18:59:30.000Z",
    authentication: {
      linkedProvider: "yahoo",
      method: "federated",
      provenance: "session_exact",
      provider: "microsoft",
      providerSubject: "must-not-leak",
    },
    authenticationObservedAt: "2026-07-14T19:05:00.000Z",
    resolvedActivityCount: 2,
    completedAt: "2026-07-14T19:30:00.000Z",
    contentExpiresAt: "2026-07-28T19:00:00.000Z",
    contentStatus: "active",
    deleteAt: null,
    dueAt: "2026-07-20T19:00:00.000Z",
    evidenceStatus: "active",
    expiresAt: "2026-07-28T19:00:00.000Z",
    firstOpenedAt: "2026-07-14T19:05:00.000Z",
    historyExpiresAt: null,
    invitationAttemptAdapter: "microsoft_graph",
    invitationAttemptCompletedAt: "2026-07-14T19:01:01.000Z",
    invitationAttemptOutcome: "delivered",
    invitationAvailableAt: "2026-07-14T19:00:00.000Z",
    invitationCompletedAt: "2026-07-14T19:01:01.000Z",
    invitationJobStatus: "completed",
    invitationQueuedAt: "2026-07-14T19:00:00.000Z",
    invitationResultAdapter: "microsoft_graph",
    invitationResultOutcome: "delivered",
    issuedAt: "2026-07-14T19:00:00.000Z",
    lastActivityAt: "2026-07-14T19:20:00.000Z",
    manifestHash: "a".repeat(64),
    purpose: "Approve a policy",
    requestId: "request-1",
    requesterSnapshot: { email: "owner@example.test" },
    responses: [{
      activityId: "approval",
      activityTitle: "Approve the policy",
      outcome: "approved",
      respondedAt: "2026-07-14T19:20:00.000Z",
      responseLabel: "Approved",
    }],
    revision: 3,
    scheduledFor: "2026-07-14T19:00:00.000Z",
    snapshotHash: "b".repeat(64),
    status: "completed",
    tenantId: "tenant-1",
    tenantName: "Example Company",
    title: "Policy approval",
    workflowRevisionId: "workflow-3",
    ...overrides,
  };
}
