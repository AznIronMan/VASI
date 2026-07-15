import { describe, expect, it } from "vitest";

import {
  NOTIFICATION_DELIVERY_LIMITATIONS,
  notificationEvidenceOutcome,
  notificationOperationalStatus,
  validateNotificationDeliveryEvidence,
} from "./notifications.mjs";

const capturedAt = "2026-07-14T20:00:00.000Z";

describe("notification delivery evidence", () => {
  it("uses honest operational provider-acceptance semantics", () => {
    expect(notificationOperationalStatus({ status: "completed", resultOutcome: "delivered" })).toBe("provider_accepted");
    expect(notificationOperationalStatus({
      attemptOutcome: "failed",
      resultOutcome: "delivered",
      status: "completed",
    })).toBe("provider_accepted");
    expect(notificationOperationalStatus({ status: "completed", resultOutcome: "suppressed" })).toBe("suppressed");
    expect(notificationOperationalStatus({ availableAt: "2026-07-15T00:00:00.000Z", status: "pending" }, new Date(capturedAt))).toBe("scheduled");
    expect(notificationOperationalStatus({ availableAt: "2026-07-14T19:00:00.000Z", status: "participant_pending" }, new Date(capturedAt))).toBe("queued");
    expect(notificationEvidenceOutcome("delivered")).toBe("provider_accepted");
  });

  it("accepts bounded evidence without message or provider response data", () => {
    const evidence = fixture();
    expect(validateNotificationDeliveryEvidence(evidence, capturedAt)).toEqual(evidence);
  });

  it("rejects invasive fields, malformed time, and inaccurate acceptance claims", () => {
    const invasive = fixture();
    invasive.jobs[0].recipient = "person@example.test";
    expect(() => validateNotificationDeliveryEvidence(invasive, capturedAt)).toThrow("notification_delivery_field_unsupported");

    const futureAttempt = fixture();
    futureAttempt.jobs[0].attempts[0].completedAt = "2026-07-14T21:00:00.000Z";
    expect(() => validateNotificationDeliveryEvidence(futureAttempt, capturedAt)).toThrow("notification_delivery_attempt_time_invalid");

    const falseAcceptance = fixture();
    falseAcceptance.jobs[0].attempts[0].outcome = "failed";
    falseAcceptance.jobs[0].attempts[0].errorCode = "graph_send_status";
    expect(() => validateNotificationDeliveryEvidence(falseAcceptance, capturedAt)).toThrow("notification_delivery_status_attempt_mismatch");
  });
});

function fixture() {
  return {
    capturedAt,
    jobs: [{
      attempts: [{
        adapter: "microsoft_graph",
        attempt: 1,
        completedAt: "2026-07-14T19:01:01.000Z",
        outcome: "provider_accepted",
        startedAt: "2026-07-14T19:01:00.000Z",
      }],
      id: "job-1",
      notificationType: "request.issued",
      queuedAt: "2026-07-14T19:00:00.000Z",
      scheduledFor: "2026-07-14T19:00:00.000Z",
      status: "provider_accepted",
    }],
    limitations: [...NOTIFICATION_DELIVERY_LIMITATIONS],
    schema: "vasi-notification-delivery-evidence/v1",
  };
}
