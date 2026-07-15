import { describe, expect, it, vi } from "vitest";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import { assertNotificationJobCurrent } from "./store.mjs";

const payload = {
  eventType: "participant_data.ready",
  expiresAt: "2030-01-02T03:04:05.000Z",
  participantPath: "/workspace",
  recipient: "person@example.test",
  requestStatus: "ready",
  schema: "vasi-participant-data-notification/v1",
  tenant: { id: "tenant-1", name: "Example Company" },
};
const command = {
  attempt: 1,
  idempotencyKey: "participant-data:privacy-1:tenant-1:participant_data.ready",
  jobId: "job-1",
  payload,
  tenantId: "tenant-1",
};

describe("integration gateway notification source binding", () => {
  it("locks and accepts only the exact running job and current privacy scope", async () => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({
          rowCount: 1,
          rows: [{
            attempts: 1,
            idempotencyKey: command.idempotencyKey,
            jobType: "notification",
            notificationType: payload.eventType,
            participantDataRequestId: "privacy-1",
            payloadHash: hashCanonicalJSON(payload),
            requestId: null,
            status: "running",
            tenantId: "tenant-1",
          }],
        })
        .mockResolvedValueOnce({
          rowCount: 1,
          rows: [{ requestStatus: "ready", scopeStatus: "approved" }],
        }),
    };

    await expect(assertNotificationJobCurrent(client, command)).resolves.toBeUndefined();
    expect(client.query.mock.calls[0][0]).toContain("for share");
    expect(client.query.mock.calls[1][0]).toContain("for share of r, s");
  });

  it("suppresses a readiness command after the export status changes", async () => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({
          rowCount: 1,
          rows: [{
            attempts: 1,
            idempotencyKey: command.idempotencyKey,
            jobType: "notification",
            notificationType: payload.eventType,
            participantDataRequestId: "privacy-1",
            payloadHash: hashCanonicalJSON(payload),
            requestId: null,
            status: "running",
            tenantId: "tenant-1",
          }],
        })
        .mockResolvedValueOnce({
          rowCount: 1,
          rows: [{ requestStatus: "expired", scopeStatus: "approved" }],
        }),
    };

    await expect(assertNotificationJobCurrent(client, command)).rejects.toMatchObject({
      code: "notification_job_obsolete",
    });
  });

  it("rejects payload or tenant substitution before loading credentials", async () => {
    const client = {
      query: vi.fn().mockResolvedValue({
        rowCount: 1,
        rows: [{
          attempts: 1,
          idempotencyKey: command.idempotencyKey,
          jobType: "notification",
          notificationType: payload.eventType,
          participantDataRequestId: "privacy-1",
          payloadHash: hashCanonicalJSON(payload),
          requestId: null,
          status: "running",
          tenantId: "tenant-1",
        }],
      }),
    };

    await expect(assertNotificationJobCurrent(client, {
      ...command,
      payload: { ...payload, recipient: "other@example.test" },
    })).rejects.toMatchObject({ code: "integration_job_integrity_failure" });
    expect(client.query).toHaveBeenCalledTimes(1);
  });
});
