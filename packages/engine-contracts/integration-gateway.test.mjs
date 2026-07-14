import { describe, expect, it } from "vitest";

import { validateIntegrationDeliveryCommand } from "./integration-gateway.mjs";

const command = {
  attempt: 1,
  capability: "notification.delivery",
  idempotencyKey: "request-1:issued",
  jobId: "job-1",
  payload: {
    eventType: "request.issued",
    participantPath: `/r/${"a".repeat(32)}`,
    recipient: "person@example.test",
    requestId: "request-1",
    tenant: { id: "tenant-1", name: "Example Company" },
    title: "Safety terms",
  },
  schema: "vasi-integration-delivery/v1",
  tenantId: "tenant-1",
};

describe("integration gateway contract", () => {
  it("normalizes a narrow notification delivery command", () => {
    expect(validateIntegrationDeliveryCommand(command)).toMatchObject({
      attempt: 1,
      capability: "notification.delivery",
      tenantId: "tenant-1",
    });
  });

  it("rejects unsupported fields and non-opaque participant paths", () => {
    expect(() => validateIntegrationDeliveryCommand({ ...command, credentials: {} })).toThrow(/unsupported/i);
    expect(() => validateIntegrationDeliveryCommand({
      ...command,
      payload: { ...command.payload, participantPath: "/admin" },
    })).toThrow(/participant path/i);
  });
});
