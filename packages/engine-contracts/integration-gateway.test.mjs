import { describe, expect, it } from "vitest";

import {
  validateArtifactScanCommand,
  validateIntegrationDeliveryCommand,
} from "./integration-gateway.mjs";

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

  it("accepts only bounded participant-data status mail to the workspace", () => {
    const privacyCommand = {
      ...command,
      idempotencyKey: "participant-data:request-1:tenant-1:participant_data.ready",
      payload: {
        eventType: "participant_data.ready",
        expiresAt: "2030-01-02T03:04:05.000Z",
        participantPath: "/workspace",
        recipient: "person@example.test",
        requestStatus: "ready",
        schema: "vasi-participant-data-notification/v1",
        tenant: { id: "tenant-1", name: "Example Company" },
      },
    };
    expect(validateIntegrationDeliveryCommand(privacyCommand).payload).toEqual(privacyCommand.payload);
    expect(() => validateIntegrationDeliveryCommand({
      ...privacyCommand,
      payload: { ...privacyCommand.payload, participantPath: "/admin" },
    })).toThrow(/path/i);
    expect(() => validateIntegrationDeliveryCommand({
      ...privacyCommand,
      payload: { ...privacyCommand.payload, rawExport: {} },
    })).toThrow(/unsupported/i);
  });
});

describe("artifact scan gateway contract", () => {
  const scan = {
    artifactId: "artifact-1",
    byteLength: 1_024,
    capability: "document.malware_scan",
    mediaType: "application/pdf",
    scanRequestId: "scan-1",
    schema: "vasi-artifact-scan/v1",
    sha256: "a".repeat(64),
    tenantId: "tenant-1",
  };

  it("normalizes only digest-bound, privacy-minimized scan metadata", () => {
    expect(validateArtifactScanCommand(scan)).toEqual(scan);
    expect(JSON.stringify(scan)).not.toContain("filename");
  });

  it("rejects extension fields, invalid digests, and unsupported media types", () => {
    expect(() => validateArtifactScanCommand({ ...scan, originalFilename: "secret.pdf" })).toThrow(/unsupported/i);
    expect(() => validateArtifactScanCommand({ ...scan, sha256: "wrong" })).toThrow(/sha256/i);
    expect(() => validateArtifactScanCommand({ ...scan, mediaType: "invalid" })).toThrow(/mediaType/i);
  });
});
