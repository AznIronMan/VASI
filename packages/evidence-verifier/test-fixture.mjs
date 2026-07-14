import { generateKeyPairSync } from "node:crypto";

import {
  createIntegritySeal,
  hashCanonicalJSON,
} from "../engine-crypto/index.mjs";

export function sealedTestRecord() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateJWK = privateKey.export({ format: "jwk" });
  const firstData = eventData(1, "0".repeat(64), "request.issued", "owner", "owner@example.test");
  const first = eventRecord(firstData);
  const secondData = eventData(2, first.eventHash, "participant.opened", "participant", "person@example.test");
  const second = eventRecord(secondData);
  const thirdData = eventData(3, second.eventHash, "request.completed", "participant", "person@example.test");
  const third = eventRecord(thirdData);
  const events = [first, second, third];
  const manifest = {
    assignment: { id: "assignment-1", participantEmail: "person@example.test", principalId: "participant" },
    evidence: {
      eventCount: events.length,
      eventHashes: events.map((event) => event.eventHash),
      firstSequence: 1,
      headHash: third.eventHash,
      lastSequence: events.length,
    },
    outcome: {
      activities: [{
        activityId: "terms",
        definitionHash: "a".repeat(64),
        ordinal: 1,
        outcome: "acknowledged",
        respondedAt: "2026-01-01T00:01:00.000Z",
        response: "acknowledged",
        responseLabel: "Acknowledged",
        revisions: [],
      }],
      status: "completed",
    },
    request: { expiresAt: "2026-01-08T00:00:00.000Z", id: "request-1", purpose: "Test evidence reporting" },
    schema: "vasi-evidence-manifest/v4",
    tenant: { id: "tenant-1", name: "Example Company" },
    timestamps: {
      completedAt: "2026-01-01T00:02:00.000Z",
      issuedAt: "2026-01-01T00:00:00.000Z",
      startedAt: "2026-01-01T00:00:30.000Z",
    },
    workflow: {
      id: "workflow-1",
      revision: 1,
      snapshot: { activities: [], purpose: "Test evidence reporting", schema: "vasi-workflow/v1", title: "Example terms" },
      snapshotHash: "b".repeat(64),
      title: "Example terms",
    },
  };
  const seal = {
    ...createIntegritySeal({ keyId: "test-seal-key", manifest, privateJWK }),
    createdAt: manifest.timestamps.completedAt,
    role: "vasi_integrity",
  };
  return {
    privateJWK,
    record: { events, manifest, seal, seals: [seal] },
  };
}

function eventData(sequence, previousHash, eventType, principalId, email) {
  return {
    actor: {
      authenticatedAt: 1_767_225_600,
      authentication: { method: "oauth", provider: principalId === "owner" ? "microsoft" : "google" },
      email,
      gatewaySessionId: `session-${principalId}`,
      principalId,
      requestContext: { ipAddress: "192.0.2.20", userAgent: "VASI test browser" },
      roles: principalId === "owner" ? ["owner"] : ["user"],
    },
    assignmentId: "assignment-1",
    engineVersion: "0.9.0",
    eventId: `event-${sequence}`,
    eventType,
    payload: {},
    previousHash,
    receivedAt: new Date(Date.UTC(2026, 0, 1, 0, sequence - 1, 0)).toISOString(),
    requestId: "request-1",
    schema: "vasi-evidence-event/v1",
    sequence,
    tenantId: "tenant-1",
  };
}

function eventRecord(eventData) {
  return {
    eventData,
    eventHash: hashCanonicalJSON(eventData),
    previousHash: eventData.previousHash,
    sequence: eventData.sequence,
  };
}
