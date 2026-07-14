import { generateKeyPairSync } from "node:crypto";

import {
  createIntegritySeal,
  hashCanonicalJSON,
} from "../engine-crypto/index.mjs";
import { calculateActivityInteractionSummary } from "../engine-domain/interaction.mjs";

export function sealedTestRecord() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateJWK = privateKey.export({ format: "jwk" });
  const activityInteraction = interactionEvidence();
  const firstData = eventData(1, "0".repeat(64), "request.issued", "owner", "owner@example.test", {}, "2026-01-01T00:00:00.000Z");
  const first = eventRecord(firstData);
  const secondData = eventData(2, first.eventHash, "participant.opened", "participant", "person@example.test", {}, "2026-01-01T00:00:10.000Z");
  const second = eventRecord(secondData);
  const interactionBatch = activityInteraction.batches[0];
  const interactionSummary = activityInteraction.summaries[0];
  const thirdData = eventData(
    3,
    second.eventHash,
    "activity.interaction.recorded",
    "participant",
    "person@example.test",
    {
      activityId: "terms",
      batch: {
        eventCount: interactionBatch.eventCount,
        firstSequence: 1,
        id: interactionBatch.id,
        lastSequence: interactionBatch.eventCount,
        payloadHash: interactionBatch.payloadHash,
        telemetrySessionId: interactionBatch.telemetrySessionId,
      },
      limitation: "Browser-reported activity presence is supporting evidence and does not prove attention or comprehension.",
      summaryHash: interactionSummary.summaryHash,
      summaryRevision: interactionSummary.revision,
    },
    "2026-01-01T00:00:15.000Z",
  );
  const third = eventRecord(thirdData);
  const fourthData = eventData(4, third.eventHash, "request.completed", "participant", "person@example.test", {}, "2026-01-01T00:02:00.000Z");
  const fourth = eventRecord(fourthData);
  const events = [first, second, third, fourth];
  const manifest = {
    activityInteraction,
    assignment: { id: "assignment-1", participantEmail: "person@example.test", principalId: "participant" },
    evidence: {
      eventCount: events.length,
      eventHashes: events.map((event) => event.eventHash),
      firstSequence: 1,
      headHash: fourth.eventHash,
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
    schema: "vasi-evidence-manifest/v5",
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

function interactionEvidence() {
  const policy = {
    heartbeatSeconds: 10,
    idleSeconds: 60,
    maxCreditedGapSeconds: 20,
    version: "vasi-activity-interaction-policy/v1",
  };
  const definitions = [
    ["presented", 0],
    ["visible", 0],
    ["focus", 0],
    ["interaction", 1_000],
    ["heartbeat", 10_000],
    ["disconnect", 12_000],
  ];
  const interactionEvents = definitions.map(([type, monotonicMs], index) => ({
    activityId: "terms",
    batchId: "batch-1",
    event: {
      clientOccurredAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      id: `interaction-event-${index + 1}`,
      monotonicMs,
      sequence: index + 1,
      type,
    },
    id: `interaction-event-${index + 1}`,
    interactionId: "interaction-1",
    receivedAt: "2026-01-01T00:00:15.000Z",
    sequence: index + 1,
    telemetrySessionId: "telemetry-session-1",
    type,
  }));
  const summary = calculateActivityInteractionSummary(policy, interactionEvents);
  const payloadHash = hashCanonicalJSON({
    activityId: "terms",
    batchId: "batch-1",
    events: interactionEvents.map((entry) => entry.event),
    interactionId: "interaction-1",
    telemetrySessionId: "telemetry-session-1",
  });
  return {
    batches: [{
      activityId: "terms",
      actorPrincipalId: "participant",
      eventCount: interactionEvents.length,
      id: "batch-1",
      interactionId: "interaction-1",
      payloadHash,
      receivedAt: "2026-01-01T00:00:15.000Z",
      telemetrySessionId: "telemetry-session-1",
    }],
    events: interactionEvents,
    summaries: [{
      activityId: "terms",
      calculatedAt: "2026-01-01T00:00:15.000Z",
      id: "interaction-summary-1",
      policy,
      revision: 1,
      summary,
      summaryHash: hashCanonicalJSON(summary),
    }],
  };
}

function eventData(sequence, previousHash, eventType, principalId, email, payload = {}, receivedAt) {
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
    payload,
    previousHash,
    receivedAt: receivedAt || new Date(Date.UTC(2026, 0, 1, 0, sequence - 1, 0)).toISOString(),
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
