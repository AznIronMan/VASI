import { generateKeyPairSync } from "node:crypto";

import {
  createIntegritySeal,
  hashCanonicalJSON,
} from "../engine-crypto/index.mjs";
import { calculateActivityInteractionSummary } from "../engine-domain/interaction.mjs";
import {
  participantContextPolicy,
  withParticipantContextProvenance,
} from "../engine-domain/context.mjs";
import { NOTIFICATION_DELIVERY_LIMITATIONS } from "../engine-domain/notifications.mjs";
import {
  applyTenantAdmissionDecision,
  defaultTenantAdmission,
  TENANT_ADMISSION_GATES,
} from "../engine-domain/productization.mjs";
import { evaluateAuthenticationAssurance } from "../engine-domain/workflow.mjs";

export function sealedTestRecord() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateJWK = privateKey.export({ format: "jwk" });
  const activityInteraction = interactionEvidence();
  const participantContext = contextEvidence();
  const notificationDelivery = notificationEvidence();
  const admission = admissionEvidence();
  const authenticationPolicy = {
    acceptedMethods: ["federated"],
    maximumAgeSeconds: 900,
  };
  const firstData = eventData(1, "0".repeat(64), "request.issued", "owner", "owner@example.test", { admission: structuredClone(admission) }, "2026-01-01T00:00:00.000Z");
  const first = eventRecord(firstData);
  const secondData = eventData(2, first.eventHash, "participant.opened", "participant", "person@example.test", {}, "2026-01-01T00:00:10.000Z");
  secondData.payload.authenticationAssurance = evaluateAuthenticationAssurance(
    authenticationPolicy,
    secondData.actor,
    secondData.receivedAt,
  );
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
  const contextSnapshot = participantContext.snapshots[0];
  const fourthData = eventData(
    4,
    third.eventHash,
    "participant.context.recorded",
    "participant",
    "person@example.test",
    {
      activityId: "terms",
      contextSessionId: contextSnapshot.contextSessionId,
      interactionId: contextSnapshot.interactionId,
      limitation: "Browser-reported context is supporting evidence and does not prove identity, attention, comprehension, or physical location.",
      snapshot: {
        id: contextSnapshot.id,
        payloadHash: contextSnapshot.payloadHash,
        purpose: contextSnapshot.purpose,
        schema: contextSnapshot.schema,
        sequence: contextSnapshot.sequence,
      },
    },
    contextSnapshot.receivedAt,
  );
  const fourth = eventRecord(fourthData);
  const fifthData = eventData(5, fourth.eventHash, "activity.response.submitted", "participant", "person@example.test", {}, "2026-01-01T00:01:00.000Z");
  fifthData.payload.authenticationAssurance = evaluateAuthenticationAssurance(
    authenticationPolicy,
    fifthData.actor,
    fifthData.receivedAt,
  );
  const fifth = eventRecord(fifthData);
  const sixthData = eventData(6, fifth.eventHash, "request.completed", "participant", "person@example.test", {}, "2026-01-01T00:02:00.000Z");
  const sixth = eventRecord(sixthData);
  const events = [first, second, third, fourth, fifth, sixth];
  const manifest = {
    admission,
    activityInteraction,
    authenticationAssurance: {
      evaluations: [secondData, fifthData].map((event) => ({
        evaluation: event.payload.authenticationAssurance,
        eventId: event.eventId,
        eventType: event.eventType,
      })),
      policy: authenticationPolicy,
      schema: "vasi-authentication-assurance-evidence/v1",
    },
    assignment: { id: "assignment-1", participantEmail: "person@example.test", principalId: "participant" },
    evidence: {
      eventCount: events.length,
      eventHashes: events.map((event) => event.eventHash),
      firstSequence: 1,
      headHash: sixth.eventHash,
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
    notificationDelivery,
    participantContext,
    request: {
      accessPolicy: {
        authentication: "verified_email",
        authenticationAssurance: authenticationPolicy,
        postCompletion: "receipt_only",
      },
      expiresAt: "2026-01-08T00:00:00.000Z",
      id: "request-1",
      purpose: "Test evidence reporting",
    },
    requester: {
      email: "owner@example.test",
      principalId: "owner",
      provenance: "authenticated_actor_at_issuance",
      relationship: "requesting_organization",
      schema: "vasi-requester-snapshot/v1",
    },
    schema: "vasi-evidence-manifest/v10",
    tenant: { id: "tenant-1", name: "Example Company" },
    timestamps: {
      completedAt: "2026-01-01T00:02:00.000Z",
      issuedAt: "2026-01-01T00:00:00.000Z",
      startedAt: "2026-01-01T00:00:30.000Z",
    },
    workflow: {
      id: "workflow-1",
      revision: 1,
      snapshot: {
        access: {
          authentication: "verified_email",
          authenticationAssurance: authenticationPolicy,
          postCompletion: "receipt_only",
        },
        activities: [],
        purpose: "Test evidence reporting",
        schema: "vasi-workflow/v1",
        title: "Example terms",
      },
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

function admissionEvidence() {
  let admission = defaultTenantAdmission();
  for (const gateId of TENANT_ADMISSION_GATES) {
    admission = applyTenantAdmissionDecision(admission, {
      decision: "approved",
      evidenceDigest: hashCanonicalJSON({ gateId }),
      evidenceReference: `fixture:${gateId}`,
      expectedRevision: 1,
      gateId,
      reviewerReference: `reviewer:${gateId}`,
      tenantId: "tenant-1",
    }, new Date("2025-12-31T12:00:00.000Z"));
  }
  return {
    admission,
    admissionHash: hashCanonicalJSON(admission),
    bindingProvenance: "issued",
    revision: 9,
    revisionId: "admission-revision-9",
  };
}

function notificationEvidence() {
  return {
    capturedAt: "2026-01-01T00:02:00.000Z",
    jobs: [{
      attempts: [{
        adapter: "microsoft_graph",
        attempt: 1,
        completedAt: "2026-01-01T00:00:02.000Z",
        outcome: "provider_accepted",
        startedAt: "2026-01-01T00:00:01.000Z",
      }],
      id: "notification-job-1",
      notificationType: "request.issued",
      queuedAt: "2026-01-01T00:00:00.000Z",
      scheduledFor: "2026-01-01T00:00:00.000Z",
      status: "provider_accepted",
    }],
    limitations: [...NOTIFICATION_DELIVERY_LIMITATIONS],
    schema: "vasi-notification-delivery-evidence/v1",
  };
}

function contextEvidence() {
  const snapshot = withParticipantContextProvenance({
    browser: {
      language: "en-US",
      languages: ["en-US", "en"],
      online: true,
      timeZone: "America/Los_Angeles",
    },
    capabilities: {
      cookiesEnabled: true,
      localStorage: "available",
      pdfViewerEnabled: true,
      sessionStorage: "available",
    },
    clientOccurredAt: "2026-01-01T00:00:20.000Z",
    connection: { effectiveType: "4g", rttMs: 50, saveData: false },
    display: {
      colorDepth: 24,
      devicePixelRatio: 2,
      screenHeight: 1080,
      screenWidth: 1920,
      viewportHeight: 900,
      viewportWidth: 1440,
    },
    id: "context-snapshot-1",
    input: { maxTouchPoints: 0 },
    monotonicMs: 20_000,
    preferences: {
      colorScheme: "dark",
      contrast: "no-preference",
      forcedColors: false,
      reducedMotion: true,
    },
    purpose: "presentation",
    schema: "vasi-participant-context/v1",
    sequence: 1,
  });
  const activityId = "terms";
  const contextSessionId = "context-session-1";
  const interactionId = "interaction-1";
  return {
    policy: participantContextPolicy(),
    snapshots: [{
      activityId,
      actorPrincipalId: "participant",
      contextSessionId,
      gatewaySessionId: "session-participant",
      id: snapshot.id,
      interactionId,
      payloadHash: hashCanonicalJSON({ activityId, contextSessionId, interactionId, snapshot }),
      purpose: snapshot.purpose,
      receivedAt: "2026-01-01T00:00:20.100Z",
      requestContext: { ipAddress: "192.0.2.20", userAgent: "VASI test browser" },
      schema: snapshot.schema,
      sequence: snapshot.sequence,
      snapshot,
    }],
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
      authentication: { method: "federated", provider: principalId === "owner" ? "microsoft" : "google" },
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
