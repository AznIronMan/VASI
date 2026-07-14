import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { verifyEvidenceRecord } from "../services/engine/evidence-store.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1_000);
const owner = actor("interaction-owner", "interaction-owner@example.test", ["admin"]);
const participant = actor("interaction-participant", "interaction-participant@example.test", ["user"]);
const intruder = actor("interaction-intruder", "interaction-intruder@example.test", ["user"]);

const tenant = await call(owner, "POST", "/v1/owner/tenants", {
  name: "VASI Activity Interaction Proof",
  slug: `interaction-${randomUUID()}`,
});
expectStatus(tenant, 200, "interaction tenant creation");

const created = await call(owner, "POST", "/v1/owner/workflows", {
  document: workflowDocument(),
  name: "General activity presence proof",
  tenantId: tenant.body.id,
});
expectStatus(created, 200, "interaction workflow creation");
const published = await call(owner, "POST", "/v1/owner/workflow-publications", {
  definitionId: created.body.definitionId,
  expectedDraftVersion: created.body.draftVersion,
  tenantId: tenant.body.id,
});
expectStatus(published, 200, "interaction workflow publication");
const issued = await call(owner, "POST", "/v1/owner/requests", {
  intendedEmail: participant.email,
  tenantId: tenant.body.id,
  workflowRevisionId: published.body.revisionId,
});
expectStatus(issued, 200, "interaction request issue");
const handle = issued.body.participantPath.split("/").at(-1);
const opened = await call(participant, "POST", "/v1/participant/open", { handle });
expectStatus(opened, 200, "interaction participant open");
if (
  opened.body.activityId !== "terms" ||
  opened.body.interactionEvidence?.policy?.version !== "vasi-activity-interaction-policy/v1"
) throw new Error("The generalized interaction-policy projection proof failed.");

const firstBatch = interactionBatch(handle, opened.body, "telemetry-a", [
  event(1, "presented", 0),
  event(2, "visible", 0),
  event(3, "focus", 0),
  event(4, "interaction", 1_000),
  event(5, "heartbeat", 10_000),
  event(6, "hidden", 15_000),
  event(7, "visible", 18_000),
  event(8, "heartbeat", 25_000),
  event(9, "disconnect", 30_000),
]);
await expectCall(intruder, "POST", "/v1/participant/interaction-events", firstBatch, 404, "wrong-participant interaction denial");
await expectCall(participant, "POST", "/v1/participant/interaction-events", {
  ...firstBatch,
  unexpected: "forbidden",
}, 400, "arbitrary interaction-field denial");

const accepted = await call(participant, "POST", "/v1/participant/interaction-events", firstBatch);
expectStatus(accepted, 200, "generalized activity interaction batch");
if (
  accepted.body.accepted !== 9 || accepted.body.duplicate ||
  accepted.body.summary.events.count !== 9 ||
  accepted.body.summary.sessions.count !== 1 ||
  accepted.body.summary.timing.openMilliseconds !== 30_000 ||
  accepted.body.summary.timing.foregroundVisibleMilliseconds !== 27_000 ||
  accepted.body.summary.timing.engagedMilliseconds !== 26_000 ||
  accepted.body.summary.timing.backgroundOrHiddenMilliseconds !== 3_000 ||
  accepted.body.summary.confidence.level !== "medium"
) throw new Error("The deterministic activity-interaction duration proof failed.");

const duplicate = await call(participant, "POST", "/v1/participant/interaction-events", firstBatch);
expectStatus(duplicate, 200, "interaction batch idempotency");
if (!duplicate.body.duplicate || duplicate.body.accepted !== 0) {
  throw new Error("The interaction batch idempotency proof failed.");
}
await expectCall(participant, "POST", "/v1/participant/interaction-events", {
  ...firstBatch,
  events: [...firstBatch.events.slice(0, -1), event(9, "disconnect", 29_000)],
}, 409, "changed interaction batch replay denial");
await expectCall(participant, "POST", "/v1/participant/interaction-events", interactionBatch(
  handle,
  opened.body,
  "telemetry-a",
  [event(9, "heartbeat", 31_000)],
), 409, "interaction sequence replay denial");

const resumed = await call(participant, "POST", "/v1/participant/interaction-events", interactionBatch(
  handle,
  opened.body,
  "telemetry-b",
  [event(1, "presented", 0), event(2, "visible", 0), event(3, "disconnect", 5_000)],
));
expectStatus(resumed, 200, "resumed activity interaction batch");
if (resumed.body.revision !== 2 || resumed.body.summary.events.count !== 12 ||
    resumed.body.summary.sessions.count !== 2) {
  throw new Error("The cross-session interaction summary-revision proof failed.");
}

const completed = await call(participant, "POST", "/v1/participant/respond", {
  activityId: opened.body.activityId,
  clientContext: {
    clientStartedAt: new Date().toISOString(),
    clientSubmittedAt: new Date().toISOString(),
    timezone: "Etc/UTC",
  },
  commandId: randomUUID(),
  handle,
  interactionId: opened.body.interaction.id,
  response: "acknowledged",
});
expectStatus(completed, 200, "interaction-qualified activity completion");
if (!completed.body.integrity?.verified) throw new Error("The activity-interaction seal proof failed.");

const record = await call(owner, "POST", "/v1/owner/records", {
  assignmentId: issued.body.assignmentId,
  tenantId: tenant.body.id,
});
expectStatus(record, 200, "interaction owner record");
const evidence = record.body.manifest.activityInteraction;
if (
  record.body.manifest.schema !== "vasi-evidence-manifest/v5" ||
  evidence.batches.length !== 2 || evidence.events.length !== 12 || evidence.summaries.length !== 2 ||
  evidence.summaries.at(-1).summary.events.count !== evidence.events.length ||
  !record.body.events.some((entry) => entry.eventData?.eventType === "activity.interaction.recorded") ||
  !verifyEvidenceRecord(record.body)
) throw new Error("The sealed generalized activity-interaction evidence proof failed.");

const tampered = structuredClone(record.body);
tampered.manifest.activityInteraction.events[3].event.monotonicMs = 29_000;
let tamperRejected = false;
try {
  verifyEvidenceRecord(tampered);
} catch {
  tamperRejected = true;
}
if (!tamperRejected) throw new Error("The offline activity-interaction recalculation proof failed.");

console.info("VASI generalized activity presence, privacy bounds, replay, timing, resume, sealing, and verification checks passed.");

function interactionBatch(handleValue, assignment, telemetrySessionId, events) {
  return {
    activityId: assignment.activityId,
    batchId: randomUUID(),
    events,
    handle: handleValue,
    interactionId: assignment.interaction.id,
    telemetrySessionId,
  };
}

function event(sequence, type, monotonicMs) {
  return {
    clientOccurredAt: new Date(Date.now() + sequence).toISOString(),
    id: randomUUID(),
    monotonicMs,
    sequence,
    type,
  };
}

function workflowDocument() {
  return {
    access: { authentication: "verified_email", postCompletion: "receipt_only" },
    activities: [{
      content: {
        acknowledgementLabel: "I acknowledge the activity-presence proof terms.",
        prompt: "Acknowledge the proof terms.",
        terms: "This exact text is used to prove privacy-bounded generalized activity interaction evidence.",
      },
      id: "terms",
      responseMode: "acknowledgement",
      title: "General activity presence",
      type: "terms_response",
    }],
    notifications: { onCompletion: true, onIssue: true, reminderHoursBeforeDue: [] },
    purpose: "Generalized activity interaction conformance proof",
    schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
    schema: "vasi-workflow/v1",
    title: "General activity presence proof",
  };
}

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.41", userAgent: "VASI interaction proof" },
    roles,
    subject: `principal-${id}`,
  };
}

async function expectCall(actorContext, method, path, body, status, label) {
  const result = await call(actorContext, method, path, body);
  expectStatus(result, status, label);
  return result;
}

async function call(actorContext, method, path, body) {
  const token = await createActorAssertion(settings, actorContext);
  return requestEngine(settings, { body, method, path, token });
}

function expectStatus(result, expected, label) {
  if (result.status !== expected) {
    throw new Error(`${label} returned ${result.status}: ${JSON.stringify(result.body)}`);
  }
}
