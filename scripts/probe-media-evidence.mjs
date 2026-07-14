import { randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import { verifyEvidenceRecord } from "../services/engine/evidence-store.mjs";
import { readRuntimeSettings } from "./settings-core.mjs";

const settings = await readRuntimeSettings({ scope: "gateway" });
const now = Math.floor(Date.now() / 1_000);
const owner = actor("media-owner", "media-owner@example.test", ["admin"]);
const participant = actor("media-participant", "media-participant@example.test", ["user"]);
const intruder = actor("media-intruder", "media-intruder@example.test", ["user"]);

const tenant = await call(owner, "POST", "/v1/owner/tenants", {
  name: "VASI Media Evidence Proof",
  slug: `media-${randomUUID()}`,
});
expectStatus(tenant, 200, "media tenant creation");

const playbackWorkflow = await createAndPublish("Instrumented playback proof", playbackDocument());
const playbackIssue = await issue(playbackWorkflow.revisionId);
const playbackHandle = playbackIssue.body.participantPath.split("/").at(-1);
const playbackOpen = await open(playbackHandle, "training");
if (
  playbackOpen.body.content.descriptor.capability !== "instrumented_player" ||
  playbackOpen.body.content.descriptor.provider !== "youtube" ||
  playbackOpen.body.content.descriptor.durationMilliseconds !== 10_000 ||
  !playbackOpen.body.content.descriptor.descriptorHash
) {
  throw new Error("The immutable instrumented-media participant projection proof failed.");
}

await expectCall(intruder, "POST", "/v1/participant/media-open", {
  activityId: "training",
  handle: playbackHandle,
}, 404, "wrong-participant media denial");
const authorized = await call(participant, "POST", "/v1/participant/media-open", {
  activityId: "training",
  handle: playbackHandle,
});
expectStatus(authorized, 200, "participant media authorization");
if (authorized.body.descriptorHash !== playbackOpen.body.content.descriptor.descriptorHash) {
  throw new Error("The media-open descriptor binding proof failed.");
}

await expectCall(participant, "POST", "/v1/participant/respond", responseCommand(
  playbackHandle,
  playbackOpen.body,
  { method: "playback" },
), 409, "playback threshold gate before telemetry");

const firstBatch = mediaBatch(playbackHandle, playbackOpen.body, "telemetry-a", [
  event(1, "presented", 0),
  event(2, "visible", 1),
  event(3, "focus", 2),
  event(4, "interaction", 3),
  event(5, "ready", 4, { durationSeconds: 10, positionSeconds: 0 }),
  event(6, "play", 5, { durationSeconds: 10, playbackRate: 1, positionSeconds: 0 }),
  event(7, "position", 1_000, { durationSeconds: 10, playbackRate: 1, positionSeconds: 0 }),
  event(8, "position", 3_000, { durationSeconds: 10, playbackRate: 1, positionSeconds: 2 }),
  event(9, "seek", 3_100, { fromSeconds: 2, toSeconds: 8 }),
  event(10, "position", 3_200, { durationSeconds: 10, playbackRate: 1, positionSeconds: 8 }),
  event(11, "position", 5_200, { durationSeconds: 10, playbackRate: 1, positionSeconds: 10 }),
  event(12, "ended", 5_300, { durationSeconds: 10, playbackRate: 1, positionSeconds: 10 }),
]);
const firstAccepted = await call(participant, "POST", "/v1/participant/media-events", firstBatch);
expectStatus(firstAccepted, 200, "instrumented media telemetry");
if (
  firstAccepted.body.summary.playback.uniqueMilliseconds !== 4_000 ||
  firstAccepted.body.summary.playback.percentBasisPoints !== 4_000 ||
  firstAccepted.body.summary.playback.completionMet !== false ||
  firstAccepted.body.summary.playback.seekCount !== 1
) {
  throw new Error("The seek-resistant playback calculation proof failed.");
}

const duplicate = await call(participant, "POST", "/v1/participant/media-events", firstBatch);
expectStatus(duplicate, 200, "media batch idempotency");
if (!duplicate.body.duplicate || duplicate.body.accepted !== 0) {
  throw new Error("The media batch idempotency proof failed.");
}
await expectCall(participant, "POST", "/v1/participant/media-events", {
  ...firstBatch,
  events: [...firstBatch.events.slice(0, -1), event(12, "pause", 5_300, { positionSeconds: 9 })],
}, 409, "changed media batch replay denial");
await expectCall(participant, "POST", "/v1/participant/media-events", mediaBatch(
  playbackHandle,
  playbackOpen.body,
  "telemetry-a",
  [event(12, "position", 5_400, { durationSeconds: 10, positionSeconds: 10 })],
), 409, "media sequence replay denial");

await expectCall(participant, "POST", "/v1/participant/respond", responseCommand(
  playbackHandle,
  playbackOpen.body,
  { method: "playback" },
), 409, "playback threshold gate after insufficient telemetry");

const resume = await call(participant, "POST", "/v1/participant/media-events", mediaBatch(
  playbackHandle,
  playbackOpen.body,
  "telemetry-b",
  [
    event(1, "presented", 0),
    event(2, "visible", 1),
    event(3, "focus", 2),
    event(4, "interaction", 3),
    event(5, "play", 4, { durationSeconds: 10, playbackRate: 1, positionSeconds: 0 }),
    event(6, "position", 1_000, { durationSeconds: 10, playbackRate: 1, positionSeconds: 0 }),
    event(7, "position", 4_000, { durationSeconds: 10, playbackRate: 1, positionSeconds: 3 }),
    event(8, "pause", 4_100, { durationSeconds: 10, playbackRate: 1, positionSeconds: 3 }),
  ],
));
expectStatus(resume, 200, "resumed media telemetry");
if (
  !resume.body.summary.playback.completionMet ||
  resume.body.summary.playback.uniqueMilliseconds !== 5_000 ||
  resume.body.summary.sessionCount !== 2
) {
  throw new Error("The cross-session unique-playback completion proof failed.");
}

const playbackCompleted = await call(participant, "POST", "/v1/participant/respond", responseCommand(
  playbackHandle,
  playbackOpen.body,
  { method: "playback" },
));
expectStatus(playbackCompleted, 200, "playback-qualified completion");
if (!playbackCompleted.body.integrity?.verified) {
  throw new Error("The playback-qualified seal proof failed.");
}

const playbackRecord = await record(playbackIssue.body.assignmentId);
const media = playbackRecord.body.manifest.media;
const outcome = playbackRecord.body.manifest.outcome.activities[0];
if (
  playbackRecord.body.manifest.schema !== "vasi-evidence-manifest/v6" ||
  media.descriptors.length !== 1 || media.events.length !== 20 || media.summaries.length !== 2 ||
  !media.snapshots.some((entry) => entry.phase === "publish") ||
  !media.snapshots.some((entry) => entry.phase === "issue") ||
  !media.snapshots.some((entry) => entry.phase === "participant_start") ||
  !media.snapshots.some((entry) => entry.phase === "completion") ||
  outcome.result.mediaSummary.playback.uniqueMilliseconds !== 5_000 ||
  outcome.result.mediaSummaryHash !== media.summaries.at(-1).summaryHash ||
  !verifyEvidenceRecord(playbackRecord.body)
) {
  throw new Error("The sealed raw-media evidence and summary-revision proof failed.");
}

const genericWorkflow = await createAndPublish("Generic frame proof", genericDocument());
const genericIssue = await issue(genericWorkflow.revisionId);
const genericHandle = genericIssue.body.participantPath.split("/").at(-1);
const genericOpen = await open(genericHandle, "drive_preview");
if (genericOpen.body.content.descriptor.capability !== "generic_embed") {
  throw new Error("The generic-provider capability downgrade proof failed.");
}
await expectCall(participant, "POST", "/v1/participant/media-events", mediaBatch(
  genericHandle,
  genericOpen.body,
  "generic-a",
  [event(1, "play", 1)],
), 400, "generic playback-event denial");
const frameEvidence = await call(participant, "POST", "/v1/participant/media-events", mediaBatch(
  genericHandle,
  genericOpen.body,
  "generic-a",
  [
    event(1, "presented", 0),
    event(2, "frame_loaded", 1),
    event(3, "visible", 2),
    event(4, "focus", 3),
    event(5, "interaction", 4),
    event(6, "heartbeat", 2_000),
  ],
));
expectStatus(frameEvidence, 200, "generic frame evidence");
if (
  frameEvidence.body.summary.confidence.level !== "none" ||
  frameEvidence.body.summary.playback.uniqueMilliseconds !== 0 ||
  frameEvidence.body.summary.playback.completionMet
) {
  throw new Error("The generic frame non-playback claim proof failed.");
}
const genericCompleted = await call(participant, "POST", "/v1/participant/respond", responseCommand(
  genericHandle,
  genericOpen.body,
  { acknowledged: true, method: "acknowledgement" },
));
expectStatus(genericCompleted, 200, "generic acknowledgement completion");
if (!genericCompleted.body.integrity?.verified) throw new Error("The generic-media seal proof failed.");
const genericRecord = await record(genericIssue.body.assignmentId);
if (
  genericRecord.body.manifest.media.events.some((entry) => ["play", "position", "ended"].includes(entry.type)) ||
  !genericRecord.body.manifest.media.summaries[0].summary.confidence.limitations.some((value) => value.includes("does not provide validated playback")) ||
  !verifyEvidenceRecord(genericRecord.body)
) {
  throw new Error("The generic-media limitation and sealed-record proof failed.");
}

console.info("VASI media descriptor, authorization, telemetry, duration, downgrade, resume, and sealed-evidence checks passed.");

async function createAndPublish(name, document) {
  const created = await call(owner, "POST", "/v1/owner/workflows", {
    document,
    name,
    tenantId: tenant.body.id,
  });
  expectStatus(created, 200, `${name} creation`);
  const publication = await call(owner, "POST", "/v1/owner/workflow-publications", {
    definitionId: created.body.definitionId,
    expectedDraftVersion: created.body.draftVersion,
    tenantId: tenant.body.id,
  });
  expectStatus(publication, 200, `${name} publication`);
  if (publication.body.snapshotHash === created.body.documentHash) {
    throw new Error(`${name} did not bind a normalized immutable media descriptor.`);
  }
  return publication.body;
}

function issue(workflowRevisionId) {
  return call(owner, "POST", "/v1/owner/requests", {
    intendedEmail: participant.email,
    tenantId: tenant.body.id,
    workflowRevisionId,
  });
}

async function open(handle, expectedActivityId) {
  const result = await call(participant, "POST", "/v1/participant/open", { handle });
  expectStatus(result, 200, `open ${expectedActivityId}`);
  if (result.body.activityId !== expectedActivityId) throw new Error(`Expected activity ${expectedActivityId}.`);
  return result;
}

function record(assignmentId) {
  return call(owner, "POST", "/v1/owner/records", { assignmentId, tenantId: tenant.body.id });
}

function responseCommand(handle, assignment, response) {
  return {
    activityId: assignment.activityId,
    clientContext: {
      clientStartedAt: new Date().toISOString(),
      clientSubmittedAt: new Date().toISOString(),
      timezone: "Etc/UTC",
    },
    commandId: randomUUID(),
    handle,
    interactionId: assignment.interaction.id,
    response,
  };
}

function mediaBatch(handle, assignment, telemetrySessionId, events) {
  return {
    activityId: assignment.activityId,
    batchId: randomUUID(),
    events,
    handle,
    interactionId: assignment.interaction.id,
    telemetrySessionId,
  };
}

function event(sequence, type, monotonicMs, fields = {}) {
  return { ...fields, id: randomUUID(), monotonicMs, sequence, type };
}

function playbackDocument() {
  return workflowDocument({
    content: {
      completionPolicy: { minimumUniqueSeconds: 5, mode: "playback", thresholdPercent: 50 },
      descriptor: {
        accessMode: "public",
        durationSeconds: 10,
        kind: "video",
        provider: "youtube",
        sourceUrl: "https://youtu.be/M7lc1UVf-VE",
        title: "Provider training",
        version: { id: "youtube-item-M7lc1UVf-VE" },
      },
      prompt: "Watch at least half of the provider training.",
      telemetryPolicy: { heartbeatSeconds: 2, idleSeconds: 10, maxCreditedGapSeconds: 5 },
    },
    id: "training",
    responseMode: "external_media",
    title: "Instrumented training",
    type: "external_media",
  });
}

function genericDocument() {
  return workflowDocument({
    content: {
      acknowledgementLabel: "I confirm that I reviewed the Drive-hosted training.",
      completionPolicy: { minimumUniqueSeconds: 1, mode: "acknowledgement", thresholdPercent: 90 },
      descriptor: {
        accessMode: "provider_shared",
        itemId: "1AbCdEfGhIjKlMnOp",
        kind: "video",
        provider: "google_drive",
        sourceUrl: "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view",
        title: "Drive-hosted training",
      },
      prompt: "Review the provider-hosted training and acknowledge it.",
      telemetryPolicy: { heartbeatSeconds: 2, idleSeconds: 10, maxCreditedGapSeconds: 5 },
    },
    id: "drive_preview",
    responseMode: "external_media",
    title: "Generic provider preview",
    type: "external_media",
  });
}

function workflowDocument(activity) {
  return {
    access: { authentication: "verified_email", postCompletion: "content_until_expiration" },
    activities: [activity],
    notifications: { onCompletion: true, onIssue: true, reminderHoursBeforeDue: [] },
    purpose: "Provider-hosted media evidence conformance proof",
    schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
    schema: "vasi-workflow/v1",
    title: activity.title,
  };
}

function actor(id, email, roles) {
  return {
    authenticatedAt: now - 30,
    authentication: { method: "integration-proof", provider: "vsign" },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: { ipAddress: "192.0.2.40", userAgent: "VASI media proof" },
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
