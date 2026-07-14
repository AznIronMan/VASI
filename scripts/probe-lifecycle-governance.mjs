import { createHash, randomUUID } from "node:crypto";

import { createActorAssertion, requestEngine } from "../packages/engine-client/index.mjs";
import {
  hashCanonicalJSON,
  verifyCertificateSeal,
  verifyDetachedIntegritySeal,
} from "../packages/engine-crypto/index.mjs";
import { DATA_EXPORT_PROFILE } from "../packages/engine-domain/lifecycle.mjs";
import { createSigningProvider } from "../services/engine/signing-provider.mjs";
import {
  advanceOneRetentionLifecycle,
  expireOneParticipantDataRequest,
} from "../services/worker/retention-worker.mjs";
import {
  createSettingsPool,
  readRuntimeSettings,
} from "./settings-core.mjs";

const gatewaySettings = await readRuntimeSettings({ scope: "gateway" });
const engineSettings = await readRuntimeSettings({ scope: "engine" });
const database = createSettingsPool();
const signingProvider = createSigningProvider(engineSettings);
const issuedAt = Math.floor(Date.now() / 1_000);
const owner = actor("lifecycle-owner", "lifecycle-owner@example.test", ["admin"]);
const participant = actor("lifecycle-participant", "lifecycle-participant@example.test", ["user"]);
const outsider = actor("lifecycle-outsider", "lifecycle-outsider@example.test", ["user"]);
const verifier = actor("lifecycle-verifier", undefined, ["verification"]);

try {
  await proveHoldSafeRetentionPurge();
  await proveReviewedParticipantDataExport();
  await proveExpiredExportCleanup();
  console.info(
    "VASI lifecycle policy, legal hold, sealed purge, participant history, reviewed data export, expiry, and immutability checks passed.",
  );
} finally {
  await database.end();
}

async function proveHoldSafeRetentionPurge() {
  const tenant = await createTenant("VASI Retention Proof", "retention");
  const destructivePolicy = {
    contentAccess: { daysAfterTerminal: 1, mode: "days_after_terminal" },
    evidence: { archiveAfterDays: 1, deleteAfterDays: 1 },
    participantHistory: { daysAfterTerminal: null },
    schema: "vasi-retention-policy/v1",
  };
  const policy = await call(owner, "POST", "/v1/owner/retention-policies", {
    expectedRevision: 0,
    name: "tenant_default",
    policy: destructivePolicy,
    tenantId: tenant.id,
  });
  expectStatus(policy, 200, "retention policy creation");
  const conflict = await call(owner, "POST", "/v1/owner/retention-policies", {
    expectedRevision: 0,
    name: "tenant_default",
    policy: destructivePolicy,
    tenantId: tenant.id,
  });
  expectStatus(conflict, 409, "retention policy optimistic concurrency");

  const completed = await issueAndCompleteWorkflow(tenant.id, participant, "Retention purge proof");
  await expectImmutableFailure(
    `update "vasi_engine"."participant_context_snapshot"
     set "purpose" = 'save' where "id" = $1`,
    [completed.contextSnapshotIds[0]],
  );
  const policyReplacement = await call(owner, "POST", "/v1/owner/retention-policies", {
    expectedRevision: 1,
    name: "tenant_default",
    policy: {
      contentAccess: { mode: "indefinite" },
      evidence: { archiveAfterDays: null, deleteAfterDays: null },
      participantHistory: { daysAfterTerminal: null },
      schema: "vasi-retention-policy/v1",
    },
    tenantId: tenant.id,
  });
  expectStatus(policyReplacement, 200, "retention policy revision");

  const records = await call(owner, "POST", "/v1/owner/lifecycle-record-list", {
    tenantId: tenant.id,
  });
  expectStatus(records, 200, "lifecycle record list");
  const record = records.body.find((entry) => entry.assignmentId === completed.assignmentId);
  if (!record || record.policyHash !== policy.body.policyHash || record.policyRevisionId !== policy.body.id) {
    throw new Error("The issued record did not retain its immutable policy snapshot.");
  }

  const holdCommandId = randomUUID();
  const holdPayload = {
    action: "place",
    assignmentId: completed.assignmentId,
    caseReference: "INTEGRATION-MATTER-1",
    commandId: holdCommandId,
    reason: "Prove that an active legal hold blocks a retention purge.",
    tenantId: tenant.id,
  };
  const hold = await call(owner, "POST", "/v1/owner/legal-holds", holdPayload);
  expectStatus(hold, 200, "legal hold placement");
  const replay = await call(owner, "POST", "/v1/owner/legal-holds", holdPayload);
  expectStatus(replay, 200, "legal hold command replay");
  if (replay.body.id !== hold.body.id) throw new Error("The legal hold command was not idempotent.");

  const past = new Date(Date.now() - 60_000);
  await database.query(
    `update "vasi_engine"."record_lifecycle_state"
     set "contentExpiresAt" = $2, "archiveAt" = $2, "deleteAt" = $2,
         "lastEvaluatedAt" = null, "updatedAt" = $3
     where "assignmentId" = $1`,
    [completed.assignmentId, past, new Date()],
  );
  const actions = [];
  for (let attempt = 0; attempt < 5 && !actions.includes("purge.blocked"); attempt += 1) {
    const result = await advanceOneRetentionLifecycle(database, signingProvider, new Date());
    if (result?.assignmentId === completed.assignmentId) actions.push(result.action);
  }
  if (!actions.includes("purge.blocked")) {
    const latest = await database.query(
      `select "eventType" from "vasi_engine"."record_lifecycle_event"
       where "assignmentId" = $1 order by "sequence"`,
      [completed.assignmentId],
    );
    actions.push(...latest.rows.map((entry) => entry.eventType));
  }
  if (!actions.includes("purge.blocked")) throw new Error("The legal hold did not block retention purge.");

  const known = await call(verifier, "POST", "/v1/public/verification", {
    fingerprint: completed.manifestHash,
  });
  expectStatus(known, 200, "pre-purge public verification");
  if (!known.body.known || !known.body.verified || known.body.retired) {
    throw new Error("The live manifest did not verify before retention purge.");
  }

  const report = await call(participant, "POST", "/v1/participant/reports", {
    assignmentId: completed.assignmentId,
    format: "json",
  });
  expectStatus(report, 200, "participant history report before purge");

  const release = await call(owner, "POST", "/v1/owner/legal-holds", {
    action: "release",
    commandId: randomUUID(),
    holdId: hold.body.id,
    reason: "The integration hold has served its purpose.",
    tenantId: tenant.id,
  });
  expectStatus(release, 200, "legal hold release");
  await database.query(
    `update "vasi_engine"."record_lifecycle_state"
     set "lastEvaluatedAt" = null where "assignmentId" = $1`,
    [completed.assignmentId],
  );
  let purged;
  for (let attempt = 0; attempt < 5 && !purged; attempt += 1) {
    const result = await advanceOneRetentionLifecycle(database, signingProvider, new Date());
    if (result?.assignmentId === completed.assignmentId && result.action === "record.purged") purged = result;
  }
  const tombstoneResult = await database.query(
    `select * from "vasi_engine"."retention_purge_tombstone" where "assignmentId" = $1`,
    [completed.assignmentId],
  );
  if (!tombstoneResult.rowCount) throw new Error("Retention purge did not preserve a sealed tombstone.");
  const tombstone = tombstoneResult.rows[0];
  if (hashCanonicalJSON(tombstone.tombstone) !== tombstone.tombstoneHash) {
    throw new Error("The retention tombstone hash is invalid.");
  }
  if (!tombstone.seal.every((seal) => verifyLifecycleSeal(
    tombstone.tombstone,
    seal,
    "vasi-retention-tombstone/v1",
  ))) throw new Error("The retention tombstone seal is invalid.");

  await assertHashChain("record_lifecycle_event", "assignmentId", completed.assignmentId);
  const sourceRows = await database.query(
    `select
       (select count(*) from "vasi_engine"."participant_assignment" where "id" = $1) as "assignments",
       (select count(*) from "vasi_engine"."evidence_event" where "assignmentId" = $1) as "events",
       (select count(*) from "vasi_engine"."activity_instance" where "assignmentId" = $1) as "activities",
       (select count(*) from "vasi_engine"."activity_response_revision" where "assignmentId" = $1) as "responses",
       (select count(*) from "vasi_engine"."activity_interaction_event" where "assignmentId" = $1) as "interactionEvents",
       (select count(*) from "vasi_engine"."activity_interaction_summary_revision" where "assignmentId" = $1) as "interactionSummaries",
       (select count(*) from "vasi_engine"."participant_context_snapshot" where "assignmentId" = $1) as "contextSnapshots",
       (select count(*) from "vasi_engine"."record_lifecycle_event" where "assignmentId" = $1) as "lifecycleEvents"`,
    [completed.assignmentId],
  );
  if (
    Number(sourceRows.rows[0].assignments) || Number(sourceRows.rows[0].events) ||
    Number(sourceRows.rows[0].activities) || Number(sourceRows.rows[0].responses) ||
    Number(sourceRows.rows[0].interactionEvents) || Number(sourceRows.rows[0].interactionSummaries) ||
    Number(sourceRows.rows[0].contextSnapshots) ||
    Number(sourceRows.rows[0].lifecycleEvents) < 5
  ) {
    throw new Error("Retention purge did not remove source rows while preserving its lifecycle audit.");
  }
  await expectImmutableFailure(
    `update "vasi_engine"."record_lifecycle_event" set "eventType" = 'policy.bound' where "assignmentId" = $1`,
    [completed.assignmentId],
  );
  await expectGuardedDeleteFailure(
    "vasi_engine.retention_purge_assignment",
    completed.assignmentId,
    `delete from "vasi_engine"."legal_hold" where "assignmentId" = $1`,
    [completed.assignmentId],
  );

  const retired = await call(verifier, "POST", "/v1/public/verification", {
    fingerprint: completed.manifestHash,
  });
  expectStatus(retired, 200, "post-purge public verification");
  if (!retired.body.known || !retired.body.retired || !retired.body.verified) {
    throw new Error("The retired manifest did not verify through its sealed tombstone.");
  }
  const removedReport = await call(participant, "POST", "/v1/participant/reports", {
    assignmentId: completed.assignmentId,
    format: "json",
  });
  expectStatus(removedReport, 404, "purged participant report");
  void purged;
}

async function proveReviewedParticipantDataExport() {
  const tenant = await createTenant("VASI Participant Data Proof", "participant-data");
  const completed = await issueAndCompleteWorkflow(tenant.id, participant, "Participant data export proof");
  const history = await call(participant, "GET", "/v1/participant/history");
  expectStatus(history, 200, "participant history");
  if (!history.body.some((entry) => entry.assignmentId === completed.assignmentId)) {
    throw new Error("The participant history did not include the completed record.");
  }

  const requested = await call(participant, "POST", "/v1/participant/data-requests", {
    commandId: randomUUID(),
  });
  expectStatus(requested, 200, "participant data request");
  if (requested.body.status !== "pending_review") throw new Error("The participant data request skipped review.");
  const pendingExport = await call(participant, "POST", "/v1/participant/data-exports", {
    requestId: requested.body.id,
  });
  expectStatus(pendingExport, 409, "unreviewed participant data export");

  const reviews = await call(owner, "POST", "/v1/owner/data-request-review-list", {
    tenantId: tenant.id,
  });
  expectStatus(reviews, 200, "data request review list");
  if (!reviews.body.some((entry) => entry.requestId === requested.body.id)) {
    throw new Error("The participant data request was unavailable to its tenant reviewer.");
  }
  const approved = await call(owner, "POST", "/v1/owner/data-request-reviews", {
    commandId: randomUUID(),
    decision: "approve",
    includeTechnicalTelemetry: true,
    reason: "Approved by the automated privacy conformance review.",
    requestId: requested.body.id,
    tenantId: tenant.id,
  });
  expectStatus(approved, 200, "participant data request approval");

  const opened = await call(participant, "POST", "/v1/participant/data-exports", {
    requestId: requested.body.id,
  });
  expectStatus(opened, 200, "participant data export open");
  const bytes = await readParticipantDataExport(participant, requested.body.id, opened.body);
  const payload = JSON.parse(bytes.toString("utf8"));
  if (
    payload.profile !== DATA_EXPORT_PROFILE ||
    payload.request.requester.email !== participant.email ||
    !payload.scopes.some((scope) => scope.records.some(
      (entry) => entry.assignment.id === completed.assignmentId && entry.events.length > 0 &&
        entry.activityInteractionEvidence.telemetryIncluded &&
        entry.activityInteractionEvidence.batches.length > 0 &&
        entry.activityInteractionEvidence.events.length > 0 &&
        entry.activityInteractionEvidence.summaries.length > 0 &&
        entry.participantContextEvidence.telemetryIncluded &&
        entry.participantContextEvidence.policy.version === "vasi-participant-context-policy/v1" &&
        entry.participantContextEvidence.snapshots.length > 0 &&
        entry.participantContextEvidence.snapshots.every((context) =>
          context.context.provenance.reliabilityClass === "browser_reported"
        ),
    ))
  ) throw new Error("The reviewed participant data export omitted expected participant data.");
  const serialized = bytes.toString("utf8");
  if (serialized.includes('"answerKey"') ||
      serialized.includes("Exact retention proof terms.") ||
      serialized.includes('"notificationPolicy"')) {
    throw new Error("The participant data export exposed internal workflow content.");
  }
  if (!opened.body.seal.every((seal) => verifyLifecycleSeal(payload, seal, DATA_EXPORT_PROFILE))) {
    throw new Error("The participant data export seal is invalid.");
  }
  const denied = await call(outsider, "POST", "/v1/participant/data-exports", {
    requestId: requested.body.id,
  });
  expectStatus(denied, 404, "participant data export isolation");
  await assertHashChain("participant_data_request_event", "requestId", requested.body.id);
  await expectImmutableFailure(
    `update "vasi_engine"."participant_data_export" set "filename" = 'changed.json' where "id" = $1`,
    [opened.body.id],
  );
  await expectGuardedDeleteFailure(
    "vasi_engine.participant_data_export_purge",
    opened.body.id,
    `delete from "vasi_engine"."participant_data_export_chunk" where "exportId" = $1`,
    [opened.body.id],
  );
}

async function proveExpiredExportCleanup() {
  const requestId = randomUUID();
  const exportId = randomUUID();
  const bytes = Buffer.from("{}", "utf8");
  const now = new Date();
  const createdAt = new Date(now.getTime() - 172_800_000);
  const expiresAt = new Date(now.getTime() - 86_400_000);
  const client = await database.connect();
  try {
    await client.query("begin");
    await client.query(
      `insert into "vasi_engine"."participant_data_request"
        ("id", "requesterPrincipalId", "requesterEmail", "status", "commandId",
         "requestedAt", "reviewCompletedAt", "expiresAt", "updatedAt")
       values ($1, $2, $3, 'ready', $4, $5, $5, $6, $5)`,
      [requestId, participant.principalId, participant.email, randomUUID(), createdAt, expiresAt],
    );
    await client.query(
      `insert into "vasi_engine"."participant_data_request_chain_head"
        ("requestId", "lastSequence", "lastHash") values ($1, 0, $2)`,
      [requestId, "0".repeat(64)],
    );
    await client.query(
      `insert into "vasi_engine"."participant_data_export"
        ("id", "requestId", "profile", "mediaType", "filename", "byteLength", "chunkCount",
         "sha256", "payloadHash", "seal", "createdAt", "expiresAt")
       values ($1, $2, $3, 'application/json', 'expired.json', $4, 1, $5, $6, '[]'::jsonb, $7, $8)`,
      [exportId, requestId, DATA_EXPORT_PROFILE, bytes.length, sha256(bytes), hashCanonicalJSON({}), createdAt, expiresAt],
    );
    await client.query(
      `insert into "vasi_engine"."participant_data_export_chunk"
        ("exportId", "sequence", "byteLength", "sha256", "bytes") values ($1, 0, $2, $3, $4)`,
      [exportId, bytes.length, sha256(bytes), bytes],
    );
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  const result = await expireOneParticipantDataRequest(database, now);
  if (result?.requestId !== requestId || result.action !== "export.expired") {
    throw new Error("The retention worker did not expire the due participant data export.");
  }
  const expired = await database.query(
    `select e."contentDeletedAt", r."status",
            (select count(*) from "vasi_engine"."participant_data_export_chunk" c where c."exportId" = e."id") as "chunks"
     from "vasi_engine"."participant_data_export" e
     join "vasi_engine"."participant_data_request" r on r."id" = e."requestId"
     where e."id" = $1`,
    [exportId],
  );
  if (!expired.rows[0]?.contentDeletedAt || expired.rows[0].status !== "expired" || Number(expired.rows[0].chunks)) {
    throw new Error("Expired export content was not removed while retaining its metadata.");
  }
  await assertHashChain("participant_data_request_event", "requestId", requestId);
}

async function issueAndCompleteWorkflow(tenantId, participantActor, title) {
  const created = await call(owner, "POST", "/v1/owner/workflows", {
    document: {
      access: { authentication: "verified_email", postCompletion: "receipt_only" },
      activities: [
        {
          content: { prompt: "Do you approve the retention proof?", terms: "Exact retention proof terms." },
          id: "retention_decision",
          responseMode: "yes_no",
          title: "Retention decision",
          type: "terms_response",
        },
        {
          content: { prompt: "Acknowledge completion.", terms: "Exact completion acknowledgement." },
          id: "retention_acknowledgement",
          responseMode: "acknowledgement",
          title: "Completion acknowledgement",
          type: "terms_response",
        },
      ],
      notifications: { onCompletion: true, onIssue: true, reminderHoursBeforeDue: [] },
      purpose: "Lifecycle and controlled purge conformance",
      retention: { profile: "tenant_default" },
      schedule: { defaultDueDays: 7, defaultExpirationDays: 14 },
      schema: "vasi-workflow/v1",
      title,
    },
    name: `Retention workflow ${randomUUID()}`,
    tenantId,
  });
  expectStatus(created, 200, `${title} workflow creation`);
  const published = await call(owner, "POST", "/v1/owner/workflow-publications", {
    definitionId: created.body.definitionId,
    expectedDraftVersion: created.body.draftVersion,
    tenantId,
  });
  expectStatus(published, 200, `${title} workflow publication`);
  const issued = await call(owner, "POST", "/v1/owner/requests", {
    intendedEmail: participantActor.email,
    tenantId,
    workflowRevisionId: published.body.revisionId,
  });
  expectStatus(issued, 200, `${title} issue`);
  const handle = issued.body.participantPath.split("/").at(-1);
  let opened = await call(participantActor, "POST", "/v1/participant/open", { handle });
  expectStatus(opened, 200, `${title} first activity open`);
  await recordActivityInteraction(participantActor, handle, opened.body, `${title} first activity`);
  const contextSnapshotIds = [];
  contextSnapshotIds.push(...await recordParticipantContext(
    participantActor,
    handle,
    opened.body,
    `${title} first activity`,
  ));
  const first = await call(participantActor, "POST", "/v1/participant/respond", {
    commandId: randomUUID(),
    handle,
    interactionId: opened.body.interaction.id,
    response: "yes",
  });
  expectStatus(first, 200, `${title} first activity completion`);
  opened = await call(participantActor, "POST", "/v1/participant/open", { handle });
  expectStatus(opened, 200, `${title} second activity open`);
  await recordActivityInteraction(participantActor, handle, opened.body, `${title} second activity`);
  contextSnapshotIds.push(...await recordParticipantContext(
    participantActor,
    handle,
    opened.body,
    `${title} second activity`,
  ));
  const completed = await call(participantActor, "POST", "/v1/participant/respond", {
    commandId: randomUUID(),
    handle,
    interactionId: opened.body.interaction.id,
    response: "acknowledged",
  });
  expectStatus(completed, 200, `${title} workflow completion`);
  return {
    assignmentId: issued.body.assignmentId,
    contextSnapshotIds,
    manifestHash: completed.body.integrity.manifestHash,
  };
}

async function recordParticipantContext(participantActor, handle, assignment, label) {
  const contextSessionId = randomUUID();
  const snapshots = [
    participantContextSnapshot(1, "presentation", 0),
    participantContextSnapshot(2, "submission", 12_000),
  ];
  const first = {
    activityId: assignment.activityId,
    contextSessionId,
    handle,
    interactionId: assignment.interaction.id,
    snapshot: snapshots[0],
  };
  expectStatus(
    await call(outsider, "POST", "/v1/participant/context-snapshots", first),
    404,
    `${label} cross-participant context denial`,
  );
  for (const snapshot of snapshots) {
    const result = await call(participantActor, "POST", "/v1/participant/context-snapshots", {
      ...first,
      snapshot,
    });
    expectStatus(result, 200, `${label} participant context ${snapshot.purpose}`);
    if (!result.body.accepted || result.body.duplicate || result.body.snapshotId !== snapshot.id) {
      throw new Error(`${label} participant context acceptance failed.`);
    }
  }
  return snapshots.map((snapshot) => snapshot.id);
}

function participantContextSnapshot(sequence, purpose, monotonicMs) {
  return {
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
    clientOccurredAt: new Date(Date.now() + sequence).toISOString(),
    connection: { effectiveType: "4g", rttMs: 45, saveData: false },
    display: {
      colorDepth: 24,
      devicePixelRatio: 2,
      screenHeight: 1080,
      screenWidth: 1920,
      viewportHeight: 900,
      viewportWidth: 1440,
    },
    id: randomUUID(),
    input: { maxTouchPoints: 0 },
    monotonicMs,
    preferences: {
      colorScheme: "dark",
      contrast: "no-preference",
      forcedColors: false,
      reducedMotion: true,
    },
    purpose,
    schema: "vasi-participant-context/v1",
    sequence,
  };
}

async function recordActivityInteraction(participantActor, handle, assignment, label) {
  const telemetrySessionId = randomUUID();
  const batch = {
    activityId: assignment.activityId,
    batchId: randomUUID(),
    events: [
      interactionEvent(1, "presented", 0),
      interactionEvent(2, "visible", 0),
      interactionEvent(3, "focus", 0),
      interactionEvent(4, "interaction", 1_000),
      interactionEvent(5, "heartbeat", 10_000),
      interactionEvent(6, "disconnect", 12_000),
    ],
    handle,
    interactionId: assignment.interaction.id,
    telemetrySessionId,
  };
  const denied = await call(outsider, "POST", "/v1/participant/interaction-events", batch);
  expectStatus(denied, 404, `${label} cross-participant interaction denial`);
  const result = await call(participantActor, "POST", "/v1/participant/interaction-events", batch);
  expectStatus(result, 200, `${label} interaction telemetry`);
  if (
    result.body.accepted !== 6 || result.body.duplicate ||
    result.body.summary.events.count !== 6 ||
    result.body.summary.timing.openMilliseconds !== 12_000 ||
    result.body.summary.timing.foregroundVisibleMilliseconds !== 12_000 ||
    result.body.summary.timing.engagedMilliseconds !== 11_000 ||
    result.body.summary.timing.idleForegroundMilliseconds !== 1_000 ||
    result.body.summary.confidence.level !== "medium"
  ) throw new Error(`${label} deterministic interaction summary failed.`);
  const duplicate = await call(participantActor, "POST", "/v1/participant/interaction-events", batch);
  expectStatus(duplicate, 200, `${label} interaction idempotency`);
  if (!duplicate.body.duplicate || duplicate.body.accepted !== 0) {
    throw new Error(`${label} interaction idempotency failed.`);
  }
  const changed = {
    ...batch,
    events: [
      ...batch.events.slice(0, -1),
      interactionEvent(6, "disconnect", 11_000),
    ],
  };
  expectStatus(
    await call(participantActor, "POST", "/v1/participant/interaction-events", changed),
    409,
    `${label} changed interaction replay denial`,
  );
  expectStatus(
    await call(participantActor, "POST", "/v1/participant/interaction-events", {
      ...batch,
      batchId: randomUUID(),
      events: [interactionEvent(6, "heartbeat", 13_000)],
    }),
    409,
    `${label} interaction sequence replay denial`,
  );
}

function interactionEvent(sequence, type, monotonicMs) {
  return {
    clientOccurredAt: new Date(Date.now() + sequence).toISOString(),
    id: randomUUID(),
    monotonicMs,
    sequence,
    type,
  };
}

async function createTenant(name, prefix) {
  const result = await call(owner, "POST", "/v1/owner/tenants", {
    name,
    slug: `${prefix}-${randomUUID()}`,
  });
  expectStatus(result, 200, `${name} tenant creation`);
  return result.body;
}

async function readParticipantDataExport(actorContext, requestId, metadata) {
  const chunks = [];
  for (let sequence = 0; sequence < metadata.chunkCount; sequence += 1) {
    const result = await call(actorContext, "POST", "/v1/participant/data-export-chunks", {
      exportId: metadata.id,
      requestId,
      sequence,
    });
    expectStatus(result, 200, `participant data export chunk ${sequence}`);
    const bytes = Buffer.from(result.body.data, "base64");
    if (bytes.length !== result.body.byteLength || sha256(bytes) !== result.body.sha256) {
      throw new Error(`Participant data export chunk ${sequence} failed integrity validation.`);
    }
    chunks.push(bytes);
  }
  const bytes = Buffer.concat(chunks);
  if (bytes.length !== metadata.byteLength || sha256(bytes) !== metadata.sha256) {
    throw new Error("The assembled participant data export failed integrity validation.");
  }
  return bytes;
}

async function assertHashChain(table, recordColumn, recordId) {
  const result = await database.query(
    `select "sequence", "eventData", "previousHash", "eventHash"
     from "vasi_engine"."${table}" where "${recordColumn}" = $1 order by "sequence"`,
    [recordId],
  );
  let previousHash = "0".repeat(64);
  for (const [index, row] of result.rows.entries()) {
    if (
      Number(row.sequence) !== index + 1 || row.previousHash !== previousHash ||
      row.eventData.previousHash !== previousHash || hashCanonicalJSON(row.eventData) !== row.eventHash
    ) throw new Error(`${table} failed its hash-chain validation.`);
    previousHash = row.eventHash;
  }
  if (!result.rowCount) throw new Error(`${table} did not retain any audit events.`);
}

async function expectImmutableFailure(statement, values) {
  try {
    await database.query(statement, values);
  } catch (error) {
    if (String(error.message).toLowerCase().includes("immutable")) return;
    throw error;
  }
  throw new Error("An immutable lifecycle record accepted a mutation.");
}

async function expectGuardedDeleteFailure(setting, value, statement, values) {
  const client = await database.connect();
  try {
    await client.query("begin");
    await client.query("select set_config($1, $2, true)", [setting, value]);
    await client.query(statement, values);
    await client.query("rollback");
  } catch (error) {
    await client.query("rollback");
    if (String(error.message).toLowerCase().includes("immutable")) return;
    throw error;
  } finally {
    client.release();
  }
  throw new Error("A caller-controlled purge setting bypassed an immutable record guard.");
}

function actor(id, email, roles) {
  return {
    authenticatedAt: email ? issuedAt - 30 : undefined,
    authentication: { method: "integration-proof", provider: email ? "vsign" : undefined },
    email,
    gatewaySessionId: `session-${id}`,
    principalId: `principal-${id}`,
    requestContext: {
      acceptLanguage: "en-US",
      clientHints: '"Chromium";v="140"',
      ipAddress: "192.0.2.42",
      userAgent: "VASI lifecycle integration proof",
    },
    roles,
    subject: `principal-${id}`,
  };
}

async function call(actorContext, method, path, body) {
  const token = await createActorAssertion(gatewaySettings, actorContext);
  return requestEngine(gatewaySettings, { body, method, path, token });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function verifyLifecycleSeal(payload, seal, profile) {
  return seal.profile === "vasi-certificate-seal/v1"
    ? verifyCertificateSeal(payload, seal)
    : verifyDetachedIntegritySeal(payload, seal, [profile]);
}

function expectStatus(result, status, label) {
  if (result.status !== status) {
    throw new Error(`${label} returned ${result.status}; expected ${status} (${JSON.stringify(result.body)}).`);
  }
}
