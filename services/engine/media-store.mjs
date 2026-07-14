import { createHash, randomUUID } from "node:crypto";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import {
  calculateMediaSummary,
  validateMediaEventBatch,
  validateMediaOriginPolicy,
} from "../../packages/engine-domain/media.mjs";
import { appendEvent } from "./evidence-events.mjs";
import { EngineStoreError } from "./errors.mjs";

export function createMediaStore(database, settings) {
  const maxEventsPerActivity = boundedIntegerSetting(
    settings.ENGINE_MEDIA_MAX_EVENTS_PER_ACTIVITY,
    20_000,
    100,
    100_000,
    "ENGINE_MEDIA_MAX_EVENTS_PER_ACTIVITY",
  );
  return Object.freeze({
    async openParticipantMedia(actor, payload) {
      requireParticipant(actor);
      const input = preliminaryMediaOpenInput(payload);
      const handleDigest = digestHandle(input.handle);
      return transaction(database, async (client) => {
        const selected = await client.query(
          `select a."id" as "assignmentId", a."tenantId", a."requestId", a."intendedEmail",
                  a."principalId", a."status", r."status" as "requestStatus", r."scheduledFor",
                  r."expiresAt", i."id" as "activityInstanceId", i."activityId",
                  i."activityType", i."status" as "activityStatus", i."definition",
                  x."id" as "descriptorId", x."descriptor", x."descriptorHash"
           from "vasi_engine"."participant_assignment" a
           join "vasi_engine"."request_instance" r on r."id" = a."requestId"
           join "vasi_engine"."activity_instance" i
             on i."assignmentId" = a."id" and i."activityId" = $2
           join "vasi_engine"."external_media_descriptor" x
             on x."workflowRevisionId" = r."workflowRevisionId" and x."activityId" = i."activityId"
           where a."handleDigest" = $1
           for update of a, r, i`,
          [handleDigest, input.activityId],
        );
        if (!selected.rowCount) notFound();
        const record = selected.rows[0];
        authorizeParticipant(record, actor);
        assertMediaAvailable(record, new Date());
        if (record.activityType !== "external_media" || record.activityStatus !== "available") {
          throw new EngineStoreError("media_activity_unavailable", 409);
        }
        const openedAt = new Date();
        return {
          activityId: record.activityId,
          descriptor: record.descriptor,
          descriptorHash: record.descriptorHash,
          openedAt: openedAt.toISOString(),
        };
      });
    },
    async recordParticipantEvents(actor, payload) {
      requireParticipant(actor);
      const preliminary = preliminaryMediaInput(payload);
      const handleDigest = digestHandle(preliminary.handle);
      return transaction(database, async (client) => {
        const selected = await client.query(
          `select a."id" as "assignmentId", a."tenantId", a."requestId", a."intendedEmail",
                  a."principalId", a."status", r."status" as "requestStatus", r."scheduledFor",
                  r."expiresAt", r."workflowRevisionId",
                  i."id" as "activityInstanceId", i."activityId", i."activityType", i."definition",
                  i."status" as "activityStatus", x."id" as "descriptorId",
                  s."id" as "interactionId", s."completedAt" as "interactionCompletedAt"
           from "vasi_engine"."participant_assignment" a
           join "vasi_engine"."request_instance" r on r."id" = a."requestId"
           join "vasi_engine"."activity_instance" i
             on i."assignmentId" = a."id" and i."activityId" = $2
           join "vasi_engine"."external_media_descriptor" x
             on x."workflowRevisionId" = r."workflowRevisionId" and x."activityId" = i."activityId"
           join "vasi_engine"."interaction_session" s
             on s."id" = $3 and s."assignmentId" = a."id" and s."principalId" = $4
           where a."handleDigest" = $1
           for update of a, r, i, s`,
          [handleDigest, preliminary.activityId, preliminary.interactionId, actor.principalId],
        );
        if (!selected.rowCount) notFound();
        const record = selected.rows[0];
        authorizeParticipant(record, actor);
        assertMediaAvailable(record, new Date());
        if (record.activityType !== "external_media" || record.activityStatus !== "available" ||
            record.interactionCompletedAt) {
          throw new EngineStoreError("media_activity_unavailable", 409);
        }
        const input = validateMediaEventBatch(payload, record.definition.content);
        if (input.activityId !== record.activityId || input.interactionId !== record.interactionId) {
          throw new EngineStoreError("media_activity_state_conflict", 409);
        }
        const payloadHash = hashCanonicalJSON({
          activityId: input.activityId,
          batchId: input.batchId,
          events: input.events,
          interactionId: input.interactionId,
          telemetrySessionId: input.telemetrySessionId,
        });

        const replay = await client.query(
          `select "assignmentId", "activityInstanceId", "interactionId", "telemetrySessionId", "payloadHash"
           from "vasi_engine"."media_event_batch"
           where "id" = $1`,
          [input.batchId],
        );
        if (replay.rowCount) {
          if (replay.rows[0].assignmentId !== record.assignmentId ||
              replay.rows[0].activityInstanceId !== record.activityInstanceId) notFound();
          if (replay.rows[0].interactionId !== input.interactionId ||
              replay.rows[0].telemetrySessionId !== input.telemetrySessionId ||
              replay.rows[0].payloadHash !== payloadHash) {
            throw new EngineStoreError("media_batch_replay_conflict", 409);
          }
          return {
            accepted: 0,
            duplicate: true,
            summary: await latestMediaSummary(client, record.assignmentId, record.activityInstanceId),
          };
        }
        const count = await client.query(
          `select count(*)::integer as "count" from "vasi_engine"."media_event"
           where "activityInstanceId" = $1`,
          [record.activityInstanceId],
        );
        if (Number(count.rows[0].count) + input.events.length > maxEventsPerActivity) {
          throw new EngineStoreError("media_event_limit_reached", 413);
        }
        const previous = await client.query(
          `select "sequence", "monotonicMs" from "vasi_engine"."media_event"
           where "activityInstanceId" = $1 and "telemetrySessionId" = $2
           order by "sequence" desc limit 1`,
          [record.activityInstanceId, input.telemetrySessionId],
        );
        if (previous.rowCount && (
          input.events[0].sequence <= Number(previous.rows[0].sequence) ||
          input.events[0].monotonicMs < Number(previous.rows[0].monotonicMs)
        )) {
          throw new EngineStoreError("media_event_sequence_conflict", 409);
        }

        const receivedAt = new Date();
        await client.query(
          `insert into "vasi_engine"."media_event_batch"
            ("id", "tenantId", "requestId", "assignmentId", "activityInstanceId",
             "descriptorId", "interactionId", "telemetrySessionId", "actorPrincipalId",
             "eventCount", "payloadHash", "receivedAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [
            input.batchId,
            record.tenantId,
            record.requestId,
            record.assignmentId,
            record.activityInstanceId,
            record.descriptorId,
            input.interactionId,
            input.telemetrySessionId,
            actor.principalId,
            input.events.length,
            payloadHash,
            receivedAt,
          ],
        );
        try {
          for (const event of input.events) {
            await client.query(
              `insert into "vasi_engine"."media_event"
                ("batchId", "id", "tenantId", "assignmentId", "activityInstanceId",
                 "interactionId", "telemetrySessionId", "sequence", "eventType",
                 "monotonicMs", "eventData", "receivedAt")
               values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
              [
                input.batchId,
                event.id,
                record.tenantId,
                record.assignmentId,
                record.activityInstanceId,
                input.interactionId,
                input.telemetrySessionId,
                event.sequence,
                event.type,
                event.monotonicMs,
                event,
                receivedAt,
              ],
            );
          }
        } catch (error) {
          if (error?.code === "23505") throw new EngineStoreError("media_event_sequence_conflict", 409);
          throw error;
        }

        if (input.events.some((event) => ["presented", "frame_loaded", "ready"].includes(event.type))) {
          await persistObservedSnapshot(client, record, "participant_start", "available", receivedAt, {
            observedEvents: input.events
              .filter((event) => ["presented", "frame_loaded", "ready"].includes(event.type))
              .map((event) => event.type),
          });
        }
        if (input.events.some((event) => ["frame_error", "provider_error"].includes(event.type))) {
          await persistObservedSnapshot(client, record, "participant_start", "error", receivedAt, {
            errors: input.events
              .filter((event) => ["frame_error", "provider_error"].includes(event.type))
              .map((event) => event.detail || { code: event.type }),
          });
        }

        const allEvents = await mediaEventsForActivity(client, record.activityInstanceId);
        const summary = calculateMediaSummary(record.definition.content, allEvents);
        const revisionResult = await client.query(
          `select coalesce(max("revision"), 0) + 1 as "revision"
           from "vasi_engine"."media_activity_summary_revision"
           where "activityInstanceId" = $1`,
          [record.activityInstanceId],
        );
        const revision = Number(revisionResult.rows[0].revision);
        const summaryHash = hashCanonicalJSON(summary);
        await client.query(
          `insert into "vasi_engine"."media_activity_summary_revision"
            ("id", "tenantId", "requestId", "assignmentId", "activityInstanceId",
             "revision", "policy", "summary", "summaryHash", "calculatedAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            randomUUID(),
            record.tenantId,
            record.requestId,
            record.assignmentId,
            record.activityInstanceId,
            revision,
            {
              completion: record.definition.content.completionPolicy,
              telemetry: record.definition.content.telemetryPolicy,
            },
            summary,
            summaryHash,
            receivedAt,
          ],
        );
        await appendEvent(client, {
          actor,
          assignmentId: record.assignmentId,
          eventType: "media.telemetry.recorded",
          payload: {
            activityId: record.activityId,
            batch: {
              eventCount: input.events.length,
              firstSequence: input.events[0].sequence,
              id: input.batchId,
              lastSequence: input.events.at(-1).sequence,
              payloadHash,
              telemetrySessionId: input.telemetrySessionId,
            },
            limitation: "Browser telemetry is supporting evidence and does not prove attention or comprehension.",
            summaryHash,
            summaryRevision: revision,
          },
          receivedAt,
          requestId: record.requestId,
          tenantId: record.tenantId,
        });
        return { accepted: input.events.length, duplicate: false, revision, summary, summaryHash };
      });
    },
    maxEventsPerActivity,
  });
}

export function resolveWorkflowMediaBindings(document, settings) {
  const configuredOrigins = configuredMediaOrigins(settings);
  const activities = [];
  const bindings = [];
  for (const activity of document.activities) {
    if (activity.type !== "external_media") {
      activities.push(activity);
      continue;
    }
    validateMediaOriginPolicy(activity.content, configuredOrigins);
    const descriptorHash = hashCanonicalJSON(activity.content.descriptor);
    const binding = Object.freeze({
      ...activity.content.descriptor,
      descriptorHash,
      id: randomUUID(),
    });
    activities.push(Object.freeze({
      ...activity,
      content: Object.freeze({ ...activity.content, descriptor: binding }),
    }));
    bindings.push(Object.freeze({ activityId: activity.id, descriptor: binding }));
  }
  const snapshot = Object.freeze({ ...document, activities: Object.freeze(activities) });
  return Object.freeze({
    bindings: Object.freeze(bindings),
    snapshot,
    snapshotHash: hashCanonicalJSON(snapshot),
  });
}

export async function persistWorkflowMediaBindings(client, tenantId, workflowRevisionId, bindings, boundAt) {
  for (const binding of bindings) {
    const descriptor = binding.descriptor;
    await client.query(
      `insert into "vasi_engine"."external_media_descriptor"
        ("id", "tenantId", "workflowRevisionId", "activityId", "provider", "itemId",
         "sourceUrl", "embedUrl", "capability", "adapterId", "adapterVersion",
         "descriptor", "descriptorHash", "boundAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
      [
        descriptor.id,
        tenantId,
        workflowRevisionId,
        binding.activityId,
        descriptor.provider,
        descriptor.itemId,
        descriptor.sourceUrl,
        descriptor.embedUrl || null,
        descriptor.capability,
        descriptor.adapter.id,
        descriptor.adapter.version,
        descriptor,
        descriptor.descriptorHash,
        boundAt,
      ],
    );
    await persistMetadataSnapshot(client, {
      availability: "configured",
      capturedAt: boundAt,
      descriptor,
      descriptorId: descriptor.id,
      phase: "publish",
      source: "tenant_supplied",
      tenantId,
    });
  }
}

export async function persistIssueMediaSnapshots(
  client,
  { assignmentId, issuedAt, requestId, tenantId, workflowRevisionId },
) {
  const descriptors = await client.query(
    `select "id", "descriptor" from "vasi_engine"."external_media_descriptor"
     where "workflowRevisionId" = $1 order by "activityId"`,
    [workflowRevisionId],
  );
  for (const row of descriptors.rows) {
    await persistMetadataSnapshot(client, {
      assignmentId,
      availability: "configured",
      capturedAt: issuedAt,
      descriptor: row.descriptor,
      descriptorId: row.id,
      phase: "issue",
      requestId,
      source: "tenant_supplied",
      tenantId,
    });
  }
}

export async function assertMediaCompletion(client, record, activity, response, completedAt) {
  if (activity.definition.type !== "external_media") return response;
  const method = response.value.method;
  const summaryRecord = await latestMediaSummaryRecord(client, record.assignmentId, activity.id);
  if (method === "playback" && !summaryRecord?.summary?.playback?.completionMet) {
    throw new EngineStoreError("media_playback_incomplete", 409);
  }
  const descriptorId = activity.definition.content.descriptor.id;
  await persistMetadataSnapshot(client, {
    assignmentId: record.assignmentId,
    availability: summaryRecord?.summary?.playback?.providerErrorCount ? "error" : "available",
    capturedAt: completedAt,
    descriptor: activity.definition.content.descriptor,
    descriptorId,
    metadata: { completionMethod: method, summaryHash: summaryRecord?.summaryHash },
    phase: "completion",
    requestId: record.requestId,
    source: "browser_observed",
    tenantId: record.tenantId,
  });
  return Object.freeze({
    ...response,
    result: Object.freeze({
      ...response.result,
      mediaSummary: summaryRecord?.summary,
      mediaSummaryHash: summaryRecord?.summaryHash,
      mediaSummaryRevision: summaryRecord?.revision,
    }),
  });
}

export async function loadMediaEvidence(client, assignmentId) {
  const descriptors = await client.query(
    `select x."id", x."activityId", x."descriptor", x."descriptorHash", x."boundAt"
     from "vasi_engine"."external_media_descriptor" x
     join "vasi_engine"."request_instance" r on r."workflowRevisionId" = x."workflowRevisionId"
     join "vasi_engine"."participant_assignment" a on a."requestId" = r."id"
     where a."id" = $1 order by x."activityId"`,
    [assignmentId],
  );
  if (!descriptors.rowCount) return undefined;
  const snapshots = await client.query(
    `select s."id", x."activityId", s."phase", s."source", s."availability", s."metadata",
            s."metadataHash", s."capturedAt"
     from "vasi_engine"."external_media_metadata_snapshot" s
     join "vasi_engine"."external_media_descriptor" x on x."id" = s."descriptorId"
     where s."assignmentId" = $1 or (s."assignmentId" is null and x."id" = any($2::text[]))
     order by x."activityId", s."capturedAt", s."id"`,
    [assignmentId, descriptors.rows.map((row) => row.id)],
  );
  const events = await client.query(
    `select i."activityId", e."batchId", e."id", e."interactionId", e."telemetrySessionId",
            e."sequence", e."eventType", e."eventData", e."receivedAt"
     from "vasi_engine"."media_event" e
     join "vasi_engine"."activity_instance" i on i."id" = e."activityInstanceId"
     where e."assignmentId" = $1
     order by i."ordinal", e."receivedAt", e."telemetrySessionId", e."sequence"`,
    [assignmentId],
  );
  const summaries = await client.query(
    `select i."activityId", s."id", s."revision", s."policy", s."summary", s."summaryHash",
            s."calculatedAt"
     from "vasi_engine"."media_activity_summary_revision" s
     join "vasi_engine"."activity_instance" i on i."id" = s."activityInstanceId"
     where s."assignmentId" = $1 order by i."ordinal", s."revision"`,
    [assignmentId],
  );
  return {
    descriptors: descriptors.rows.map((row) => ({
      activityId: row.activityId,
      boundAt: new Date(row.boundAt).toISOString(),
      descriptor: row.descriptor,
      descriptorHash: row.descriptorHash,
      id: row.id,
    })),
    events: events.rows.map((row) => ({
      activityId: row.activityId,
      batchId: row.batchId,
      event: row.eventData,
      id: row.id,
      interactionId: row.interactionId,
      receivedAt: new Date(row.receivedAt).toISOString(),
      sequence: Number(row.sequence),
      telemetrySessionId: row.telemetrySessionId,
      type: row.eventType,
    })),
    snapshots: snapshots.rows.map((row) => ({
      activityId: row.activityId,
      availability: row.availability,
      capturedAt: new Date(row.capturedAt).toISOString(),
      id: row.id,
      metadata: row.metadata,
      metadataHash: row.metadataHash,
      phase: row.phase,
      source: row.source,
    })),
    summaries: summaries.rows.map((row) => ({
      activityId: row.activityId,
      calculatedAt: new Date(row.calculatedAt).toISOString(),
      id: row.id,
      policy: row.policy,
      revision: Number(row.revision),
      summary: row.summary,
      summaryHash: row.summaryHash,
    })),
  };
}

async function latestMediaSummary(client, assignmentId, activityInstanceId) {
  return (await latestMediaSummaryRecord(client, assignmentId, activityInstanceId))?.summary;
}

async function latestMediaSummaryRecord(client, assignmentId, activityInstanceId) {
  const result = await client.query(
    `select "revision", "summary", "summaryHash" from "vasi_engine"."media_activity_summary_revision"
     where "assignmentId" = $1 and "activityInstanceId" = $2
     order by "revision" desc limit 1`,
    [assignmentId, activityInstanceId],
  );
  if (!result.rowCount) return undefined;
  return { ...result.rows[0], revision: Number(result.rows[0].revision) };
}

async function mediaEventsForActivity(client, activityInstanceId) {
  const result = await client.query(
    `select "interactionId", "telemetrySessionId", "eventData" as "event"
     from "vasi_engine"."media_event" where "activityInstanceId" = $1
     order by "receivedAt", "telemetrySessionId", "sequence"`,
    [activityInstanceId],
  );
  return result.rows;
}

async function persistObservedSnapshot(client, record, phase, availability, capturedAt, metadata) {
  await persistMetadataSnapshot(client, {
    assignmentId: record.assignmentId,
    availability,
    capturedAt,
    descriptor: record.definition.content.descriptor,
    descriptorId: record.descriptorId,
    metadata,
    phase,
    requestId: record.requestId,
    source: "browser_observed",
    tenantId: record.tenantId,
  });
}

async function persistMetadataSnapshot(client, {
  assignmentId,
  availability,
  capturedAt,
  descriptor,
  descriptorId,
  metadata,
  phase,
  requestId,
  source,
  tenantId,
}) {
  const snapshot = {
    accessMode: descriptor.accessMode,
    adapter: descriptor.adapter,
    capability: descriptor.capability,
    dimensions: descriptor.dimensions,
    durationMilliseconds: descriptor.durationMilliseconds,
    itemId: descriptor.itemId,
    kind: descriptor.kind,
    limitations: descriptor.limitations,
    metadataProvenance: descriptor.metadataProvenance,
    observed: metadata,
    owner: descriptor.owner,
    provider: descriptor.provider,
    sourceUrl: descriptor.sourceUrl,
    title: descriptor.title,
    version: descriptor.version,
  };
  await client.query(
    `insert into "vasi_engine"."external_media_metadata_snapshot"
      ("id", "tenantId", "descriptorId", "requestId", "assignmentId", "phase", "source",
       "availability", "metadata", "metadataHash", "capturedAt")
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     on conflict ("descriptorId", "assignmentId", "phase", "source", "availability")
     do nothing`,
    [
      randomUUID(),
      tenantId,
      descriptorId,
      requestId || null,
      assignmentId || null,
      phase,
      source,
      availability,
      snapshot,
      hashCanonicalJSON(snapshot),
      capturedAt,
    ],
  );
}

function configuredMediaOrigins(settings) {
  return String(settings.ENGINE_MEDIA_GENERIC_ORIGINS || "")
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function preliminaryMediaInput(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new EngineStoreError("invalid_media_telemetry", 400);
  }
  return {
    activityId: token(value.activityId, "activityId", 64),
    handle: token(value.handle, "handle", 64),
    interactionId: token(value.interactionId, "interactionId", 128),
  };
}

function preliminaryMediaOpenInput(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new EngineStoreError("invalid_media_request", 400);
  }
  return {
    activityId: token(value.activityId, "activity_id", 64),
    handle: token(value.handle, "handle", 64),
  };
}

function authorizeParticipant(record, actor) {
  if (record.intendedEmail.toLowerCase() !== actor.email ||
      (record.principalId && record.principalId !== actor.principalId)) notFound();
}

function assertMediaAvailable(record, now) {
  if (record.status === "revoked" || record.requestStatus === "revoked") {
    throw new EngineStoreError("assignment_revoked", 410);
  }
  if (record.status === "completed" || record.requestStatus === "completed") {
    throw new EngineStoreError("media_activity_unavailable", 409);
  }
  if (record.status === "expired" || record.requestStatus === "expired" ||
      new Date(record.expiresAt) <= now) {
    throw new EngineStoreError("assignment_expired", 410);
  }
  if (record.scheduledFor && new Date(record.scheduledFor) > now) {
    throw new EngineStoreError("assignment_not_yet_available", 425);
  }
}

function requireParticipant(actor) {
  if (!actor?.principalId || !actor?.email) throw new EngineStoreError("participant_identity_required", 403);
}

function digestHandle(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) notFound();
  return createHash("sha256").update(value, "utf8").digest();
}

function token(value, field, maximum) {
  if (typeof value !== "string" || !value || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new EngineStoreError(`invalid_${field}`, 400);
  }
  return value;
}

function boundedIntegerSetting(value, fallback, minimum, maximum, name) {
  const parsed = value === undefined || value === null || value === "" ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be a whole number between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function notFound() {
  throw new EngineStoreError("not_found", 404);
}

async function transaction(database, callback) {
  const client = await database.connect();
  try {
    await client.query("begin");
    const value = await callback(client);
    await client.query("commit");
    return value;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
