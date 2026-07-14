import { createHash, randomUUID } from "node:crypto";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import {
  activityInteractionPolicy,
  calculateActivityInteractionSummary,
  validateActivityInteractionBatch,
} from "../../packages/engine-domain/interaction.mjs";
import { appendEvent } from "./evidence-events.mjs";
import { EngineStoreError } from "./errors.mjs";

export function createInteractionStore(database, settings) {
  const policy = activityInteractionPolicy(settings);
  const maxEventsPerActivity = boundedIntegerSetting(
    settings.ENGINE_ACTIVITY_MAX_EVENTS_PER_ACTIVITY,
    20_000,
    100,
    100_000,
    "ENGINE_ACTIVITY_MAX_EVENTS_PER_ACTIVITY",
  );

  return Object.freeze({
    maxEventsPerActivity,
    policy,
    async recordParticipantEvents(actor, payload) {
      requireParticipant(actor);
      const preliminary = preliminaryInput(payload);
      const handleDigest = digestHandle(preliminary.handle);
      return transaction(database, async (client) => {
        const selected = await client.query(
          `select a."id" as "assignmentId", a."tenantId", a."requestId", a."intendedEmail",
                  a."principalId", a."status", r."status" as "requestStatus", r."scheduledFor",
                  r."expiresAt", i."id" as "activityInstanceId", i."activityId",
                  i."status" as "activityStatus", s."id" as "interactionId",
                  s."completedAt" as "interactionCompletedAt"
           from "vasi_engine"."participant_assignment" a
           join "vasi_engine"."request_instance" r on r."id" = a."requestId"
           join "vasi_engine"."activity_instance" i
             on i."assignmentId" = a."id" and i."activityId" = $2
           join "vasi_engine"."interaction_session" s
             on s."id" = $3 and s."assignmentId" = a."id" and s."principalId" = $4
           where a."handleDigest" = $1
           for update of a, r, i, s`,
          [handleDigest, preliminary.activityId, preliminary.interactionId, actor.principalId],
        );
        if (!selected.rowCount) notFound();
        const record = selected.rows[0];
        authorizeParticipant(record, actor);
        assertActivityAvailable(record, new Date());
        if (record.activityStatus !== "available" || record.interactionCompletedAt) {
          throw new EngineStoreError("activity_interaction_unavailable", 409);
        }

        const input = validateActivityInteractionBatch(payload);
        if (input.activityId !== record.activityId || input.interactionId !== record.interactionId) {
          throw new EngineStoreError("activity_interaction_state_conflict", 409);
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
           from "vasi_engine"."activity_interaction_event_batch" where "id" = $1`,
          [input.batchId],
        );
        if (replay.rowCount) {
          if (replay.rows[0].assignmentId !== record.assignmentId ||
              replay.rows[0].activityInstanceId !== record.activityInstanceId) notFound();
          if (replay.rows[0].interactionId !== input.interactionId ||
              replay.rows[0].telemetrySessionId !== input.telemetrySessionId ||
              replay.rows[0].payloadHash !== payloadHash) {
            throw new EngineStoreError("activity_interaction_batch_replay_conflict", 409);
          }
          return {
            accepted: 0,
            duplicate: true,
            summary: await latestActivityInteractionSummary(
              client,
              record.assignmentId,
              record.activityInstanceId,
            ),
          };
        }

        const count = await client.query(
          `select count(*)::integer as "count" from "vasi_engine"."activity_interaction_event"
           where "activityInstanceId" = $1`,
          [record.activityInstanceId],
        );
        if (Number(count.rows[0].count) + input.events.length > maxEventsPerActivity) {
          throw new EngineStoreError("activity_interaction_event_limit_reached", 413);
        }
        const previous = await client.query(
          `select "sequence", "monotonicMs" from "vasi_engine"."activity_interaction_event"
           where "activityInstanceId" = $1 and "telemetrySessionId" = $2
           order by "sequence" desc limit 1`,
          [record.activityInstanceId, input.telemetrySessionId],
        );
        if (previous.rowCount && (
          input.events[0].sequence <= Number(previous.rows[0].sequence) ||
          input.events[0].monotonicMs < Number(previous.rows[0].monotonicMs)
        )) {
          throw new EngineStoreError("activity_interaction_event_sequence_conflict", 409);
        }

        const receivedAt = new Date();
        await client.query(
          `insert into "vasi_engine"."activity_interaction_event_batch"
            ("id", "tenantId", "requestId", "assignmentId", "activityInstanceId",
             "interactionId", "telemetrySessionId", "actorPrincipalId", "eventCount",
             "payloadHash", "receivedAt")
           values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            input.batchId,
            record.tenantId,
            record.requestId,
            record.assignmentId,
            record.activityInstanceId,
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
              `insert into "vasi_engine"."activity_interaction_event"
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
          if (error?.code === "23505") {
            throw new EngineStoreError("activity_interaction_event_sequence_conflict", 409);
          }
          throw error;
        }

        const allEvents = await activityInteractionEventsForActivity(client, record.activityInstanceId);
        const summary = calculateActivityInteractionSummary(policy, allEvents);
        const revisionResult = await client.query(
          `select coalesce(max("revision"), 0) + 1 as "revision"
           from "vasi_engine"."activity_interaction_summary_revision"
           where "activityInstanceId" = $1`,
          [record.activityInstanceId],
        );
        const revision = Number(revisionResult.rows[0].revision);
        const summaryHash = hashCanonicalJSON(summary);
        await client.query(
          `insert into "vasi_engine"."activity_interaction_summary_revision"
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
            policy,
            summary,
            summaryHash,
            receivedAt,
          ],
        );
        await appendEvent(client, {
          actor,
          assignmentId: record.assignmentId,
          eventType: "activity.interaction.recorded",
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
            limitation: "Browser-reported activity presence is supporting evidence and does not prove attention or comprehension.",
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
  });
}

export async function loadActivityInteractionEvidence(client, assignmentId) {
  const batches = await client.query(
    `select i."activityId", b."id", b."interactionId", b."telemetrySessionId",
            b."actorPrincipalId", b."eventCount", b."payloadHash", b."receivedAt"
     from "vasi_engine"."activity_interaction_event_batch" b
     join "vasi_engine"."activity_instance" i on i."id" = b."activityInstanceId"
     where b."assignmentId" = $1 order by i."ordinal", b."receivedAt", b."id"`,
    [assignmentId],
  );
  const events = await client.query(
    `select i."activityId", e."batchId", e."id", e."interactionId", e."telemetrySessionId",
            e."sequence", e."eventType", e."eventData", e."receivedAt"
     from "vasi_engine"."activity_interaction_event" e
     join "vasi_engine"."activity_instance" i on i."id" = e."activityInstanceId"
     where e."assignmentId" = $1
     order by i."ordinal", e."receivedAt", e."telemetrySessionId", e."sequence"`,
    [assignmentId],
  );
  const summaries = await client.query(
    `select i."activityId", s."id", s."revision", s."policy", s."summary", s."summaryHash",
            s."calculatedAt"
     from "vasi_engine"."activity_interaction_summary_revision" s
     join "vasi_engine"."activity_instance" i on i."id" = s."activityInstanceId"
     where s."assignmentId" = $1 order by i."ordinal", s."revision"`,
    [assignmentId],
  );
  return {
    batches: batches.rows.map((row) => ({
      activityId: row.activityId,
      actorPrincipalId: row.actorPrincipalId,
      eventCount: Number(row.eventCount),
      id: row.id,
      interactionId: row.interactionId,
      payloadHash: row.payloadHash,
      receivedAt: new Date(row.receivedAt).toISOString(),
      telemetrySessionId: row.telemetrySessionId,
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

export async function latestActivityInteractionSummary(client, assignmentId, activityInstanceId) {
  const result = await client.query(
    `select "summary" from "vasi_engine"."activity_interaction_summary_revision"
     where "assignmentId" = $1 and "activityInstanceId" = $2
     order by "revision" desc limit 1`,
    [assignmentId, activityInstanceId],
  );
  return result.rows[0]?.summary;
}

async function activityInteractionEventsForActivity(client, activityInstanceId) {
  const result = await client.query(
    `select "interactionId", "telemetrySessionId", "sequence", "eventType",
            "monotonicMs", "eventData", "receivedAt"
     from "vasi_engine"."activity_interaction_event" where "activityInstanceId" = $1
     order by "receivedAt", "telemetrySessionId", "sequence"`,
    [activityInstanceId],
  );
  return result.rows;
}

function preliminaryInput(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new EngineStoreError("invalid_activity_interaction", 400);
  }
  return {
    activityId: token(value.activityId, "activity_id", 64),
    handle: token(value.handle, "handle", 64),
    interactionId: token(value.interactionId, "interaction_id", 128),
  };
}

function authorizeParticipant(record, actor) {
  if (record.intendedEmail.toLowerCase() !== actor.email ||
      (record.principalId && record.principalId !== actor.principalId)) notFound();
}

function assertActivityAvailable(record, now) {
  if (record.status === "revoked" || record.requestStatus === "revoked") {
    throw new EngineStoreError("assignment_revoked", 410);
  }
  if (record.status === "completed" || record.requestStatus === "completed") {
    throw new EngineStoreError("activity_interaction_unavailable", 409);
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
  if (!actor?.principalId || !actor?.email) {
    throw new EngineStoreError("participant_identity_required", 403);
  }
}

function digestHandle(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) notFound();
  return createHash("sha256").update(value, "utf8").digest();
}

function token(value, field, maximum) {
  if (typeof value !== "string" || !value || value.length > maximum ||
      /[\u0000-\u001f\u007f]/.test(value)) {
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
