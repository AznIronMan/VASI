import { createHash } from "node:crypto";

import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import {
  participantContextPolicy,
  validateParticipantContextSubmission,
  withParticipantContextProvenance,
} from "../../packages/engine-domain/context.mjs";
import { appendEvent } from "./evidence-events.mjs";
import { EngineStoreError } from "./errors.mjs";

export function createContextStore(database, settings) {
  const policy = participantContextPolicy(settings);

  return Object.freeze({
    policy,
    async recordParticipantContext(actor, payload) {
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
          throw new EngineStoreError("participant_context_unavailable", 409);
        }

        const input = validateParticipantContextSubmission(payload);
        if (input.activityId !== record.activityId || input.interactionId !== record.interactionId) {
          throw new EngineStoreError("participant_context_state_conflict", 409);
        }
        const snapshot = withParticipantContextProvenance(input.snapshot);
        const payloadHash = hashCanonicalJSON({
          activityId: input.activityId,
          contextSessionId: input.contextSessionId,
          interactionId: input.interactionId,
          snapshot,
        });

        const replay = await client.query(
          `select "assignmentId", "activityInstanceId", "interactionId", "contextSessionId",
                  "sequence", "payloadHash"
           from "vasi_engine"."participant_context_snapshot" where "id" = $1`,
          [snapshot.id],
        );
        if (replay.rowCount) {
          const existing = replay.rows[0];
          if (existing.assignmentId !== record.assignmentId ||
              existing.activityInstanceId !== record.activityInstanceId) notFound();
          if (existing.interactionId !== input.interactionId ||
              existing.contextSessionId !== input.contextSessionId ||
              Number(existing.sequence) !== snapshot.sequence || existing.payloadHash !== payloadHash) {
            throw new EngineStoreError("participant_context_replay_conflict", 409);
          }
          return { accepted: false, duplicate: true, payloadHash, snapshotId: snapshot.id };
        }

        const count = await client.query(
          `select count(*)::integer as "count" from "vasi_engine"."participant_context_snapshot"
           where "activityInstanceId" = $1`,
          [record.activityInstanceId],
        );
        if (Number(count.rows[0].count) >= policy.maxSnapshotsPerActivity) {
          throw new EngineStoreError("participant_context_limit_reached", 413);
        }
        const previous = await client.query(
          `select "sequence", "snapshot"->>'monotonicMs' as "monotonicMs"
           from "vasi_engine"."participant_context_snapshot"
           where "activityInstanceId" = $1 and "contextSessionId" = $2
           order by "sequence" desc limit 1`,
          [record.activityInstanceId, input.contextSessionId],
        );
        if (!previous.rowCount && (snapshot.sequence !== 1 || snapshot.purpose !== "presentation")) {
          throw new EngineStoreError("participant_context_sequence_conflict", 409);
        }
        if (previous.rowCount && (
          snapshot.sequence <= Number(previous.rows[0].sequence) ||
          snapshot.monotonicMs < Number(previous.rows[0].monotonicMs)
        )) {
          throw new EngineStoreError("participant_context_sequence_conflict", 409);
        }

        const receivedAt = new Date();
        try {
          await client.query(
            `insert into "vasi_engine"."participant_context_snapshot"
              ("id", "tenantId", "requestId", "assignmentId", "activityInstanceId",
               "interactionId", "contextSessionId", "sequence", "purpose", "schema",
               "actorPrincipalId", "gatewaySessionId", "snapshot", "requestContext",
               "payloadHash", "receivedAt")
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
            [
              snapshot.id,
              record.tenantId,
              record.requestId,
              record.assignmentId,
              record.activityInstanceId,
              input.interactionId,
              input.contextSessionId,
              snapshot.sequence,
              snapshot.purpose,
              snapshot.schema,
              actor.principalId,
              actor.gatewaySessionId,
              snapshot,
              actor.requestContext || null,
              payloadHash,
              receivedAt,
            ],
          );
        } catch (error) {
          if (error?.code === "23505") {
            throw new EngineStoreError("participant_context_sequence_conflict", 409);
          }
          throw error;
        }
        await appendEvent(client, {
          actor,
          assignmentId: record.assignmentId,
          eventType: "participant.context.recorded",
          payload: {
            activityId: record.activityId,
            contextSessionId: input.contextSessionId,
            interactionId: input.interactionId,
            limitation: "Browser-reported context is supporting evidence and does not prove identity, attention, comprehension, or physical location.",
            snapshot: {
              id: snapshot.id,
              payloadHash,
              purpose: snapshot.purpose,
              schema: snapshot.schema,
              sequence: snapshot.sequence,
            },
          },
          receivedAt,
          requestId: record.requestId,
          tenantId: record.tenantId,
        });
        return { accepted: true, duplicate: false, payloadHash, snapshotId: snapshot.id };
      });
    },
  });
}

export async function loadParticipantContextEvidence(client, assignmentId, policy) {
  const result = await client.query(
    `select i."activityId", s."id", s."interactionId", s."contextSessionId", s."sequence",
            s."purpose", s."schema", s."actorPrincipalId", s."gatewaySessionId",
            s."snapshot", s."requestContext", s."payloadHash", s."receivedAt"
     from "vasi_engine"."participant_context_snapshot" s
     join "vasi_engine"."activity_instance" i on i."id" = s."activityInstanceId"
     where s."assignmentId" = $1
     order by i."ordinal", s."receivedAt", s."contextSessionId", s."sequence"`,
    [assignmentId],
  );
  return {
    policy,
    snapshots: result.rows.map((row) => ({
      activityId: row.activityId,
      actorPrincipalId: row.actorPrincipalId,
      contextSessionId: row.contextSessionId,
      gatewaySessionId: row.gatewaySessionId,
      id: row.id,
      interactionId: row.interactionId,
      payloadHash: row.payloadHash,
      purpose: row.purpose,
      receivedAt: new Date(row.receivedAt).toISOString(),
      requestContext: row.requestContext || undefined,
      schema: row.schema,
      sequence: Number(row.sequence),
      snapshot: row.snapshot,
    })),
  };
}

function preliminaryInput(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new EngineStoreError("invalid_participant_context", 400);
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
    throw new EngineStoreError("participant_context_unavailable", 409);
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
  if (!actor?.principalId || !actor?.email || !actor?.gatewaySessionId) {
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
