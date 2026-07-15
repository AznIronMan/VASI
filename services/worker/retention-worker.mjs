import { hashCanonicalJSON } from "../../packages/engine-crypto/index.mjs";
import {
  appendDataRequestEvent,
  appendLifecycleEvent,
} from "../engine/lifecycle-store.mjs";

const TOMBSTONE_PROFILE = "vasi-retention-tombstone/v1";

export async function expireOneParticipantDataRequest(database, now = new Date()) {
  return transaction(database, async (client) => {
    const result = await client.query(
      `select r.*, e."id" as "exportId", e."contentDeletedAt"
       from "vasi_engine"."participant_data_request" r
       left join "vasi_engine"."participant_data_export" e on e."requestId" = r."id"
       where r."status" not in ('expired', 'cancelled')
         and ((e."id" is not null and e."expiresAt" <= $1)
           or (e."id" is null and r."expiresAt" <= $1))
       order by least(r."expiresAt", coalesce(e."expiresAt", r."expiresAt")), r."id"
       limit 1 for update of r skip locked`,
      [now],
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    const actor = serviceActor();
    if (row.exportId && !row.contentDeletedAt) {
      await appendDataRequestEvent(client, {
        actor,
        createdAt: now,
        eventType: "export.expired",
        payload: { exportId: row.exportId, reason: "delivery_window_elapsed" },
        requestId: row.id,
      });
      await client.query(
        `select "vasi_engine"."expire_participant_data_export"($1)`,
        [row.exportId],
      );
      return { action: "export.expired", requestId: row.id };
    }
    await client.query(
      `update "vasi_engine"."participant_data_request"
       set "status" = 'expired', "updatedAt" = $2 where "id" = $1`,
      [row.id, now],
    );
    await appendDataRequestEvent(client, {
      actor,
      createdAt: now,
      eventType: "request.expired",
      payload: { reason: "review_or_delivery_window_elapsed" },
      requestId: row.id,
    });
    return { action: "request.expired", requestId: row.id };
  });
}

export async function advanceOneRetentionLifecycle(database, signingProvider, now = new Date()) {
  return transaction(database, async (client) => {
    const result = await client.query(
      `select l.*
       from "vasi_engine"."record_lifecycle_state" l
       where (l."contentStatus" = 'active' and l."contentExpiresAt" is not null and l."contentExpiresAt" <= $1)
          or (l."historyStatus" = 'active' and l."historyExpiresAt" is not null and l."historyExpiresAt" <= $1)
          or (l."evidenceStatus" = 'active' and l."archiveAt" is not null and l."archiveAt" <= $1)
          or (l."deleteAt" is not null and l."deleteAt" <= $1
              and (l."lastEvaluatedAt" is null or l."lastEvaluatedAt" <= $1 - interval '1 day'))
       order by
         case
           when l."contentStatus" = 'active' and l."contentExpiresAt" is not null and l."contentExpiresAt" <= $1 then 0
           when l."historyStatus" = 'active' and l."historyExpiresAt" is not null and l."historyExpiresAt" <= $1 then 1
           when l."evidenceStatus" = 'active' and l."archiveAt" is not null and l."archiveAt" <= $1 then 2
           else 3
         end,
         least(
           coalesce(l."contentExpiresAt", 'infinity'::timestamptz),
           coalesce(l."historyExpiresAt", 'infinity'::timestamptz),
           coalesce(l."archiveAt", 'infinity'::timestamptz),
           coalesce(l."deleteAt", 'infinity'::timestamptz)
         ),
         l."assignmentId"
       limit 1 for update of l skip locked`,
      [now],
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    const actor = serviceActor();
    if (due(row.contentExpiresAt, now) && row.contentStatus === "active") {
      await client.query(
        `update "vasi_engine"."record_lifecycle_state"
         set "contentStatus" = 'expired', "lastEvaluatedAt" = null, "updatedAt" = $2
         where "assignmentId" = $1`,
        [row.assignmentId, now],
      );
      await appendLifecycleEvent(client, lifecycleEvent(row, actor, now, "content.expired", {
        deadline: new Date(row.contentExpiresAt).toISOString(),
      }));
      return { action: "content.expired", assignmentId: row.assignmentId };
    }
    if (due(row.historyExpiresAt, now) && row.historyStatus === "active") {
      await client.query(
        `update "vasi_engine"."record_lifecycle_state"
         set "historyStatus" = 'expired', "lastEvaluatedAt" = null, "updatedAt" = $2
         where "assignmentId" = $1`,
        [row.assignmentId, now],
      );
      await appendLifecycleEvent(client, lifecycleEvent(row, actor, now, "history.expired", {
        deadline: new Date(row.historyExpiresAt).toISOString(),
      }));
      return { action: "history.expired", assignmentId: row.assignmentId };
    }
    if (due(row.archiveAt, now) && row.evidenceStatus === "active") {
      await client.query(
        `update "vasi_engine"."record_lifecycle_state"
         set "evidenceStatus" = 'archived', "lastEvaluatedAt" = null, "updatedAt" = $2
         where "assignmentId" = $1`,
        [row.assignmentId, now],
      );
      await appendLifecycleEvent(client, lifecycleEvent(row, actor, now, "evidence.archived", {
        deadline: new Date(row.archiveAt).toISOString(),
        effect: "logical_archive_preserves_verification",
      }));
      return { action: "evidence.archived", assignmentId: row.assignmentId };
    }
    if (!due(row.deleteAt, now)) return null;

    const blockers = await purgeBlockers(client, row.assignmentId, now);
    if (blockers.activeHoldCount || blockers.activeDataRequestCount) {
      await client.query(
        `update "vasi_engine"."record_lifecycle_state"
         set "lastEvaluatedAt" = $2, "updatedAt" = $2 where "assignmentId" = $1`,
        [row.assignmentId, now],
      );
      await appendLifecycleEvent(client, lifecycleEvent(row, actor, now, "purge.blocked", blockers));
      return { action: "purge.blocked", assignmentId: row.assignmentId, blockers };
    }

    if (row.evidenceStatus !== "purge_due") {
      await client.query(
        `update "vasi_engine"."record_lifecycle_state"
         set "evidenceStatus" = 'purge_due', "lastEvaluatedAt" = $2, "updatedAt" = $2
         where "assignmentId" = $1`,
        [row.assignmentId, now],
      );
      await appendLifecycleEvent(client, lifecycleEvent(row, actor, now, "purge.due", {
        deadline: new Date(row.deleteAt).toISOString(),
        policyHash: row.policyHash,
      }));
    }

    const evidence = await client.query(
      `select h."lastHash" as "evidenceHeadHash", m."manifestHash"
       from "vasi_engine"."evidence_chain_head" h
       left join "vasi_engine"."evidence_manifest" m on m."assignmentId" = h."assignmentId"
       where h."assignmentId" = $1`,
      [row.assignmentId],
    );
    if (!evidence.rowCount) throw workerError("evidence_chain_missing");
    const purgedEvent = await appendLifecycleEvent(client, lifecycleEvent(row, actor, now, "record.purged", {
      deadline: new Date(row.deleteAt).toISOString(),
      effect: "participant_and_transaction_rows_removed; sealed_tombstone_retained",
      policyHash: row.policyHash,
    }));
    const tombstone = {
      assignmentId: row.assignmentId,
      evidenceHeadHash: evidence.rows[0].evidenceHeadHash,
      lifecycleHeadHash: purgedEvent.eventHash,
      manifestHash: evidence.rows[0].manifestHash || null,
      policyHash: row.policyHash,
      purgedAt: now.toISOString(),
      requestId: row.requestId,
      schema: "vasi-retention-purge-tombstone/v1",
      tenantId: row.tenantId,
    };
    const tombstoneHash = hashCanonicalJSON(tombstone);
    const seals = signingProvider.signDetached(tombstone, TOMBSTONE_PROFILE);
    await client.query(
      `insert into "vasi_engine"."retention_purge_tombstone"
        ("assignmentId", "tenantId", "requestId", "manifestHash", "evidenceHeadHash",
         "lifecycleHeadHash", "policyHash", "tombstone", "tombstoneHash", "seal", "purgedAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        row.assignmentId,
        row.tenantId,
        row.requestId,
        tombstone.manifestHash,
        tombstone.evidenceHeadHash,
        tombstone.lifecycleHeadHash,
        row.policyHash,
        tombstone,
        tombstoneHash,
        JSON.stringify(seals),
        now,
      ],
    );
    await client.query(
      `select "vasi_engine"."purge_record_for_retention"($1, $2)`,
      [row.assignmentId, tombstoneHash],
    );
    return { action: "record.purged", assignmentId: row.assignmentId, tombstoneHash };
  });
}

async function purgeBlockers(client, assignmentId, now) {
  const result = await client.query(
    `select
       (select count(*) from "vasi_engine"."legal_hold" h
        left join "vasi_engine"."legal_hold_release" r on r."holdId" = h."id"
        where h."assignmentId" = $1 and r."id" is null) as "activeHoldCount",
       (select count(*)
        from "vasi_engine"."participant_data_request_scope" s
        join "vasi_engine"."participant_data_request" r on r."id" = s."requestId"
        where $1 = any(s."matchedAssignmentIds")
          and r."status" in ('pending_review', 'approved', 'partially_approved', 'ready')
          and r."expiresAt" > $2) as "activeDataRequestCount"`,
    [assignmentId, now],
  );
  return {
    activeDataRequestCount: Number(result.rows[0].activeDataRequestCount),
    activeHoldCount: Number(result.rows[0].activeHoldCount),
  };
}

function lifecycleEvent(row, actor, createdAt, eventType, payload) {
  return {
    actor,
    assignmentId: row.assignmentId,
    createdAt,
    eventType,
    payload,
    requestId: row.requestId,
    source: "worker",
    tenantId: row.tenantId,
  };
}

function due(value, now) {
  return Boolean(value && new Date(value) <= now);
}

function serviceActor() {
  return {
    authentication: { method: "service" },
    principalId: "vasi-worker",
    roles: ["service"],
  };
}

function workerError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
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
