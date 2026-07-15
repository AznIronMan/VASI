import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

import {
  decryptJSONEnvelope,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";
import {
  createSettingsPool,
  loadBootstrapSettings,
  readRuntimeSettings,
} from "../../scripts/settings-core.mjs";
import {
  appendDataRequestEvent,
  createParticipantDataExportWorker,
} from "../engine/lifecycle-store.mjs";
import { queueOneParticipantDataNotification } from "../engine/participant-data-notifications.mjs";
import { createSigningProvider } from "../engine/signing-provider.mjs";
import { createIntegrationGatewayClient } from "./integration-gateway-client.mjs";
import {
  participantDataJobIsEligible,
  suppressObsoleteJobs,
  suppressOneObsoleteParticipantDataJob,
} from "./notification-lifecycle.mjs";
import {
  advanceOneRetentionLifecycle,
  expireOneParticipantDataRequest,
} from "./retention-worker.mjs";

const ENGINE_VERSION = "0.36.1";
const GENESIS_HASH = "0".repeat(64);
let stopping = false;

export async function runWorker() {
  const bootstrap = loadBootstrapSettings();
  const settings = await readRuntimeSettings({ bootstrap, scope: "engine" });
  const database = createSettingsPool(bootstrap);
  const pollMilliseconds = boundedPollMilliseconds(settings.ENGINE_WORKER_POLL_MS);
  const dispatchNotification = createIntegrationGatewayClient(settings);
  const signingProvider = createSigningProvider(settings);
  const dataExportWorker = createParticipantDataExportWorker(database, settings);
  const stop = () => { stopping = true; };
  stopping = false;
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  console.info(`VASI worker ${ENGINE_VERSION} started with deterministic lifecycle and outbox processing.`);
  try {
    while (!stopping) {
      try {
        await database.query(
          'delete from "vasi_engine"."actor_assertion_replay" where "expiresAt" < CURRENT_TIMESTAMP',
        );
        await recoverStaleJobs(database);
        await advanceOneLifecycle(database);
        await expireOneParticipantDataRequest(database);
        await suppressObsoleteJobs(database);
        await suppressOneObsoleteParticipantDataJob(database);
        await dataExportWorker.prepareOne();
        await queueOneParticipantDataNotification(
          database,
          settings.ENGINE_OUTBOX_ENCRYPTION_SECRET,
        );
        await advanceOneRetentionLifecycle(database, signingProvider);
        const job = await claimJob(database);
        if (job) {
          await deliverJob(
            database,
            job,
            dispatchNotification,
            settings.ENGINE_OUTBOX_ENCRYPTION_SECRET,
          );
        }
      } catch (error) {
        console.error("VASI worker poll failed", error?.code || "database_unavailable");
      }
      await delay(pollMilliseconds);
    }
  } finally {
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    await database.end();
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await runWorker();
}

export async function claimJob(databaseClient) {
  const result = await databaseClient.query(
    `with candidate as (
       select j."id" from "vasi_engine"."outbox_job" j
       left join "vasi_engine"."request_instance" r on r."id" = j."requestId"
       left join "vasi_engine"."participant_data_request" d
         on d."id" = j."participantDataRequestId"
       left join "vasi_engine"."participant_data_request_scope" s
         on s."requestId" = d."id" and s."tenantId" = j."tenantId"
       where j."status" in ('pending', 'participant_pending')
         and j."availableAt" <= CURRENT_TIMESTAMP
         and (
           (j."participantDataRequestId" is not null and (
             (j."notificationType" = 'participant_data.ready'
               and d."status" = 'ready' and s."status" = 'approved') or
             (j."notificationType" = 'participant_data.denied'
               and d."status" in ('ready', 'denied') and s."status" = 'denied') or
             (j."notificationType" = 'participant_data.preparation_failed'
               and d."status" = 'preparation_failed' and s."status" = 'approved') or
             (j."notificationType" = 'participant_data.expired'
               and d."status" = 'expired' and s."status" = 'approved')
           )) or
           (j."participantDataRequestId" is null and (
             r."id" is null or
             (j."notificationType" in ('request.issued', 'request.reminder') and
               r."status" in ('scheduled', 'issued', 'in_progress')) or
             (j."notificationType" = 'request.completed' and r."status" = 'completed') or
             (j."notificationType" is null and r."status" not in ('revoked', 'expired'))
           ))
         )
       order by j."availableAt", j."createdAt", j."id"
       limit 1 for update of j skip locked
     )
     update "vasi_engine"."outbox_job" j
     set "status" = 'running', "attempts" = j."attempts" + 1,
         "lockedAt" = CURRENT_TIMESTAMP, "lockedBy" = $1, "updatedAt" = CURRENT_TIMESTAMP
     from candidate where j."id" = candidate."id"
     returning j.*`,
    [`worker-${process.pid}`],
  );
  return result.rows[0];
}

export async function deliverJob(databaseClient, job, dispatch, encryptionSecret) {
  const startedAt = new Date();
  let delivery;
  try {
    if (job.jobType !== "notification") throw workerError("unsupported_job_type");
    if (!await participantDataJobIsEligible(databaseClient, job)) {
      delivery = {
        adapter: "engine",
        outcome: "suppressed",
        responseMetadata: {},
      };
    } else {
      const payload = decryptJSONEnvelope(job.payload?.envelope, encryptionSecret);
      if (hashCanonicalJSON(payload) !== job.payloadHash) throw workerError("outbox_payload_mismatch");
      delivery = await dispatch({
        attempt: job.attempts,
        id: job.id,
        idempotencyKey: job.idempotencyKey,
        payload,
        tenantId: job.tenantId,
      });
    }
  } catch (error) {
    delivery = {
      adapter: adapterName(job),
      errorCode: boundedErrorCode(error?.code),
      outcome: "failed",
      responseMetadata: {},
    };
  }
  const completedAt = new Date();
  const terminal = delivery.outcome !== "failed" || Number(job.attempts) >= Number(job.maxAttempts);
  const nextStatus = terminal
    ? (delivery.outcome === "failed" ? "failed" : "completed")
    : job.participantDataRequestId ? "participant_pending" : "pending";
  const nextAvailableAt = new Date(completedAt.getTime() + retryDelayMilliseconds(Number(job.attempts)));
  const client = await databaseClient.connect();
  try {
    await client.query("begin");
    await client.query(
      `insert into "vasi_engine"."notification_delivery_attempt"
        ("id", "jobId", "attempt", "adapter", "outcome", "errorCode", "responseMetadata",
         "startedAt", "completedAt")
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        randomUUID(),
        job.id,
        job.attempts,
        delivery.adapter,
        delivery.outcome,
        delivery.errorCode || null,
        delivery.responseMetadata || {},
        startedAt,
        completedAt,
      ],
    );
    await client.query(
      `update "vasi_engine"."outbox_job"
       set "status" = $2, "availableAt" = $3, "lockedAt" = null, "lockedBy" = null,
           "lastErrorCode" = $4, "completedAt" = $5, "result" = $6,
           "payload" = case when $7 then jsonb_build_object('redacted', true) else "payload" end,
           "updatedAt" = $5
       where "id" = $1`,
      [
        job.id,
        nextStatus,
        nextAvailableAt,
        delivery.errorCode || null,
        terminal ? completedAt : null,
        { adapter: delivery.adapter, outcome: delivery.outcome },
        terminal,
      ],
    );
    if (terminal && job.participantDataRequestId) {
      await appendParticipantDataNotificationResult(client, job, delivery, completedAt);
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function appendParticipantDataNotificationResult(client, job, delivery, completedAt) {
  const outcome = delivery.outcome === "delivered" ? "provider_accepted" : delivery.outcome;
  await appendDataRequestEvent(client, {
    actor: {
      authentication: { method: "service" },
      principalId: "vasi-worker",
      roles: ["service"],
    },
    commandId: `participant-data-notification:${job.id}:terminal`,
    createdAt: completedAt,
    eventType: `notification.${outcome}`,
    payload: {
      adapter: delivery.adapter,
      ...(delivery.errorCode ? { errorCode: delivery.errorCode } : {}),
      jobId: job.id,
      notificationType: job.notificationType,
      outcome,
    },
    requestId: job.participantDataRequestId,
    tenantId: job.tenantId,
  });
}

async function recoverStaleJobs(databaseClient) {
  await databaseClient.query(
    `update "vasi_engine"."outbox_job"
     set "status" = case when "participantDataRequestId" is null
           then 'pending' else 'participant_pending' end,
         "lockedAt" = null, "lockedBy" = null,
         "availableAt" = CURRENT_TIMESTAMP, "updatedAt" = CURRENT_TIMESTAMP
     where "status" = 'running' and "lockedAt" < CURRENT_TIMESTAMP - interval '10 minutes'`,
  );
}

async function advanceOneLifecycle(databaseClient) {
  const client = await databaseClient.connect();
  try {
    await client.query("begin");
    const result = await client.query(
      `select r."id" as "requestId", r."tenantId", r."status", r."scheduledFor", r."expiresAt",
              a."id" as "assignmentId"
       from "vasi_engine"."request_instance" r
       join "vasi_engine"."participant_assignment" a on a."requestId" = r."id"
       where (r."status" = 'scheduled' and r."scheduledFor" <= CURRENT_TIMESTAMP)
          or (r."status" in ('scheduled', 'issued', 'in_progress') and r."expiresAt" <= CURRENT_TIMESTAMP)
       order by case when r."expiresAt" <= CURRENT_TIMESTAMP then 0 else 1 end,
                r."expiresAt", r."scheduledFor", r."id"
       limit 1 for update of r, a skip locked`,
    );
    if (!result.rowCount) {
      await client.query("commit");
      return;
    }
    const row = result.rows[0];
    const now = new Date();
    const expired = new Date(row.expiresAt) <= now;
    const nextStatus = expired ? "expired" : "issued";
    await client.query(
      `update "vasi_engine"."request_instance" set "status" = $2 where "id" = $1`,
      [row.requestId, nextStatus],
    );
    await client.query(
      `update "vasi_engine"."participant_assignment" set "status" = $2 where "id" = $1`,
      [row.assignmentId, nextStatus],
    );
    await appendWorkerEvent(client, row, `request.${nextStatus}`, now);
    await client.query(
      `insert into "vasi_engine"."request_lifecycle_event"
        ("id", "tenantId", "requestId", "eventType", "actorPrincipalId", "idempotencyKey", "eventData", "createdAt")
       values ($1, $2, $3, $4, 'vasi-worker', $5, $6, $7)
       on conflict ("idempotencyKey") do nothing`,
      [
        randomUUID(),
        row.tenantId,
        row.requestId,
        `request.${nextStatus}`,
        `worker:${row.requestId}:${nextStatus}`,
        { previousStatus: row.status, resultingStatus: nextStatus },
        now,
      ],
    );
    if (expired) {
      await client.query(
        `update "vasi_engine"."outbox_job"
         set "status" = 'completed', "completedAt" = $2,
             "result" = '{"adapter":"engine","outcome":"suppressed","reason":"request_expired"}'::jsonb,
             "payload" = '{"redacted":true}'::jsonb, "updatedAt" = $2
         where "requestId" = $1 and "status" = 'pending'
           and "notificationType" in ('request.issued', 'request.reminder')`,
        [row.requestId, now],
      );
    }
    await client.query("commit");
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function appendWorkerEvent(client, row, eventType, receivedAt) {
  const head = await client.query(
    `select "lastSequence", "lastHash" from "vasi_engine"."evidence_chain_head"
     where "assignmentId" = $1 for update`,
    [row.assignmentId],
  );
  const sequence = Number(head.rows[0]?.lastSequence || 0) + 1;
  const previousHash = head.rows[0]?.lastHash || GENESIS_HASH;
  const eventId = randomUUID();
  const eventData = {
    actor: {
      authentication: { method: "service" },
      gatewaySessionId: "vasi-worker",
      principalId: "vasi-worker",
      roles: ["service"],
    },
    assignmentId: row.assignmentId,
    engineVersion: ENGINE_VERSION,
    eventId,
    eventType,
    payload: { previousStatus: row.status },
    previousHash,
    receivedAt: receivedAt.toISOString(),
    requestId: row.requestId,
    schema: "vasi-evidence-event/v1",
    sequence,
    tenantId: row.tenantId,
  };
  const eventHash = hashCanonicalJSON(eventData);
  await client.query(
    `insert into "vasi_engine"."evidence_event"
      ("id", "tenantId", "requestId", "assignmentId", "sequence", "eventType",
       "actorPrincipalId", "eventData", "previousHash", "eventHash", "receivedAt", "engineVersion")
     values ($1, $2, $3, $4, $5, $6, 'vasi-worker', $7, $8, $9, $10, $11)`,
    [
      eventId,
      row.tenantId,
      row.requestId,
      row.assignmentId,
      sequence,
      eventType,
      eventData,
      previousHash,
      eventHash,
      receivedAt,
      ENGINE_VERSION,
    ],
  );
  await client.query(
    `update "vasi_engine"."evidence_chain_head"
     set "lastSequence" = $2, "lastHash" = $3 where "assignmentId" = $1`,
    [row.assignmentId, sequence, eventHash],
  );
}

function retryDelayMilliseconds(attempt) {
  return Math.min(3_600_000, 30_000 * (2 ** Math.max(0, attempt - 1)));
}

function boundedPollMilliseconds(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1_000 || parsed > 60_000) {
    throw new Error("ENGINE_WORKER_POLL_MS must be between 1000 and 60000.");
  }
  return parsed;
}

function adapterName(job) {
  return job.jobType === "notification" ? "notification" : "worker";
}

function boundedErrorCode(value) {
  return typeof value === "string" && /^[a-z0-9_]{1,64}$/.test(value)
    ? value
    : "delivery_failed";
}

function workerError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
