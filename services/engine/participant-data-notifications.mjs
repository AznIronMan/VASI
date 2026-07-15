import { randomUUID } from "node:crypto";

import {
  encryptJSONEnvelope,
  hashCanonicalJSON,
} from "../../packages/engine-crypto/index.mjs";
import { requireNotificationType } from "../../packages/engine-domain/notifications.mjs";
import { appendDataRequestEvent } from "./lifecycle-store.mjs";

export async function queueOneParticipantDataNotification(
  database,
  encryptionSecret,
  now = new Date(),
) {
  return transaction(database, async (client) => {
    const result = await client.query(
      `select r."id" as "requestId", r."requesterEmail", r."status" as "requestStatus",
              r."reviewCompletedAt", s."tenantId", s."status" as "scopeStatus",
              t."name" as "tenantName", e."id" as "exportId", e."expiresAt" as "exportExpiresAt",
              notification."notificationType"
       from "vasi_engine"."participant_data_request" r
       join "vasi_engine"."participant_data_request_scope" s on s."requestId" = r."id"
       join "vasi_engine"."tenant" t on t."id" = s."tenantId"
       left join "vasi_engine"."participant_data_export" e on e."requestId" = r."id"
       cross join lateral (
         select case
           when r."status" = 'ready' and s."status" = 'approved'
             then 'participant_data.ready'
           when r."status" in ('ready', 'denied') and s."status" = 'denied'
             then 'participant_data.denied'
           when r."status" = 'preparation_failed' and s."status" = 'approved'
             then 'participant_data.preparation_failed'
           when r."status" = 'expired' and s."status" = 'approved' and e."id" is not null
             then 'participant_data.expired'
           else null
         end as "notificationType"
       ) notification
       where notification."notificationType" is not null
         and not exists (
           select 1 from "vasi_engine"."outbox_job" j
           where j."idempotencyKey" = concat(
             'participant-data:', r."id", ':', s."tenantId", ':', notification."notificationType"
           )
         )
       order by coalesce(r."reviewCompletedAt", r."updatedAt"), r."id", s."tenantId"
       limit 1 for update of r skip locked`,
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    const notificationType = requireNotificationType(row.notificationType);
    const jobId = randomUUID();
    const idempotencyKey = `participant-data:${row.requestId}:${row.tenantId}:${notificationType}`;
    const payload = participantDataNotificationPayload(row, notificationType);
    const envelope = encryptJSONEnvelope(payload, encryptionSecret);
    await client.query(
      `insert into "vasi_engine"."outbox_job"
        ("id", "jobType", "notificationType", "tenantId", "participantDataRequestId",
         "idempotencyKey", "payload", "payloadHash", "status", "availableAt")
       values ($1, 'notification', $2, $3, $4, $5, $6, $7, 'participant_pending', $8)
       on conflict ("idempotencyKey") where "idempotencyKey" is not null do nothing`,
      [
        jobId,
        notificationType,
        row.tenantId,
        row.requestId,
        idempotencyKey,
        { envelope },
        hashCanonicalJSON(payload),
        now,
      ],
    );
    await appendDataRequestEvent(client, {
      actor: serviceActor(),
      commandId: `participant-data-notification:${jobId}:queued`,
      createdAt: now,
      eventType: "notification.queued",
      payload: {
        jobId,
        notificationType,
        purpose: "participant_data_status",
      },
      requestId: row.requestId,
      tenantId: row.tenantId,
    });
    return Object.freeze({
      jobId,
      notificationType,
      requestId: row.requestId,
      tenantId: row.tenantId,
    });
  });
}

function participantDataNotificationPayload(row, notificationType) {
  return Object.freeze({
    eventType: notificationType,
    ...(row.exportExpiresAt ? { expiresAt: new Date(row.exportExpiresAt).toISOString() } : {}),
    participantPath: "/workspace",
    recipient: row.requesterEmail,
    requestStatus: row.requestStatus,
    schema: "vasi-participant-data-notification/v1",
    tenant: { id: row.tenantId, name: row.tenantName },
  });
}

function serviceActor() {
  return {
    authentication: { method: "service" },
    principalId: "vasi-worker",
    roles: ["service"],
  };
}

async function transaction(database, callback) {
  const client = await database.connect();
  try {
    await client.query("begin");
    const result = await callback(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
