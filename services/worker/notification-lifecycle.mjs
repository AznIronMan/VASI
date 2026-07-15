import { appendDataRequestEvent } from "../engine/lifecycle-store.mjs";

export async function suppressObsoleteJobs(databaseClient) {
  await databaseClient.query(
    `update "vasi_engine"."outbox_job" j
     set "status" = 'completed', "completedAt" = CURRENT_TIMESTAMP,
         "result" = jsonb_build_object(
           'adapter', 'engine',
           'outcome', 'suppressed',
           'reason', case r."status"
             when 'completed' then 'request_completed'
             when 'revoked' then 'request_revoked'
             else 'request_expired'
           end
         ),
         "payload" = '{"redacted":true}'::jsonb, "updatedAt" = CURRENT_TIMESTAMP
     from "vasi_engine"."request_instance" r
     where j."requestId" = r."id" and j."status" = 'pending'
       and j."notificationType" in ('request.issued', 'request.reminder')
       and r."status" in ('completed', 'revoked', 'expired')`,
  );
}

export async function suppressOneObsoleteParticipantDataJob(database) {
  return transaction(database, async (client) => {
    const result = await client.query(
      `select j."id", j."notificationType", j."tenantId", j."participantDataRequestId",
              r."status" as "requestStatus", s."status" as "scopeStatus"
       from "vasi_engine"."outbox_job" j
       join "vasi_engine"."participant_data_request" r
         on r."id" = j."participantDataRequestId"
       left join "vasi_engine"."participant_data_request_scope" s
         on s."requestId" = r."id" and s."tenantId" = j."tenantId"
       where j."status" = 'participant_pending' and (
         (j."notificationType" = 'participant_data.ready'
           and (r."status" <> 'ready' or s."status" <> 'approved')) or
         (j."notificationType" = 'participant_data.denied'
           and (r."status" not in ('ready', 'denied') or s."status" <> 'denied')) or
         (j."notificationType" = 'participant_data.preparation_failed'
           and (r."status" <> 'preparation_failed' or s."status" <> 'approved')) or
         (j."notificationType" = 'participant_data.expired'
           and (r."status" <> 'expired' or s."status" <> 'approved'))
       )
       order by j."createdAt", j."id"
       limit 1 for update of j skip locked`,
    );
    if (!result.rowCount) return null;
    const job = result.rows[0];
    const now = new Date();
    await client.query(
      `update "vasi_engine"."outbox_job"
       set "status" = 'completed', "completedAt" = $2,
           "result" = '{"adapter":"engine","outcome":"suppressed","reason":"participant_data_status_changed"}'::jsonb,
           "payload" = '{"redacted":true}'::jsonb, "updatedAt" = $2
       where "id" = $1`,
      [job.id, now],
    );
    await appendDataRequestEvent(client, {
      actor: serviceActor(),
      commandId: `participant-data-notification:${job.id}:terminal`,
      createdAt: now,
      eventType: "notification.suppressed",
      payload: {
        adapter: "engine",
        jobId: job.id,
        notificationType: job.notificationType,
        outcome: "suppressed",
        reason: "participant_data_status_changed",
      },
      requestId: job.participantDataRequestId,
      tenantId: job.tenantId,
    });
    return Object.freeze({ jobId: job.id, outcome: "suppressed" });
  });
}

export async function participantDataJobIsEligible(database, job) {
  if (!job.participantDataRequestId) return true;
  const result = await database.query(
    `select r."status" as "requestStatus", s."status" as "scopeStatus"
     from "vasi_engine"."participant_data_request" r
     left join "vasi_engine"."participant_data_request_scope" s
       on s."requestId" = r."id" and s."tenantId" = $2
     where r."id" = $1`,
    [job.participantDataRequestId, job.tenantId],
  );
  if (!result.rowCount) return false;
  const row = result.rows[0];
  if (job.notificationType === "participant_data.ready") {
    return row.requestStatus === "ready" && row.scopeStatus === "approved";
  }
  if (job.notificationType === "participant_data.denied") {
    return ["ready", "denied"].includes(row.requestStatus) && row.scopeStatus === "denied";
  }
  if (job.notificationType === "participant_data.preparation_failed") {
    return row.requestStatus === "preparation_failed" && row.scopeStatus === "approved";
  }
  if (job.notificationType === "participant_data.expired") {
    return row.requestStatus === "expired" && row.scopeStatus === "approved";
  }
  return false;
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
