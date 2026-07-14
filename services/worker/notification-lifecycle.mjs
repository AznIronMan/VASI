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
