-- Explicit notification purpose supports lifecycle-safe suppression, bounded
-- owner status, and privacy-bounded evidence without decrypting message data.

alter table "vasi_engine"."outbox_job"
  add column "notificationType" text;

update "vasi_engine"."outbox_job"
set "notificationType" = case
  when "idempotencyKey" like '%:issued' then 'request.issued'
  when "idempotencyKey" like '%:completed' then 'request.completed'
  when "idempotencyKey" like '%:reminder:%'
    or "idempotencyKey" like '%:manual-reminder:%' then 'request.reminder'
  else null
end
where "jobType" = 'notification' and "notificationType" is null;

alter table "vasi_engine"."outbox_job"
  add constraint "outbox_job_notification_type_check"
  check (
    "notificationType" is null or
    "notificationType" in ('request.issued', 'request.reminder', 'request.completed')
  );

create index "outbox_job_request_notification_idx"
  on "vasi_engine"."outbox_job" ("tenantId", "requestId", "notificationType", "createdAt" desc)
  where "jobType" = 'notification';

-- Productized gateway attempts were added after the original retention purge
-- function. Keep them immutable during normal operation while allowing the
-- existing tombstone-authorized request purge to remove them before their
-- parent outbox job.
create function "vasi_engine"."integration_gateway_attempt_change_guard"()
returns trigger language plpgsql as $$
declare
  purge_request text := nullif(current_setting('vasi_engine.retention_purge_request', true), '');
begin
  if TG_OP = 'DELETE' and purge_request is not null and exists (
    select 1 from "vasi_engine"."retention_purge_tombstone"
    where "requestId" = purge_request
  ) and exists (
    select 1 from "vasi_engine"."outbox_job"
    where "id" = OLD."jobId" and "requestId" = purge_request
  ) then
    return OLD;
  end if;
  raise exception 'VASI immutable integration gateway attempts cannot be changed';
end;
$$;

drop trigger "integration_gateway_attempt_immutable"
  on "vasi_engine"."integration_gateway_attempt";
create trigger "integration_gateway_attempt_immutable"
  before update or delete on "vasi_engine"."integration_gateway_attempt"
  for each row execute function "vasi_engine"."integration_gateway_attempt_change_guard"();

create function "vasi_engine"."purge_integration_gateway_attempts_for_outbox"()
returns trigger language plpgsql as $$
declare
  purge_request text := nullif(current_setting('vasi_engine.retention_purge_request', true), '');
begin
  if TG_OP = 'DELETE' and purge_request is not null
     and OLD."requestId" = purge_request and exists (
       select 1 from "vasi_engine"."retention_purge_tombstone"
       where "requestId" = purge_request
     ) then
    delete from "vasi_engine"."integration_gateway_attempt"
      where "jobId" = OLD."id";
  end if;
  return OLD;
end;
$$;

create trigger "outbox_job_retention_gateway_cleanup"
  before delete on "vasi_engine"."outbox_job"
  for each row execute function "vasi_engine"."purge_integration_gateway_attempts_for_outbox"();

revoke all on function "vasi_engine"."integration_gateway_attempt_change_guard"() from PUBLIC;
revoke all on function "vasi_engine"."purge_integration_gateway_attempts_for_outbox"() from PUBLIC;

revoke all on all tables in schema "vasi_engine" from PUBLIC;
