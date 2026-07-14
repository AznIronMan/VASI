-- Independent retention horizons, legal holds, purge tombstones, and reviewed
-- participant data requests. Material audit rows remain append-only.

create table "vasi_engine"."retention_policy_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "name" text not null,
  "revision" integer not null check ("revision" > 0),
  "policy" jsonb not null,
  "policyHash" text not null check ("policyHash" ~ '^[a-f0-9]{64}$'),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "name", "revision")
);

create table "vasi_engine"."retention_policy_pointer" (
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "name" text not null,
  "activeRevisionId" text not null references "vasi_engine"."retention_policy_revision" ("id"),
  "revision" integer not null check ("revision" > 0),
  "updatedByPrincipalId" text not null,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("tenantId", "name")
);

create table "vasi_engine"."record_lifecycle_state" (
  "assignmentId" text primary key references "vasi_engine"."participant_assignment" ("id"),
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "policyRevisionId" text references "vasi_engine"."retention_policy_revision" ("id"),
  "policySnapshot" jsonb not null,
  "policyHash" text not null check ("policyHash" ~ '^[a-f0-9]{64}$'),
  "terminalAt" timestamptz not null,
  "contentExpiresAt" timestamptz,
  "historyExpiresAt" timestamptz,
  "archiveAt" timestamptz,
  "deleteAt" timestamptz,
  "contentStatus" text not null default 'active' check ("contentStatus" in ('active', 'expired')),
  "historyStatus" text not null default 'active' check ("historyStatus" in ('active', 'expired')),
  "evidenceStatus" text not null default 'active' check ("evidenceStatus" in ('active', 'archived', 'purge_due')),
  "lastEvaluatedAt" timestamptz,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  check ("deleteAt" is null or "archiveAt" is null or "deleteAt" >= "archiveAt")
);

create index "record_lifecycle_content_due_idx"
  on "vasi_engine"."record_lifecycle_state" ("contentExpiresAt", "assignmentId")
  where "contentStatus" = 'active' and "contentExpiresAt" is not null;
create index "record_lifecycle_history_due_idx"
  on "vasi_engine"."record_lifecycle_state" ("historyExpiresAt", "assignmentId")
  where "historyStatus" = 'active' and "historyExpiresAt" is not null;
create index "record_lifecycle_archive_due_idx"
  on "vasi_engine"."record_lifecycle_state" ("archiveAt", "assignmentId")
  where "evidenceStatus" = 'active' and "archiveAt" is not null;
create index "record_lifecycle_delete_due_idx"
  on "vasi_engine"."record_lifecycle_state" ("deleteAt", "assignmentId")
  where "evidenceStatus" <> 'purge_due' and "deleteAt" is not null;

create table "vasi_engine"."record_lifecycle_chain_head" (
  "assignmentId" text primary key,
  "lastSequence" bigint not null default 0 check ("lastSequence" >= 0),
  "lastHash" text not null check ("lastHash" ~ '^[a-f0-9]{64}$')
);

create table "vasi_engine"."record_lifecycle_event" (
  "id" text primary key,
  "tenantId" text not null,
  "requestId" text not null,
  "assignmentId" text not null,
  "sequence" bigint not null check ("sequence" > 0),
  "eventType" text not null check ("eventType" in (
    'policy.bound', 'terminal.anchored', 'content.expired', 'history.expired',
    'evidence.archived', 'purge.due', 'purge.blocked', 'record.purged',
    'hold.placed', 'hold.released'
  )),
  "actorPrincipalId" text not null,
  "source" text not null check ("source" in ('engine', 'owner', 'worker')),
  "commandId" text,
  "eventData" jsonb not null,
  "previousHash" text not null check ("previousHash" ~ '^[a-f0-9]{64}$'),
  "eventHash" text not null check ("eventHash" ~ '^[a-f0-9]{64}$'),
  "createdAt" timestamptz not null,
  unique ("assignmentId", "sequence"),
  unique ("assignmentId", "eventHash")
);

create unique index "record_lifecycle_event_command_idx"
  on "vasi_engine"."record_lifecycle_event" ("commandId") where "commandId" is not null;

create table "vasi_engine"."legal_hold" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null,
  "assignmentId" text not null,
  "caseReference" text not null,
  "reason" text not null,
  "placedByPrincipalId" text not null,
  "placementCommandId" text not null unique,
  "placedAt" timestamptz not null
);

create index "legal_hold_assignment_idx"
  on "vasi_engine"."legal_hold" ("tenantId", "assignmentId", "placedAt" desc);

create table "vasi_engine"."legal_hold_release" (
  "id" text primary key,
  "holdId" text not null unique references "vasi_engine"."legal_hold" ("id"),
  "reason" text not null,
  "releasedByPrincipalId" text not null,
  "releaseCommandId" text not null unique,
  "releasedAt" timestamptz not null
);

create table "vasi_engine"."retention_purge_tombstone" (
  "assignmentId" text primary key,
  "tenantId" text not null,
  "requestId" text not null,
  "manifestHash" text check ("manifestHash" is null or "manifestHash" ~ '^[a-f0-9]{64}$'),
  "evidenceHeadHash" text not null check ("evidenceHeadHash" ~ '^[a-f0-9]{64}$'),
  "lifecycleHeadHash" text not null check ("lifecycleHeadHash" ~ '^[a-f0-9]{64}$'),
  "policyHash" text not null check ("policyHash" ~ '^[a-f0-9]{64}$'),
  "tombstone" jsonb not null,
  "tombstoneHash" text not null unique check ("tombstoneHash" ~ '^[a-f0-9]{64}$'),
  "seal" jsonb not null,
  "purgedAt" timestamptz not null
);

create unique index "retention_purge_manifest_idx"
  on "vasi_engine"."retention_purge_tombstone" ("manifestHash") where "manifestHash" is not null;

create table "vasi_engine"."participant_data_request" (
  "id" text primary key,
  "requesterPrincipalId" text not null,
  "requesterEmail" text not null,
  "status" text not null check ("status" in (
    'pending_review', 'approved', 'partially_approved', 'denied', 'ready', 'expired', 'cancelled'
  )),
  "commandId" text not null unique,
  "requestedAt" timestamptz not null,
  "reviewCompletedAt" timestamptz,
  "expiresAt" timestamptz not null,
  "updatedAt" timestamptz not null
);

create index "participant_data_request_requester_idx"
  on "vasi_engine"."participant_data_request" ("requesterPrincipalId", "requestedAt" desc);

create table "vasi_engine"."participant_data_request_scope" (
  "requestId" text not null references "vasi_engine"."participant_data_request" ("id"),
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "status" text not null default 'pending_review' check ("status" in ('pending_review', 'approved', 'denied')),
  "matchedAssignmentIds" text[] not null,
  "reviewPolicy" jsonb,
  "reviewedByPrincipalId" text,
  "reviewCommandId" text unique,
  "reviewReason" text,
  "reviewedAt" timestamptz,
  primary key ("requestId", "tenantId"),
  check (
    ("status" = 'pending_review' and "reviewedAt" is null and "reviewedByPrincipalId" is null)
    or
    ("status" <> 'pending_review' and "reviewedAt" is not null and "reviewedByPrincipalId" is not null)
  )
);

create index "participant_data_request_scope_review_idx"
  on "vasi_engine"."participant_data_request_scope" ("tenantId", "status", "requestId");

create table "vasi_engine"."participant_data_request_chain_head" (
  "requestId" text primary key references "vasi_engine"."participant_data_request" ("id"),
  "lastSequence" bigint not null default 0 check ("lastSequence" >= 0),
  "lastHash" text not null check ("lastHash" ~ '^[a-f0-9]{64}$')
);

create table "vasi_engine"."participant_data_request_event" (
  "id" text primary key,
  "requestId" text not null references "vasi_engine"."participant_data_request" ("id"),
  "tenantId" text,
  "sequence" bigint not null check ("sequence" > 0),
  "eventType" text not null check ("eventType" in (
    'request.created', 'scope.approved', 'scope.denied', 'export.created',
    'export.opened', 'export.downloaded', 'export.expired', 'request.expired', 'request.cancelled'
  )),
  "actorPrincipalId" text not null,
  "commandId" text,
  "eventData" jsonb not null,
  "previousHash" text not null check ("previousHash" ~ '^[a-f0-9]{64}$'),
  "eventHash" text not null check ("eventHash" ~ '^[a-f0-9]{64}$'),
  "createdAt" timestamptz not null,
  unique ("requestId", "sequence"),
  unique ("requestId", "eventHash")
);

create unique index "participant_data_request_event_command_idx"
  on "vasi_engine"."participant_data_request_event" ("commandId") where "commandId" is not null;

create table "vasi_engine"."participant_data_export" (
  "id" text primary key,
  "requestId" text not null unique references "vasi_engine"."participant_data_request" ("id"),
  "profile" text not null,
  "mediaType" text not null,
  "filename" text not null,
  "byteLength" bigint not null check ("byteLength" > 0),
  "chunkCount" integer not null check ("chunkCount" > 0),
  "sha256" text not null check ("sha256" ~ '^[a-f0-9]{64}$'),
  "payloadHash" text not null check ("payloadHash" ~ '^[a-f0-9]{64}$'),
  "seal" jsonb not null,
  "createdAt" timestamptz not null,
  "expiresAt" timestamptz not null,
  "contentDeletedAt" timestamptz,
  check ("expiresAt" > "createdAt")
);

create table "vasi_engine"."participant_data_export_chunk" (
  "exportId" text not null references "vasi_engine"."participant_data_export" ("id"),
  "sequence" integer not null check ("sequence" >= 0),
  "byteLength" integer not null check ("byteLength" > 0),
  "sha256" text not null check ("sha256" ~ '^[a-f0-9]{64}$'),
  "bytes" bytea not null,
  primary key ("exportId", "sequence"),
  check (octet_length("bytes") = "byteLength")
);

create table "vasi_engine"."participant_data_export_access_event" (
  "id" text primary key,
  "requestId" text not null,
  "exportId" text not null,
  "accessType" text not null check ("accessType" in ('metadata', 'chunk')),
  "actorPrincipalId" text not null,
  "gatewaySessionId" text not null,
  "sequence" integer,
  "occurredAt" timestamptz not null
);

insert into "vasi_engine"."record_lifecycle_state" (
  "assignmentId", "tenantId", "requestId", "policySnapshot", "policyHash", "terminalAt",
  "contentExpiresAt", "historyExpiresAt", "archiveAt", "deleteAt"
)
select a."id", a."tenantId", a."requestId",
       '{"contentAccess":{"mode":"request_expiration"},"evidence":{"archiveAfterDays":365,"deleteAfterDays":null},"participantHistory":{"daysAfterTerminal":null},"schema":"vasi-retention-policy/v1"}'::jsonb,
       'd24d9895e50c8338053da78e1a0bdc8499a1fa5f1558cb5f40c1de493930abfe',
       coalesce(a."completedAt", r."completedAt", r."expiresAt"),
       r."expiresAt",
       null,
       coalesce(a."completedAt", r."completedAt", r."expiresAt") + interval '365 days',
       null
from "vasi_engine"."participant_assignment" a
join "vasi_engine"."request_instance" r on r."id" = a."requestId";

insert into "vasi_engine"."record_lifecycle_chain_head" ("assignmentId", "lastHash")
select "id", repeat('0', 64) from "vasi_engine"."participant_assignment";

create or replace function "vasi_engine"."reject_immutable_change"()
returns trigger language plpgsql as $$
declare
  purge_assignment text := nullif(current_setting('vasi_engine.retention_purge_assignment', true), '');
  purge_request text := nullif(current_setting('vasi_engine.retention_purge_request', true), '');
  purge_export text := nullif(current_setting('vasi_engine.participant_data_export_purge', true), '');
  old_data jsonb := to_jsonb(OLD);
begin
  if TG_OP = 'DELETE' and purge_assignment is not null and exists (
    select 1 from "vasi_engine"."retention_purge_tombstone"
    where "assignmentId" = purge_assignment
  ) then
    if TG_TABLE_NAME in (
      'evidence_access_event', 'evidence_export_artifact',
      'document_artifact_access_event', 'external_media_metadata_snapshot',
      'media_activity_summary_revision', 'media_event', 'media_event_batch',
      'activity_response', 'activity_response_revision', 'participant_response',
      'evidence_event', 'evidence_manifest'
    ) and old_data ->> 'assignmentId' = purge_assignment then
      return OLD;
    end if;
    if TG_TABLE_NAME = 'evidence_seal' and exists (
      select 1 from "vasi_engine"."evidence_manifest"
      where "id" = old_data ->> 'manifestId' and "assignmentId" = purge_assignment
    ) then
      return OLD;
    end if;
    if TG_TABLE_NAME = 'evidence_export_chunk' and exists (
      select 1 from "vasi_engine"."evidence_export_artifact"
      where "id" = old_data ->> 'exportArtifactId' and "assignmentId" = purge_assignment
    ) then
      return OLD;
    end if;
  end if;
  if TG_OP = 'DELETE' and purge_request is not null and exists (
    select 1 from "vasi_engine"."retention_purge_tombstone"
    where "requestId" = purge_request
  ) then
    if TG_TABLE_NAME in (
      'evidence_access_event', 'document_artifact_access_event',
      'external_media_metadata_snapshot', 'request_lifecycle_event'
    ) and old_data ->> 'requestId' = purge_request then
      return OLD;
    end if;
    if TG_TABLE_NAME = 'notification_delivery_attempt' and exists (
      select 1 from "vasi_engine"."outbox_job"
      where "id" = old_data ->> 'jobId' and "requestId" = purge_request
    ) then
      return OLD;
    end if;
  end if;
  if TG_OP = 'DELETE' and TG_TABLE_NAME = 'participant_data_export_chunk'
     and old_data ->> 'exportId' = purge_export and exists (
       select 1 from "vasi_engine"."participant_data_export"
       where "id" = purge_export and "expiresAt" <= CURRENT_TIMESTAMP
     ) then
    return OLD;
  end if;
  raise exception 'VASI immutable evidence records cannot be changed';
end;
$$;

create function "vasi_engine"."purge_record_for_retention"(
  purge_assignment_id text,
  expected_tombstone_hash text
) returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare
  lifecycle record;
  request_has_other_assignments boolean;
begin
  select * into lifecycle
  from "vasi_engine"."record_lifecycle_state"
  where "assignmentId" = purge_assignment_id
  for update;
  if not found then
    raise exception 'record lifecycle state is unavailable';
  end if;
  if lifecycle."evidenceStatus" <> 'purge_due'
     or lifecycle."deleteAt" is null
     or lifecycle."deleteAt" > CURRENT_TIMESTAMP then
    raise exception 'record is not due for retention purge';
  end if;
  if exists (
    select 1 from "vasi_engine"."legal_hold" h
    left join "vasi_engine"."legal_hold_release" r on r."holdId" = h."id"
    where h."assignmentId" = purge_assignment_id and r."id" is null
  ) then
    raise exception 'active legal hold blocks retention purge';
  end if;
  if exists (
    select 1
    from "vasi_engine"."participant_data_request_scope" s
    join "vasi_engine"."participant_data_request" r on r."id" = s."requestId"
    where purge_assignment_id = any(s."matchedAssignmentIds")
      and r."status" in ('pending_review', 'approved', 'partially_approved', 'ready')
      and r."expiresAt" > CURRENT_TIMESTAMP
  ) then
    raise exception 'active participant data request blocks retention purge';
  end if;
  if not exists (
    select 1 from "vasi_engine"."retention_purge_tombstone"
    where "assignmentId" = purge_assignment_id and "tombstoneHash" = expected_tombstone_hash
      and "tenantId" = lifecycle."tenantId" and "requestId" = lifecycle."requestId"
      and "policyHash" = lifecycle."policyHash"
  ) then
    raise exception 'sealed retention purge tombstone is missing';
  end if;

  perform set_config('vasi_engine.retention_purge_assignment', purge_assignment_id, true);

  delete from "vasi_engine"."evidence_access_event"
    where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."evidence_export_chunk" c
    using "vasi_engine"."evidence_export_artifact" a
    where c."exportArtifactId" = a."id" and a."assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."evidence_export_artifact" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."document_artifact_access_event"
    where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."evidence_seal" s
    using "vasi_engine"."evidence_manifest" m
    where s."manifestId" = m."id" and m."assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."evidence_manifest" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."external_media_metadata_snapshot"
    where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."media_activity_summary_revision" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."media_event" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."media_event_batch" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."activity_response" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."activity_response_revision" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."participant_response" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."interaction_session" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."activity_instance" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."evidence_event" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."evidence_chain_head" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."record_lifecycle_state" where "assignmentId" = purge_assignment_id;
  delete from "vasi_engine"."participant_assignment" where "id" = purge_assignment_id;

  select exists (
    select 1 from "vasi_engine"."participant_assignment" where "requestId" = lifecycle."requestId"
  ) into request_has_other_assignments;
  if not request_has_other_assignments and not exists (
    select 1 from "vasi_engine"."request_instance" where "reissuedFromRequestId" = lifecycle."requestId"
  ) then
    perform set_config('vasi_engine.retention_purge_request', lifecycle."requestId", true);
    delete from "vasi_engine"."evidence_access_event"
      where "requestId" = lifecycle."requestId";
    delete from "vasi_engine"."document_artifact_access_event"
      where "requestId" = lifecycle."requestId";
    delete from "vasi_engine"."external_media_metadata_snapshot"
      where "requestId" = lifecycle."requestId";
    delete from "vasi_engine"."notification_delivery_attempt" a
      using "vasi_engine"."outbox_job" j
      where a."jobId" = j."id" and j."requestId" = lifecycle."requestId";
    delete from "vasi_engine"."outbox_job" where "requestId" = lifecycle."requestId";
    delete from "vasi_engine"."request_lifecycle_event" where "requestId" = lifecycle."requestId";
    delete from "vasi_engine"."request_instance" where "id" = lifecycle."requestId";
  end if;
end;
$$;

create function "vasi_engine"."expire_participant_data_export"(purge_export_id text)
returns void
language plpgsql security definer set search_path = pg_catalog as $$
declare
  export_row record;
begin
  select * into export_row from "vasi_engine"."participant_data_export"
  where "id" = purge_export_id for update;
  if not found then
    raise exception 'participant data export is unavailable';
  end if;
  if export_row."contentDeletedAt" is not null then
    return;
  end if;
  if export_row."expiresAt" > CURRENT_TIMESTAMP then
    raise exception 'participant data export is not expired';
  end if;
  perform set_config('vasi_engine.participant_data_export_purge', purge_export_id, true);
  delete from "vasi_engine"."participant_data_export_chunk" where "exportId" = purge_export_id;
  update "vasi_engine"."participant_data_export"
    set "contentDeletedAt" = CURRENT_TIMESTAMP where "id" = purge_export_id;
  update "vasi_engine"."participant_data_request"
    set "status" = 'expired', "updatedAt" = CURRENT_TIMESTAMP
    where "id" = export_row."requestId" and "status" <> 'cancelled';
end;
$$;

revoke all on function "vasi_engine"."purge_record_for_retention"(text, text) from PUBLIC;
revoke all on function "vasi_engine"."expire_participant_data_export"(text) from PUBLIC;

create function "vasi_engine"."participant_data_export_change_guard"()
returns trigger language plpgsql as $$
begin
  if TG_OP = 'DELETE' then
    raise exception 'VASI participant data export metadata cannot be deleted';
  end if;
  if nullif(current_setting('vasi_engine.participant_data_export_purge', true), '') = OLD."id"
     and OLD."expiresAt" <= CURRENT_TIMESTAMP
     and OLD."contentDeletedAt" is null and NEW."contentDeletedAt" is not null
     and (to_jsonb(OLD) - 'contentDeletedAt') = (to_jsonb(NEW) - 'contentDeletedAt') then
    return NEW;
  end if;
  raise exception 'VASI participant data export metadata is immutable';
end;
$$;

create trigger "retention_policy_revision_immutable"
  before update or delete on "vasi_engine"."retention_policy_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "record_lifecycle_event_immutable"
  before update or delete on "vasi_engine"."record_lifecycle_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "legal_hold_immutable"
  before update or delete on "vasi_engine"."legal_hold"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "legal_hold_release_immutable"
  before update or delete on "vasi_engine"."legal_hold_release"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "retention_purge_tombstone_immutable"
  before update or delete on "vasi_engine"."retention_purge_tombstone"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "participant_data_request_event_immutable"
  before update or delete on "vasi_engine"."participant_data_request_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "participant_data_export_change_guard"
  before update or delete on "vasi_engine"."participant_data_export"
  for each row execute function "vasi_engine"."participant_data_export_change_guard"();
create trigger "participant_data_export_chunk_immutable"
  before update or delete on "vasi_engine"."participant_data_export_chunk"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "participant_data_export_access_event_immutable"
  before update or delete on "vasi_engine"."participant_data_export_access_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
