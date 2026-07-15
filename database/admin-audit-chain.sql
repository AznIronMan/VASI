-- Make gateway identity-administration evidence append-only and hash chained.
-- Existing runtimes remain compatible because the insert trigger supplies every
-- new chain field when older INSERT statements omit them.

alter table "vasi_admin_audit"
  drop constraint if exists "vasi_admin_audit_actorUserId_fkey",
  drop constraint if exists "vasi_admin_audit_targetUserId_fkey";

alter table "vasi_admin_audit"
  add column "commandId" text,
  add column "phase" text,
  add column "requestId" text,
  add column "actorSessionId" text,
  add column "ipAddress" text,
  add column "userAgent" text,
  add column "sequence" bigint,
  add column "previousHash" text,
  add column "canonicalPayload" text,
  add column "eventHash" text;

update "vasi_admin_audit"
set "commandId" = "id",
    "phase" = 'event',
    "requestId" = "id";

create table "vasi_admin_audit_chain_head" (
  "id" smallint primary key check ("id" = 1),
  "lastSequence" bigint not null check ("lastSequence" >= 0),
  "lastHash" text not null check ("lastHash" ~ '^[a-f0-9]{64}$'),
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP
);

insert into "vasi_admin_audit_chain_head" ("id", "lastSequence", "lastHash")
values (1, 0, repeat('0', 64));

do $$
declare
  audit record;
  canonical_payload text;
  event_hash text;
  previous_hash text := repeat('0', 64);
  next_sequence bigint := 0;
begin
  for audit in
    select * from "vasi_admin_audit" order by "createdAt", "id"
  loop
    next_sequence := next_sequence + 1;
    canonical_payload := jsonb_build_object(
      'action', audit."action",
      'actorSessionId', audit."actorSessionId",
      'actorUserId', audit."actorUserId",
      'commandId', audit."commandId",
      'createdAt', audit."createdAt",
      'id', audit."id",
      'ipAddress', audit."ipAddress",
      'metadata', audit."metadata",
      'phase', audit."phase",
      'requestId', audit."requestId",
      'targetUserId', audit."targetUserId",
      'userAgent', audit."userAgent"
    )::text;
    event_hash := encode(
      sha256(convert_to(previous_hash || canonical_payload, 'UTF8')),
      'hex'
    );

    update "vasi_admin_audit"
    set "sequence" = next_sequence,
        "previousHash" = previous_hash,
        "canonicalPayload" = canonical_payload,
        "eventHash" = event_hash
    where "id" = audit."id";

    previous_hash := event_hash;
  end loop;

  update "vasi_admin_audit_chain_head"
  set "lastSequence" = next_sequence,
      "lastHash" = previous_hash,
      "updatedAt" = CURRENT_TIMESTAMP
  where "id" = 1;
end;
$$;

alter table "vasi_admin_audit"
  alter column "commandId" set not null,
  alter column "phase" set not null,
  alter column "requestId" set not null,
  alter column "sequence" set not null,
  alter column "previousHash" set not null,
  alter column "canonicalPayload" set not null,
  alter column "eventHash" set not null,
  add constraint "vasi_admin_audit_action_bounded"
    check (length("action") between 1 and 128),
  add constraint "vasi_admin_audit_command_bounded"
    check (length("commandId") between 1 and 128),
  add constraint "vasi_admin_audit_phase_valid"
    check ("phase" in ('event', 'started', 'succeeded', 'failed', 'ambiguous')),
  add constraint "vasi_admin_audit_request_bounded"
    check (length("requestId") between 1 and 128),
  add constraint "vasi_admin_audit_session_bounded"
    check ("actorSessionId" is null or length("actorSessionId") between 1 and 128),
  add constraint "vasi_admin_audit_ip_bounded"
    check ("ipAddress" is null or length("ipAddress") between 1 and 512),
  add constraint "vasi_admin_audit_user_agent_bounded"
    check ("userAgent" is null or length("userAgent") between 1 and 512),
  add constraint "vasi_admin_audit_metadata_object"
    check (jsonb_typeof("metadata") = 'object' and pg_column_size("metadata") <= 16384),
  add constraint "vasi_admin_audit_sequence_positive"
    check ("sequence" > 0),
  add constraint "vasi_admin_audit_previous_hash_valid"
    check ("previousHash" ~ '^[a-f0-9]{64}$'),
  add constraint "vasi_admin_audit_payload_bounded"
    check (length("canonicalPayload") between 2 and 65536),
  add constraint "vasi_admin_audit_event_hash_valid"
    check ("eventHash" ~ '^[a-f0-9]{64}$');

create unique index "vasi_admin_audit_sequence_idx"
  on "vasi_admin_audit" ("sequence");

create unique index "vasi_admin_audit_event_hash_idx"
  on "vasi_admin_audit" ("eventHash");

create unique index "vasi_admin_audit_command_phase_idx"
  on "vasi_admin_audit" ("commandId", "phase")
  where "phase" <> 'event';

create index "vasi_admin_audit_command_idx"
  on "vasi_admin_audit" ("commandId", "sequence");

create function "vasi_admin_audit_append"()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
declare
  head record;
begin
  perform pg_advisory_xact_lock(hashtextextended('vasi:admin-audit-chain', 0));
  select "lastSequence", "lastHash" into head
  from "vasi_admin_audit_chain_head" where "id" = 1 for update;
  if not found then
    raise exception 'VASI administrator audit chain head is unavailable.';
  end if;

  NEW."commandId" := coalesce(nullif(NEW."commandId", ''), NEW."id");
  NEW."phase" := coalesce(nullif(NEW."phase", ''), 'event');
  NEW."requestId" := coalesce(nullif(NEW."requestId", ''), NEW."id");
  NEW."sequence" := head."lastSequence" + 1;
  NEW."previousHash" := head."lastHash";
  NEW."canonicalPayload" := jsonb_build_object(
    'action', NEW."action",
    'actorSessionId', NEW."actorSessionId",
    'actorUserId', NEW."actorUserId",
    'commandId', NEW."commandId",
    'createdAt', NEW."createdAt",
    'id', NEW."id",
    'ipAddress', NEW."ipAddress",
    'metadata', NEW."metadata",
    'phase', NEW."phase",
    'requestId', NEW."requestId",
    'targetUserId', NEW."targetUserId",
    'userAgent', NEW."userAgent"
  )::text;
  NEW."eventHash" := encode(
    sha256(convert_to(NEW."previousHash" || NEW."canonicalPayload", 'UTF8')),
    'hex'
  );

  update "vasi_admin_audit_chain_head"
  set "lastSequence" = NEW."sequence",
      "lastHash" = NEW."eventHash",
      "updatedAt" = CURRENT_TIMESTAMP
  where "id" = 1;
  return NEW;
end;
$$;

create trigger "vasi_admin_audit_append"
  before insert on "vasi_admin_audit"
  for each row execute function "vasi_admin_audit_append"();

create function "vasi_admin_audit_immutable"()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  raise exception 'VASI administrator audit events are immutable.';
end;
$$;

create trigger "vasi_admin_audit_immutable_rows"
  before update or delete on "vasi_admin_audit"
  for each row execute function "vasi_admin_audit_immutable"();

create trigger "vasi_admin_audit_immutable_truncate"
  before truncate on "vasi_admin_audit"
  for each statement execute function "vasi_admin_audit_immutable"();

revoke all on function "vasi_admin_audit_append"() from PUBLIC;
revoke all on function "vasi_admin_audit_immutable"() from PUBLIC;

comment on table "vasi_admin_audit" is
  'Immutable, serialized gateway identity-administration audit chain.';
