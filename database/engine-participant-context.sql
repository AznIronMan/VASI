-- Privacy-bounded, browser-reported participant context snapshots.

create table "vasi_engine"."participant_context_snapshot" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id") on delete cascade,
  "requestId" text not null references "vasi_engine"."request_instance" ("id") on delete cascade,
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id") on delete cascade,
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id") on delete cascade,
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id") on delete cascade,
  "contextSessionId" text not null,
  "sequence" integer not null check ("sequence" between 1 and 64),
  "purpose" text not null check ("purpose" in ('presentation', 'save', 'submission')),
  "schema" text not null check ("schema" = 'vasi-participant-context/v1'),
  "actorPrincipalId" text not null,
  "gatewaySessionId" text not null,
  "snapshot" jsonb not null,
  "requestContext" jsonb,
  "payloadHash" text not null check ("payloadHash" ~ '^[a-f0-9]{64}$'),
  "receivedAt" timestamptz not null,
  unique ("activityInstanceId", "contextSessionId", "sequence")
);

create index "participant_context_snapshot_assignment_idx"
  on "vasi_engine"."participant_context_snapshot"
    ("assignmentId", "activityInstanceId", "contextSessionId", "sequence");

create or replace function "vasi_engine"."reject_participant_context_change"()
returns trigger language plpgsql as $$
declare
  purge_assignment text := nullif(current_setting('vasi_engine.retention_purge_assignment', true), '');
begin
  if TG_OP = 'DELETE' and purge_assignment is not null
     and OLD."assignmentId" = purge_assignment
     and exists (
       select 1 from "vasi_engine"."retention_purge_tombstone"
       where "assignmentId" = purge_assignment
     ) then
    return OLD;
  end if;
  raise exception 'VASI participant context evidence is immutable';
end;
$$;

create trigger "participant_context_snapshot_immutable"
  before update or delete on "vasi_engine"."participant_context_snapshot"
  for each row execute function "vasi_engine"."reject_participant_context_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
