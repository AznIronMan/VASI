-- Privacy-bounded activity presence events and deterministic duration summaries.

create table "vasi_engine"."activity_interaction_event_batch" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id") on delete cascade,
  "requestId" text not null references "vasi_engine"."request_instance" ("id") on delete cascade,
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id") on delete cascade,
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id") on delete cascade,
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id") on delete cascade,
  "telemetrySessionId" text not null,
  "actorPrincipalId" text not null,
  "eventCount" integer not null check ("eventCount" between 1 and 100),
  "payloadHash" text not null check ("payloadHash" ~ '^[a-f0-9]{64}$'),
  "receivedAt" timestamptz not null
);

create table "vasi_engine"."activity_interaction_event" (
  "batchId" text not null references "vasi_engine"."activity_interaction_event_batch" ("id") on delete cascade,
  "id" text not null,
  "tenantId" text not null references "vasi_engine"."tenant" ("id") on delete cascade,
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id") on delete cascade,
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id") on delete cascade,
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id") on delete cascade,
  "telemetrySessionId" text not null,
  "sequence" integer not null check ("sequence" between 1 and 100000),
  "eventType" text not null check ("eventType" in (
    'presented', 'visible', 'hidden', 'focus', 'blur', 'heartbeat', 'interaction', 'disconnect'
  )),
  "monotonicMs" bigint not null check ("monotonicMs" between 0 and 604800000),
  "eventData" jsonb not null,
  "receivedAt" timestamptz not null,
  primary key ("batchId", "id"),
  unique ("activityInstanceId", "telemetrySessionId", "id"),
  unique ("activityInstanceId", "telemetrySessionId", "sequence")
);

create index "activity_interaction_event_activity_idx"
  on "vasi_engine"."activity_interaction_event"
    ("assignmentId", "activityInstanceId", "telemetrySessionId", "sequence");

create table "vasi_engine"."activity_interaction_summary_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id") on delete cascade,
  "requestId" text not null references "vasi_engine"."request_instance" ("id") on delete cascade,
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id") on delete cascade,
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id") on delete cascade,
  "revision" integer not null check ("revision" > 0),
  "policy" jsonb not null,
  "summary" jsonb not null,
  "summaryHash" text not null check ("summaryHash" ~ '^[a-f0-9]{64}$'),
  "calculatedAt" timestamptz not null,
  unique ("activityInstanceId", "revision")
);

create or replace function "vasi_engine"."reject_activity_interaction_change"()
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
  raise exception 'VASI activity interaction evidence is immutable';
end;
$$;

create trigger "activity_interaction_event_batch_immutable"
  before update or delete on "vasi_engine"."activity_interaction_event_batch"
  for each row execute function "vasi_engine"."reject_activity_interaction_change"();
create trigger "activity_interaction_event_immutable"
  before update or delete on "vasi_engine"."activity_interaction_event"
  for each row execute function "vasi_engine"."reject_activity_interaction_change"();
create trigger "activity_interaction_summary_revision_immutable"
  before update or delete on "vasi_engine"."activity_interaction_summary_revision"
  for each row execute function "vasi_engine"."reject_activity_interaction_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
