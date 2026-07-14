-- Provider-hosted media descriptors, browser telemetry, and deterministic duration summaries.

alter table "vasi_engine"."workflow_revision"
  drop constraint "workflow_revision_activityType_check",
  drop constraint "workflow_revision_responseMode_check",
  add constraint "workflow_revision_activityType_check" check ("activityType" in (
    'terms_response', 'approval', 'single_choice', 'multiple_choice', 'free_form',
    'electronic_signature', 'document_review', 'questionnaire', 'external_media'
  )),
  add constraint "workflow_revision_responseMode_check" check ("responseMode" in (
    'acknowledgement', 'yes_no', 'approval', 'single_choice', 'multiple_choice',
    'free_form', 'electronic_signature', 'document_review', 'questionnaire', 'external_media'
  ));

create table "vasi_engine"."external_media_descriptor" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "workflowRevisionId" text not null references "vasi_engine"."workflow_revision" ("id"),
  "activityId" text not null,
  "provider" text not null check ("provider" in (
    'youtube', 'vimeo', 'sharepoint', 'google_drive', 'dropbox', 'generic', 'external_link'
  )),
  "itemId" text not null,
  "sourceUrl" text not null,
  "embedUrl" text,
  "capability" text not null check ("capability" in (
    'instrumented_player', 'version_aware_preview', 'generic_embed', 'external_link'
  )),
  "adapterId" text not null,
  "adapterVersion" text not null,
  "descriptor" jsonb not null,
  "descriptorHash" text not null check ("descriptorHash" ~ '^[a-f0-9]{64}$'),
  "boundAt" timestamptz not null,
  unique ("workflowRevisionId", "activityId")
);

create table "vasi_engine"."external_media_metadata_snapshot" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "descriptorId" text not null references "vasi_engine"."external_media_descriptor" ("id"),
  "requestId" text references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text references "vasi_engine"."participant_assignment" ("id"),
  "phase" text not null check ("phase" in ('publish', 'issue', 'participant_start', 'completion')),
  "source" text not null check ("source" in ('tenant_supplied', 'provider_api', 'browser_observed')),
  "availability" text not null check ("availability" in (
    'configured', 'available', 'access_denied', 'blocked', 'removed', 'error', 'unknown'
  )),
  "metadata" jsonb not null,
  "metadataHash" text not null check ("metadataHash" ~ '^[a-f0-9]{64}$'),
  "capturedAt" timestamptz not null,
  unique ("descriptorId", "assignmentId", "phase", "source", "availability")
);

create table "vasi_engine"."media_event_batch" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id"),
  "descriptorId" text not null references "vasi_engine"."external_media_descriptor" ("id"),
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id"),
  "telemetrySessionId" text not null,
  "actorPrincipalId" text not null,
  "eventCount" integer not null check ("eventCount" between 1 and 100),
  "payloadHash" text not null check ("payloadHash" ~ '^[a-f0-9]{64}$'),
  "receivedAt" timestamptz not null
);

create table "vasi_engine"."media_event" (
  "batchId" text not null references "vasi_engine"."media_event_batch" ("id"),
  "id" text not null,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id"),
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id"),
  "telemetrySessionId" text not null,
  "sequence" integer not null check ("sequence" > 0),
  "eventType" text not null,
  "monotonicMs" bigint not null check ("monotonicMs" >= 0),
  "eventData" jsonb not null,
  "receivedAt" timestamptz not null,
  primary key ("batchId", "id"),
  unique ("activityInstanceId", "telemetrySessionId", "sequence")
);

create index "media_event_activity_idx"
  on "vasi_engine"."media_event" ("assignmentId", "activityInstanceId", "telemetrySessionId", "sequence");

create table "vasi_engine"."media_activity_summary_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id"),
  "revision" integer not null check ("revision" > 0),
  "policy" jsonb not null,
  "summary" jsonb not null,
  "summaryHash" text not null check ("summaryHash" ~ '^[a-f0-9]{64}$'),
  "calculatedAt" timestamptz not null,
  unique ("activityInstanceId", "revision")
);

create trigger "external_media_descriptor_immutable"
  before update or delete on "vasi_engine"."external_media_descriptor"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "external_media_metadata_snapshot_immutable"
  before update or delete on "vasi_engine"."external_media_metadata_snapshot"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "media_event_batch_immutable"
  before update or delete on "vasi_engine"."media_event_batch"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "media_event_immutable"
  before update or delete on "vasi_engine"."media_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "media_activity_summary_revision_immutable"
  before update or delete on "vasi_engine"."media_activity_summary_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
