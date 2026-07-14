-- PostgreSQL-backed immutable document artifacts and append-only activity response revisions.

alter table "vasi_engine"."workflow_revision"
  drop constraint "workflow_revision_activityType_check",
  drop constraint "workflow_revision_responseMode_check",
  add constraint "workflow_revision_activityType_check" check ("activityType" in (
    'terms_response', 'approval', 'single_choice', 'multiple_choice', 'free_form',
    'electronic_signature', 'document_review', 'questionnaire'
  )),
  add constraint "workflow_revision_responseMode_check" check ("responseMode" in (
    'acknowledgement', 'yes_no', 'approval', 'single_choice', 'multiple_choice',
    'free_form', 'electronic_signature', 'document_review', 'questionnaire'
  ));

create table "vasi_engine"."document_artifact" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "familyId" text not null,
  "revision" integer not null check ("revision" > 0),
  "role" text not null check ("role" in (
    'source_document', 'derived_preview', 'completed_document', 'report',
    'manifest', 'structured_export', 'evidence_bundle'
  )),
  "status" text not null default 'quarantined' check ("status" in ('quarantined', 'published', 'rejected')),
  "originalFilename" text not null,
  "mediaType" text not null,
  "expectedByteLength" bigint not null check ("expectedByteLength" > 0),
  "byteLength" bigint,
  "chunkCount" integer,
  "sha256" text,
  "source" text not null default 'owner_upload',
  "sourceArtifactId" text references "vasi_engine"."document_artifact" ("id"),
  "replacesArtifactId" text references "vasi_engine"."document_artifact" ("id"),
  "inspectionStatus" text not null default 'pending' check ("inspectionStatus" in ('pending', 'passed', 'rejected')),
  "inspectionProfile" text,
  "inspectionResult" jsonb,
  "encryptionMetadata" jsonb not null,
  "retentionPolicy" jsonb not null,
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  "publishedAt" timestamptz,
  "rejectedAt" timestamptz,
  unique ("tenantId", "familyId", "revision"),
  check (
    ("status" = 'quarantined' and "byteLength" is null and "chunkCount" is null and "sha256" is null
      and "publishedAt" is null and "rejectedAt" is null)
    or
    ("status" = 'published' and "byteLength" = "expectedByteLength" and "chunkCount" > 0
      and "sha256" ~ '^[a-f0-9]{64}$' and "inspectionStatus" = 'passed'
      and "publishedAt" is not null and "rejectedAt" is null)
    or
    ("status" = 'rejected' and "inspectionStatus" = 'rejected' and "rejectedAt" is not null)
  )
);

create index "document_artifact_tenant_idx"
  on "vasi_engine"."document_artifact" ("tenantId", "status", "createdAt" desc);

create table "vasi_engine"."document_artifact_chunk" (
  "artifactId" text not null references "vasi_engine"."document_artifact" ("id"),
  "sequence" integer not null check ("sequence" >= 0),
  "byteLength" integer not null check ("byteLength" > 0),
  "sha256" text not null check ("sha256" ~ '^[a-f0-9]{64}$'),
  "bytes" bytea not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("artifactId", "sequence"),
  check ("byteLength" = octet_length("bytes"))
);

create table "vasi_engine"."workflow_artifact_binding" (
  "workflowRevisionId" text not null references "vasi_engine"."workflow_revision" ("id"),
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "activityId" text not null,
  "artifactId" text not null references "vasi_engine"."document_artifact" ("id"),
  "artifactRole" text not null,
  "mediaType" text not null,
  "byteLength" bigint not null,
  "sha256" text not null check ("sha256" ~ '^[a-f0-9]{64}$'),
  "boundAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("workflowRevisionId", "activityId", "artifactId")
);

create table "vasi_engine"."document_artifact_access_event" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "artifactId" text not null references "vasi_engine"."document_artifact" ("id"),
  "requestId" text references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text references "vasi_engine"."participant_assignment" ("id"),
  "activityInstanceId" text references "vasi_engine"."activity_instance" ("id"),
  "actorPrincipalId" text not null,
  "accessType" text not null check ("accessType" in ('owner_stream', 'participant_presentation', 'participant_download')),
  "disposition" text not null check ("disposition" in ('inline', 'attachment')),
  "metadata" jsonb not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "document_artifact_access_assignment_idx"
  on "vasi_engine"."document_artifact_access_event" ("assignmentId", "activityInstanceId", "createdAt");

create table "vasi_engine"."activity_response_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "activityInstanceId" text not null references "vasi_engine"."activity_instance" ("id"),
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id"),
  "revision" integer not null check ("revision" > 0),
  "commandId" text not null unique,
  "state" text not null check ("state" in ('saved', 'submitted')),
  "responseValue" jsonb not null,
  "responseLabel" text not null,
  "outcome" text not null,
  "result" jsonb,
  "clientContext" jsonb,
  "recordedAt" timestamptz not null,
  unique ("activityInstanceId", "revision")
);

alter table "vasi_engine"."activity_response"
  add column "responseRevisionId" text references "vasi_engine"."activity_response_revision" ("id"),
  add column "responseLabel" text,
  add column "outcome" text,
  add column "result" jsonb;

create or replace function "vasi_engine"."guard_document_artifact_change"()
returns trigger language plpgsql as $$
begin
  if TG_OP = 'DELETE' or OLD."status" <> 'quarantined' then
    raise exception 'document artifacts are immutable after finalization';
  end if;
  if NEW."id" <> OLD."id" or NEW."tenantId" <> OLD."tenantId"
     or NEW."familyId" <> OLD."familyId" or NEW."revision" <> OLD."revision"
     or NEW."role" <> OLD."role" or NEW."originalFilename" <> OLD."originalFilename"
     or NEW."mediaType" <> OLD."mediaType" or NEW."expectedByteLength" <> OLD."expectedByteLength"
     or NEW."createdByPrincipalId" <> OLD."createdByPrincipalId" or NEW."createdAt" <> OLD."createdAt" then
    raise exception 'document artifact identity fields are immutable';
  end if;
  return NEW;
end;
$$;

create or replace function "vasi_engine"."guard_document_chunk_insert"()
returns trigger language plpgsql as $$
begin
  if not exists (
    select 1 from "vasi_engine"."document_artifact"
    where "id" = NEW."artifactId" and "status" = 'quarantined'
  ) then
    raise exception 'document chunks may only be added to quarantined artifacts';
  end if;
  return NEW;
end;
$$;

create trigger "document_artifact_change_guard"
  before update or delete on "vasi_engine"."document_artifact"
  for each row execute function "vasi_engine"."guard_document_artifact_change"();
create trigger "document_artifact_chunk_insert_guard"
  before insert on "vasi_engine"."document_artifact_chunk"
  for each row execute function "vasi_engine"."guard_document_chunk_insert"();
create trigger "document_artifact_chunk_immutable"
  before update or delete on "vasi_engine"."document_artifact_chunk"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "workflow_artifact_binding_immutable"
  before update or delete on "vasi_engine"."workflow_artifact_binding"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "document_artifact_access_event_immutable"
  before update or delete on "vasi_engine"."document_artifact_access_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "activity_response_revision_immutable"
  before update or delete on "vasi_engine"."activity_response_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
