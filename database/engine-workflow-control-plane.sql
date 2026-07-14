-- General VASI workflow and company-owner control plane.

alter table "vasi_engine"."tenant_membership"
  add column "email" text,
  add column "source" text not null default 'direct',
  add column "validFrom" timestamptz not null default CURRENT_TIMESTAMP,
  add column "expiresAt" timestamptz;

create unique index "tenant_membership_email_idx"
  on "vasi_engine"."tenant_membership" ("tenantId", lower("email"))
  where "email" is not null;

create table "vasi_engine"."tenant_membership_grant" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "email" text not null,
  "roles" text[] not null,
  "status" text not null default 'active' check ("status" in ('active', 'disabled')),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "email")
);

create table "vasi_engine"."workflow_definition" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "name" text not null,
  "status" text not null default 'draft' check ("status" in ('draft', 'active', 'archived')),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "id")
);

create index "workflow_definition_tenant_idx"
  on "vasi_engine"."workflow_definition" ("tenantId", "status", "updatedAt" desc);

create table "vasi_engine"."workflow_draft" (
  "definitionId" text primary key references "vasi_engine"."workflow_definition" ("id"),
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "version" integer not null default 1 check ("version" > 0),
  "schemaVersion" text not null,
  "document" jsonb not null,
  "documentHash" text not null check ("documentHash" ~ '^[a-f0-9]{64}$'),
  "updatedByPrincipalId" text not null,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP
);

alter table "vasi_engine"."workflow_revision"
  add column "definitionId" text references "vasi_engine"."workflow_definition" ("id"),
  add column "schemaVersion" text,
  add column "snapshot" jsonb,
  add column "snapshotHash" text;

alter table "vasi_engine"."workflow_revision"
  add constraint "workflow_revision_snapshot_pair" check (
    ("definitionId" is null and "snapshot" is null and "snapshotHash" is null)
    or
    ("definitionId" is not null and "schemaVersion" is not null and "snapshot" is not null
      and "snapshotHash" ~ '^[a-f0-9]{64}$')
  );

create unique index "workflow_revision_definition_revision_idx"
  on "vasi_engine"."workflow_revision" ("definitionId", "revision")
  where "definitionId" is not null;

alter table "vasi_engine"."request_instance"
  drop constraint "request_instance_status_check",
  add constraint "request_instance_status_check"
    check ("status" in ('scheduled', 'issued', 'in_progress', 'completed', 'revoked', 'expired')),
  add column "scheduledFor" timestamptz,
  add column "dueAt" timestamptz,
  add column "accessPolicy" jsonb,
  add column "notificationPolicy" jsonb,
  add column "reissuedFromRequestId" text references "vasi_engine"."request_instance" ("id");

alter table "vasi_engine"."participant_assignment"
  drop constraint "participant_assignment_status_check",
  add constraint "participant_assignment_status_check"
    check ("status" in ('scheduled', 'issued', 'in_progress', 'completed', 'revoked', 'expired'));

create table "vasi_engine"."activity_instance" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "activityId" text not null,
  "ordinal" integer not null check ("ordinal" >= 0),
  "activityType" text not null,
  "contractVersion" integer not null check ("contractVersion" > 0),
  "definition" jsonb not null,
  "definitionHash" text not null check ("definitionHash" ~ '^[a-f0-9]{64}$'),
  "status" text not null check ("status" in ('pending', 'available', 'completed', 'skipped')),
  "availableAt" timestamptz,
  "openedAt" timestamptz,
  "completedAt" timestamptz,
  unique ("assignmentId", "activityId"),
  unique ("assignmentId", "ordinal")
);

create index "activity_instance_current_idx"
  on "vasi_engine"."activity_instance" ("assignmentId", "status", "ordinal");

create table "vasi_engine"."activity_response" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "activityInstanceId" text not null unique references "vasi_engine"."activity_instance" ("id"),
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id"),
  "commandId" text not null unique,
  "responseValue" jsonb not null,
  "clientContext" jsonb,
  "respondedAt" timestamptz not null
);

create table "vasi_engine"."request_lifecycle_event" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "eventType" text not null,
  "actorPrincipalId" text not null,
  "idempotencyKey" text not null unique,
  "eventData" jsonb not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

alter table "vasi_engine"."outbox_job"
  add column "tenantId" text references "vasi_engine"."tenant" ("id"),
  add column "requestId" text references "vasi_engine"."request_instance" ("id"),
  add column "idempotencyKey" text,
  add column "payloadHash" text,
  add column "maxAttempts" integer not null default 5 check ("maxAttempts" between 1 and 20),
  add column "completedAt" timestamptz,
  add column "result" jsonb;

create unique index "outbox_job_idempotency_idx"
  on "vasi_engine"."outbox_job" ("idempotencyKey")
  where "idempotencyKey" is not null;

create table "vasi_engine"."notification_delivery_attempt" (
  "id" text primary key,
  "jobId" text not null references "vasi_engine"."outbox_job" ("id"),
  "attempt" integer not null check ("attempt" > 0),
  "adapter" text not null,
  "outcome" text not null check ("outcome" in ('delivered', 'failed', 'suppressed')),
  "errorCode" text,
  "responseMetadata" jsonb,
  "startedAt" timestamptz not null,
  "completedAt" timestamptz not null,
  unique ("jobId", "attempt")
);

create trigger "activity_response_immutable"
  before update or delete on "vasi_engine"."activity_response"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "request_lifecycle_event_immutable"
  before update or delete on "vasi_engine"."request_lifecycle_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "notification_delivery_attempt_immutable"
  before update or delete on "vasi_engine"."notification_delivery_attempt"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
