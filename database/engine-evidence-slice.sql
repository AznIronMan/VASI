-- First sealed VASI evidence vertical slice. This migration intentionally
-- covers only immutable text/terms plus acknowledgement or yes/no response.

create table "vasi_engine"."tenant" (
  "id" text primary key,
  "slug" text not null unique,
  "name" text not null,
  "status" text not null default 'active' check ("status" in ('active', 'disabled')),
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

create table "vasi_engine"."tenant_membership" (
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "principalId" text not null,
  "roles" text[] not null,
  "status" text not null default 'active' check ("status" in ('active', 'disabled')),
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("tenantId", "principalId")
);

create table "vasi_engine"."workflow_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "revision" integer not null check ("revision" > 0),
  "title" text not null,
  "purpose" text not null,
  "activityType" text not null check ("activityType" = 'terms_response'),
  "responseMode" text not null check ("responseMode" in ('acknowledgement', 'yes_no')),
  "content" jsonb not null,
  "contentHash" text not null check ("contentHash" ~ '^[a-f0-9]{64}$'),
  "publishedByPrincipalId" text not null,
  "publishedAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "id", "revision")
);

create table "vasi_engine"."request_instance" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "workflowRevisionId" text not null references "vasi_engine"."workflow_revision" ("id"),
  "createdByPrincipalId" text not null,
  "purpose" text not null,
  "status" text not null check ("status" in ('issued', 'completed', 'revoked', 'expired')),
  "issuedAt" timestamptz not null,
  "expiresAt" timestamptz not null,
  "completedAt" timestamptz,
  check ("expiresAt" > "issuedAt")
);

create table "vasi_engine"."participant_assignment" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "handleDigest" bytea not null unique check (octet_length("handleDigest") = 32),
  "intendedEmail" text not null,
  "principalId" text,
  "participantEmail" text,
  "status" text not null check ("status" in ('issued', 'in_progress', 'completed', 'revoked', 'expired')),
  "issuedAt" timestamptz not null,
  "firstOpenedAt" timestamptz,
  "completedAt" timestamptz,
  unique ("requestId", "id")
);

create index "participant_assignment_principal_idx"
  on "vasi_engine"."participant_assignment" ("principalId", "status");

create table "vasi_engine"."interaction_session" (
  "id" text primary key,
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "principalId" text not null,
  "gatewaySessionId" text not null,
  "authentication" jsonb not null,
  "requestContext" jsonb,
  "startedAt" timestamptz not null,
  "completedAt" timestamptz,
  unique ("assignmentId", "id")
);

create unique index "interaction_session_open_idx"
  on "vasi_engine"."interaction_session" ("assignmentId", "principalId")
  where "completedAt" is null;

create table "vasi_engine"."participant_response" (
  "id" text primary key,
  "assignmentId" text not null unique references "vasi_engine"."participant_assignment" ("id"),
  "interactionId" text not null references "vasi_engine"."interaction_session" ("id"),
  "commandId" text not null unique,
  "responseMode" text not null,
  "responseValue" text not null,
  "respondedAt" timestamptz not null,
  "clientContext" jsonb
);

create table "vasi_engine"."evidence_chain_head" (
  "assignmentId" text primary key references "vasi_engine"."participant_assignment" ("id"),
  "lastSequence" bigint not null default 0 check ("lastSequence" >= 0),
  "lastHash" text not null check ("lastHash" ~ '^[a-f0-9]{64}$')
);

create table "vasi_engine"."evidence_event" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "sequence" bigint not null check ("sequence" > 0),
  "eventType" text not null,
  "actorPrincipalId" text not null,
  "eventData" jsonb not null,
  "previousHash" text not null check ("previousHash" ~ '^[a-f0-9]{64}$'),
  "eventHash" text not null check ("eventHash" ~ '^[a-f0-9]{64}$'),
  "receivedAt" timestamptz not null,
  "engineVersion" text not null,
  unique ("assignmentId", "sequence"),
  unique ("assignmentId", "eventHash")
);

create index "evidence_event_request_idx"
  on "vasi_engine"."evidence_event" ("tenantId", "requestId", "assignmentId", "sequence");

create table "vasi_engine"."evidence_manifest" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null unique references "vasi_engine"."participant_assignment" ("id"),
  "manifest" jsonb not null,
  "manifestHash" text not null check ("manifestHash" ~ '^[a-f0-9]{64}$'),
  "createdAt" timestamptz not null
);

create table "vasi_engine"."evidence_seal" (
  "id" text primary key,
  "manifestId" text not null unique references "vasi_engine"."evidence_manifest" ("id"),
  "profile" text not null,
  "algorithm" text not null,
  "keyId" text not null,
  "publicJwk" jsonb not null,
  "signature" text not null,
  "createdAt" timestamptz not null
);

create function "vasi_engine"."reject_immutable_change"()
returns trigger language plpgsql as $$
begin
  raise exception 'VASI immutable evidence records cannot be changed';
end;
$$;

create trigger "workflow_revision_immutable"
  before update or delete on "vasi_engine"."workflow_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "participant_response_immutable"
  before update or delete on "vasi_engine"."participant_response"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_event_immutable"
  before update or delete on "vasi_engine"."evidence_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_manifest_immutable"
  before update or delete on "vasi_engine"."evidence_manifest"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_seal_immutable"
  before update or delete on "vasi_engine"."evidence_seal"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
