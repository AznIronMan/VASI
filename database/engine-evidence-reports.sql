-- Deterministic evidence reports, portable bundles, signing-key history, and
-- append-only access evidence. Export bytes stay chunked in PostgreSQL.

alter table "vasi_engine"."evidence_seal"
  drop constraint "evidence_seal_manifestId_key",
  add column "sealRole" text not null default 'vasi_integrity' check ("sealRole" in (
    'vasi_integrity', 'certificate', 'tenant', 'timestamp'
  )),
  add column "certificateChain" jsonb,
  add column "metadata" jsonb not null default '{}'::jsonb,
  add constraint "evidence_seal_manifest_role_key_unique"
    unique ("manifestId", "sealRole", "keyId");

create table "vasi_engine"."evidence_seal_key" (
  "keyId" text primary key,
  "sealRole" text not null check ("sealRole" in ('vasi_integrity', 'certificate', 'tenant', 'timestamp')),
  "algorithm" text not null,
  "publicJwk" jsonb,
  "certificateChain" jsonb,
  "fingerprint" text not null check ("fingerprint" ~ '^[a-f0-9]{64}$'),
  "metadata" jsonb not null default '{}'::jsonb,
  "registeredAt" timestamptz not null default CURRENT_TIMESTAMP,
  check ("publicJwk" is not null or "certificateChain" is not null)
);

create table "vasi_engine"."evidence_seal_key_status_event" (
  "id" text primary key,
  "keyId" text not null references "vasi_engine"."evidence_seal_key" ("keyId"),
  "status" text not null check ("status" in ('active', 'retired', 'compromised', 'revoked')),
  "reason" text,
  "recordedByPrincipalId" text not null,
  "recordedAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "evidence_seal_key_status_idx"
  on "vasi_engine"."evidence_seal_key_status_event" ("keyId", "recordedAt" desc, "id" desc);

create table "vasi_engine"."evidence_export_artifact" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "requestId" text not null references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text not null references "vasi_engine"."participant_assignment" ("id"),
  "kind" text not null check ("kind" in ('report', 'bundle')),
  "profile" text not null check ("profile" in (
    'participant', 'nontechnical', 'technical', 'structured', 'full'
  )),
  "format" text not null check ("format" in ('json', 'text', 'html', 'zip')),
  "mediaType" text not null,
  "filename" text not null,
  "byteLength" bigint not null check ("byteLength" > 0),
  "chunkCount" integer not null check ("chunkCount" > 0),
  "sha256" text not null check ("sha256" ~ '^[a-f0-9]{64}$'),
  "sourceManifestHash" text not null check ("sourceManifestHash" ~ '^[a-f0-9]{64}$'),
  "generatorVersion" text not null,
  "templateVersion" text not null,
  "provenance" jsonb not null,
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null,
  unique (
    "assignmentId", "sourceManifestHash", "kind", "profile", "format",
    "generatorVersion", "templateVersion"
  )
);

create table "vasi_engine"."evidence_export_chunk" (
  "exportArtifactId" text not null references "vasi_engine"."evidence_export_artifact" ("id"),
  "sequence" integer not null check ("sequence" >= 0),
  "byteLength" integer not null check ("byteLength" > 0),
  "sha256" text not null check ("sha256" ~ '^[a-f0-9]{64}$'),
  "bytes" bytea not null,
  primary key ("exportArtifactId", "sequence"),
  check ("byteLength" = octet_length("bytes"))
);

create table "vasi_engine"."evidence_access_event" (
  "id" text primary key,
  "tenantId" text references "vasi_engine"."tenant" ("id"),
  "requestId" text references "vasi_engine"."request_instance" ("id"),
  "assignmentId" text references "vasi_engine"."participant_assignment" ("id"),
  "manifestHash" text check ("manifestHash" is null or "manifestHash" ~ '^[a-f0-9]{64}$'),
  "exportArtifactId" text references "vasi_engine"."evidence_export_artifact" ("id"),
  "actorPrincipalId" text not null,
  "accessType" text not null check ("accessType" in (
    'owner_record_view', 'owner_report_export', 'owner_bundle_export',
    'participant_receipt', 'participant_report_export', 'public_verification'
  )),
  "metadata" jsonb not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "evidence_access_assignment_idx"
  on "vasi_engine"."evidence_access_event" ("assignmentId", "createdAt" desc, "id" desc);
create index "evidence_access_manifest_idx"
  on "vasi_engine"."evidence_access_event" ("manifestHash", "createdAt" desc, "id" desc);

create trigger "evidence_seal_key_immutable"
  before update or delete on "vasi_engine"."evidence_seal_key"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_seal_key_status_event_immutable"
  before update or delete on "vasi_engine"."evidence_seal_key_status_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_export_artifact_immutable"
  before update or delete on "vasi_engine"."evidence_export_artifact"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_export_chunk_immutable"
  before update or delete on "vasi_engine"."evidence_export_chunk"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "evidence_access_event_immutable"
  before update or delete on "vasi_engine"."evidence_access_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
