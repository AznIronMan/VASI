-- Installation-neutral product profiles, tenant capacity policy, governed
-- integration adapters, and immutable configuration audit chains.

create table "vasi_engine"."installation_profile_revision" (
  "id" text primary key,
  "installationId" text not null,
  "revision" integer not null check ("revision" > 0),
  "profile" jsonb not null,
  "profileHash" text not null check ("profileHash" ~ '^[a-f0-9]{64}$'),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("installationId", "revision")
);

create table "vasi_engine"."installation_profile_pointer" (
  "installationId" text primary key,
  "activeRevisionId" text not null references "vasi_engine"."installation_profile_revision" ("id"),
  "revision" integer not null check ("revision" > 0),
  "updatedByPrincipalId" text not null,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP
);

create table "vasi_engine"."tenant_profile_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "revision" integer not null check ("revision" > 0),
  "profile" jsonb not null,
  "profileHash" text not null check ("profileHash" ~ '^[a-f0-9]{64}$'),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "revision")
);

create table "vasi_engine"."tenant_profile_pointer" (
  "tenantId" text primary key references "vasi_engine"."tenant" ("id"),
  "activeRevisionId" text not null references "vasi_engine"."tenant_profile_revision" ("id"),
  "revision" integer not null check ("revision" > 0),
  "updatedByPrincipalId" text not null,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP
);

create table "vasi_engine"."product_configuration_chain_head" (
  "scopeType" text not null check ("scopeType" in ('installation', 'tenant', 'integration')),
  "scopeId" text not null,
  "lastSequence" bigint not null default 0 check ("lastSequence" >= 0),
  "lastHash" text not null check ("lastHash" ~ '^[a-f0-9]{64}$'),
  primary key ("scopeType", "scopeId")
);

create table "vasi_engine"."product_configuration_event" (
  "id" text primary key,
  "scopeType" text not null check ("scopeType" in ('installation', 'tenant', 'integration')),
  "scopeId" text not null,
  "tenantId" text references "vasi_engine"."tenant" ("id"),
  "sequence" bigint not null check ("sequence" > 0),
  "eventType" text not null check ("eventType" in (
    'installation.profile.created', 'installation.profile.updated',
    'tenant.provisioned', 'tenant.profile.updated',
    'integration.binding.created', 'integration.binding.updated', 'integration.binding.disabled'
  )),
  "actorPrincipalId" text not null,
  "eventData" jsonb not null,
  "previousHash" text not null check ("previousHash" ~ '^[a-f0-9]{64}$'),
  "eventHash" text not null check ("eventHash" ~ '^[a-f0-9]{64}$'),
  "createdAt" timestamptz not null,
  unique ("scopeType", "scopeId", "sequence"),
  unique ("scopeType", "scopeId", "eventHash")
);

create table "vasi_engine"."integration_adapter_registry" (
  "adapterId" text not null,
  "adapterVersion" text not null,
  "manifest" jsonb not null,
  "manifestHash" text not null check ("manifestHash" ~ '^[a-f0-9]{64}$'),
  "conformanceStatus" text not null check ("conformanceStatus" in ('built_in_verified', 'disabled')),
  "registeredAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("adapterId", "adapterVersion")
);

create table "vasi_engine"."integration_binding_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "capability" text not null,
  "revision" integer not null check ("revision" > 0),
  "adapterId" text not null,
  "adapterVersion" text not null,
  "status" text not null check ("status" in ('active', 'disabled')),
  "config" jsonb not null,
  "configHash" text not null check ("configHash" ~ '^[a-f0-9]{64}$'),
  "credentialEnvelope" jsonb not null,
  "credentialFingerprint" text not null check ("credentialFingerprint" ~ '^[a-f0-9]{64}$'),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "capability", "revision"),
  foreign key ("adapterId", "adapterVersion")
    references "vasi_engine"."integration_adapter_registry" ("adapterId", "adapterVersion")
);

create table "vasi_engine"."integration_binding_pointer" (
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "capability" text not null,
  "activeRevisionId" text not null references "vasi_engine"."integration_binding_revision" ("id"),
  "revision" integer not null check ("revision" > 0),
  "updatedByPrincipalId" text not null,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  primary key ("tenantId", "capability")
);

create table "vasi_engine"."integration_gateway_attempt" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "jobId" text not null references "vasi_engine"."outbox_job" ("id"),
  "attempt" integer not null check ("attempt" > 0),
  "bindingRevisionId" text references "vasi_engine"."integration_binding_revision" ("id"),
  "capability" text not null,
  "adapterId" text not null,
  "adapterVersion" text not null,
  "idempotencyKey" text not null,
  "requestHash" text not null check ("requestHash" ~ '^[a-f0-9]{64}$'),
  "outcome" text not null check ("outcome" in ('delivered', 'failed', 'suppressed')),
  "errorCode" text,
  "responseMetadata" jsonb not null,
  "startedAt" timestamptz not null,
  "completedAt" timestamptz not null,
  unique ("jobId", "attempt")
);

alter table "vasi_engine"."request_instance"
  add column "tenantProfileRevisionId" text references "vasi_engine"."tenant_profile_revision" ("id"),
  add column "tenantProfileSnapshot" jsonb,
  add column "tenantProfileHash" text,
  add column "tenantProfileBindingProvenance" text check (
    "tenantProfileBindingProvenance" in ('issued', 'migration_default')
  );

alter table "vasi_engine"."request_instance"
  add constraint "request_instance_tenant_profile_snapshot" check (
    ("tenantProfileRevisionId" is null and "tenantProfileSnapshot" is null and "tenantProfileHash" is null
      and "tenantProfileBindingProvenance" is null)
    or
    ("tenantProfileRevisionId" is not null and "tenantProfileSnapshot" is not null
      and "tenantProfileHash" ~ '^[a-f0-9]{64}$' and "tenantProfileBindingProvenance" is not null)
  );

create trigger "installation_profile_revision_immutable"
  before update or delete on "vasi_engine"."installation_profile_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "tenant_profile_revision_immutable"
  before update or delete on "vasi_engine"."tenant_profile_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "product_configuration_event_immutable"
  before update or delete on "vasi_engine"."product_configuration_event"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "integration_adapter_registry_immutable"
  before update or delete on "vasi_engine"."integration_adapter_registry"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "integration_binding_revision_immutable"
  before update or delete on "vasi_engine"."integration_binding_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();
create trigger "integration_gateway_attempt_immutable"
  before update or delete on "vasi_engine"."integration_gateway_attempt"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
