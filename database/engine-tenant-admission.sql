-- Immutable tenant production-admission decisions and fail-closed database
-- enforcement for request issuance and outbound integration activation.

create table "vasi_engine"."tenant_admission_revision" (
  "id" text primary key,
  "tenantId" text not null references "vasi_engine"."tenant" ("id"),
  "revision" integer not null check ("revision" > 0),
  "admission" jsonb not null check (
    "admission"->>'schema' = 'vasi-tenant-admission/v1'
    and "admission"->>'status' in ('pending', 'admitted')
    and jsonb_typeof("admission"->'gates') = 'array'
    and jsonb_array_length("admission"->'gates') = 8
  ),
  "admissionHash" text not null check ("admissionHash" ~ '^[a-f0-9]{64}$'),
  "createdByPrincipalId" text not null,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  unique ("tenantId", "revision"),
  unique ("id", "tenantId", "revision")
);

create table "vasi_engine"."tenant_admission_pointer" (
  "tenantId" text primary key references "vasi_engine"."tenant" ("id"),
  "activeRevisionId" text not null references "vasi_engine"."tenant_admission_revision" ("id"),
  "revision" integer not null check ("revision" > 0),
  "updatedByPrincipalId" text not null,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP,
  foreign key ("activeRevisionId", "tenantId", "revision")
    references "vasi_engine"."tenant_admission_revision" ("id", "tenantId", "revision")
);

alter table "vasi_engine"."request_instance"
  add column "tenantAdmissionRevisionId" text
    references "vasi_engine"."tenant_admission_revision" ("id"),
  add column "tenantAdmissionSnapshot" jsonb,
  add column "tenantAdmissionHash" text,
  add column "tenantAdmissionBindingProvenance" text check (
    "tenantAdmissionBindingProvenance" = 'issued'
  );

alter table "vasi_engine"."request_instance"
  add constraint "request_instance_tenant_admission_snapshot" check (
    ("tenantAdmissionRevisionId" is null and "tenantAdmissionSnapshot" is null
      and "tenantAdmissionHash" is null and "tenantAdmissionBindingProvenance" is null)
    or
    ("tenantAdmissionRevisionId" is not null and "tenantAdmissionSnapshot" is not null
      and "tenantAdmissionSnapshot"->>'schema' = 'vasi-tenant-admission/v1'
      and "tenantAdmissionSnapshot"->>'status' = 'admitted'
      and "tenantAdmissionHash" ~ '^[a-f0-9]{64}$'
      and "tenantAdmissionBindingProvenance" = 'issued')
  );

do $$
declare
  existing_constraint text;
begin
  select c.conname into existing_constraint
  from pg_constraint c
  where c.conrelid = '"vasi_engine"."product_configuration_event"'::regclass
    and c.contype = 'c'
    and pg_get_constraintdef(c.oid) like '%eventType%';
  if existing_constraint is null then
    raise exception 'The product configuration event-type constraint is unavailable.';
  end if;
  execute format(
    'alter table "vasi_engine"."product_configuration_event" drop constraint %I',
    existing_constraint
  );
end $$;

alter table "vasi_engine"."product_configuration_event"
  add constraint "product_configuration_event_event_type_check_v2" check ("eventType" in (
    'installation.profile.created', 'installation.profile.updated',
    'tenant.provisioned', 'tenant.profile.updated',
    'tenant.admission.created', 'tenant.admission.approved', 'tenant.admission.revoked',
    'integration.binding.created', 'integration.binding.updated', 'integration.binding.disabled'
  ));

create function "vasi_engine"."enforce_tenant_production_admission"()
returns trigger
language plpgsql
set search_path = pg_catalog, vasi_engine
as $$
begin
  if TG_TABLE_NAME = 'request_instance' then
    if not exists (
      select 1
      from "vasi_engine"."tenant_admission_revision" r
      where r."tenantId" = NEW."tenantId"
        and r."id" = NEW."tenantAdmissionRevisionId"
        and r."admissionHash" = NEW."tenantAdmissionHash"
        and r."admission" = NEW."tenantAdmissionSnapshot"
        and r."admission"->>'status' = 'admitted'
        and (
          current_setting('vasi.tenant_import', true) = 'on'
          or exists (
            select 1 from "vasi_engine"."tenant_admission_pointer" p
            where p."tenantId" = NEW."tenantId" and p."activeRevisionId" = r."id"
          )
        )
    ) then
      raise exception 'The tenant is not admitted for production request issuance.'
        using errcode = '23514', constraint = 'tenant_production_admission_required';
    end if;
  elsif TG_TABLE_NAME = 'integration_binding_revision' and NEW."status" = 'active'
      and current_setting('vasi.tenant_import', true) is distinct from 'on' then
    if not exists (
      select 1
      from "vasi_engine"."tenant_admission_pointer" p
      join "vasi_engine"."tenant_admission_revision" r
        on r."id" = p."activeRevisionId" and r."tenantId" = p."tenantId"
      where p."tenantId" = NEW."tenantId" and r."admission"->>'status' = 'admitted'
    ) then
      raise exception 'The tenant is not admitted for outbound integration activation.'
        using errcode = '23514', constraint = 'tenant_production_admission_required';
    end if;
  end if;
  return NEW;
end;
$$;

create function "vasi_engine"."request_issuance_bindings_immutable"()
returns trigger
language plpgsql
set search_path = pg_catalog, vasi_engine
as $$
begin
  if NEW."tenantProfileRevisionId" is distinct from OLD."tenantProfileRevisionId"
     or NEW."tenantProfileSnapshot" is distinct from OLD."tenantProfileSnapshot"
     or NEW."tenantProfileHash" is distinct from OLD."tenantProfileHash"
     or NEW."tenantProfileBindingProvenance" is distinct from OLD."tenantProfileBindingProvenance"
     or NEW."tenantAdmissionRevisionId" is distinct from OLD."tenantAdmissionRevisionId"
     or NEW."tenantAdmissionSnapshot" is distinct from OLD."tenantAdmissionSnapshot"
     or NEW."tenantAdmissionHash" is distinct from OLD."tenantAdmissionHash"
     or NEW."tenantAdmissionBindingProvenance" is distinct from OLD."tenantAdmissionBindingProvenance" then
    raise exception 'Request issuance profile and admission bindings are immutable.';
  end if;
  return NEW;
end;
$$;

create trigger "tenant_admission_request_gate"
  before insert on "vasi_engine"."request_instance"
  for each row execute function "vasi_engine"."enforce_tenant_production_admission"();
create trigger "tenant_admission_integration_gate"
  before insert on "vasi_engine"."integration_binding_revision"
  for each row execute function "vasi_engine"."enforce_tenant_production_admission"();
create trigger "request_issuance_bindings_immutable"
  before update on "vasi_engine"."request_instance"
  for each row execute function "vasi_engine"."request_issuance_bindings_immutable"();
create trigger "tenant_admission_revision_immutable"
  before update or delete on "vasi_engine"."tenant_admission_revision"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on function "vasi_engine"."enforce_tenant_production_admission"() from PUBLIC;
revoke all on function "vasi_engine"."request_issuance_bindings_immutable"() from PUBLIC;
revoke all on all tables in schema "vasi_engine" from PUBLIC;
