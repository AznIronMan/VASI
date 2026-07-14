-- Atomic tenant production-stop audit contract. The engine performs the
-- admission and request state transitions in one transaction; PostgreSQL keeps
-- each stop command globally replay-resistant in the immutable tenant chain.

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
  add constraint "product_configuration_event_event_type_check_v3" check ("eventType" in (
    'installation.profile.created', 'installation.profile.updated',
    'tenant.provisioned', 'tenant.profile.updated',
    'tenant.admission.created', 'tenant.admission.approved', 'tenant.admission.revoked',
    'tenant.production.stopped',
    'integration.binding.created', 'integration.binding.updated', 'integration.binding.disabled'
  ));

create unique index "product_configuration_tenant_stop_command_idx"
  on "vasi_engine"."product_configuration_event" (("eventData"->>'commandId'))
  where "eventType" = 'tenant.production.stopped';

revoke all on all tables in schema "vasi_engine" from PUBLIC;
