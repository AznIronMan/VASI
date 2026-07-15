-- Installation-scoped replay safety for administrator tenant provisioning.
-- The input itself is not retained; its canonical digest is bound to the
-- actor and the exact bounded result returned by the committed transaction.

create table "vasi_engine"."tenant_provision_command" (
  "commandId" uuid primary key,
  "actorPrincipalId" text not null,
  "inputHash" text not null check ("inputHash" ~ '^[a-f0-9]{64}$'),
  "result" jsonb not null check (jsonb_typeof("result") = 'object'),
  "resultHash" text not null check ("resultHash" ~ '^[a-f0-9]{64}$'),
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

create trigger "tenant_provision_command_immutable"
  before update or delete on "vasi_engine"."tenant_provision_command"
  for each row execute function "vasi_engine"."reject_immutable_change"();

revoke all on all tables in schema "vasi_engine" from PUBLIC;
