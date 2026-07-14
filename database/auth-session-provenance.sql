-- Session-level authentication provenance for evidence-grade actor assertions.

alter table "session"
  add column "authenticationMethod" text,
  add column "authenticationProvider" text,
  add column "authenticationAccountId" text,
  add column "authenticationProvenance" text;

create index "session_authentication_provider_idx"
  on "session" ("authenticationProvider", "createdAt" desc)
  where "authenticationProvider" is not null;
