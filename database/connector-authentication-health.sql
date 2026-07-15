-- Durable per-connector authentication health. Generic account maintenance must
-- not advance these observations.

alter table "account"
  add column "lastAuthenticatedAt" timestamptz,
  add column "lastAuthenticationProvenance" text;

with observations as (
  select
    a."id",
    (
      select max(s."createdAt")
      from "session" s
      where s."userId" = a."userId"
        and s."authenticationMethod" = 'federated'
        and s."authenticationProvider" = a."providerId"
        and s."authenticationAccountId" = a."accountId"
    ) as "attributedSessionAt"
  from "account" a
  where a."providerId" in ('microsoft', 'google', 'apple', 'yahoo', 'zoho')
)
update "account" a
set
  "lastAuthenticatedAt" = coalesce(o."attributedSessionAt", a."updatedAt"),
  "lastAuthenticationProvenance" = case
    when o."attributedSessionAt" is not null
      then 'attributed_session_backfill/v1'
    else 'account_updated_at_estimate/v1'
  end
from observations o
where o."id" = a."id";

alter table "account"
  add constraint "account_authentication_observation_valid"
  check (
    (
      "lastAuthenticatedAt" is null
      and "lastAuthenticationProvenance" is null
    )
    or
    (
      "lastAuthenticatedAt" is not null
      and "lastAuthenticationProvenance" is not null
      and "lastAuthenticationProvenance" in (
        'federated_session/v1',
        'attributed_session_backfill/v1',
        'account_updated_at_estimate/v1'
      )
    )
  );

create index "account_connector_authentication_idx"
  on "account" ("providerId", "lastAuthenticatedAt" desc)
  where "lastAuthenticatedAt" is not null;

comment on column "account"."lastAuthenticatedAt" is
  'Latest provider authentication observation; generic account updates must not modify it.';

comment on column "account"."lastAuthenticationProvenance" is
  'Bounded provenance for an observed federated session or a migration-time legacy estimate.';
