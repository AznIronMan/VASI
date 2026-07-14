-- Immutable requesting-user provenance and participant disclosure source.

alter table "vasi_engine"."request_instance"
  add column "requesterSnapshot" jsonb;

update "vasi_engine"."request_instance" r
set "requesterSnapshot" = coalesce(
  (
    select jsonb_build_object(
      'schema', 'vasi-requester-snapshot/v1',
      'principalId', r."createdByPrincipalId",
      'email', e."eventData" -> 'actor' ->> 'email',
      'relationship', 'requesting_organization',
      'provenance', 'evidence_event_backfill'
    )
    from "vasi_engine"."evidence_event" e
    where e."requestId" = r."id"
      and e."eventType" in ('request.issued', 'request.scheduled')
      and e."eventData" -> 'actor' ->> 'principalId' = r."createdByPrincipalId"
      and e."eventData" -> 'actor' ->> 'email' is not null
    order by e."sequence"
    limit 1
  ),
  (
    select jsonb_build_object(
      'schema', 'vasi-requester-snapshot/v1',
      'principalId', r."createdByPrincipalId",
      'email', lower(m."email"),
      'relationship', 'requesting_organization',
      'provenance', 'membership_backfill'
    )
    from "vasi_engine"."tenant_membership" m
    where m."tenantId" = r."tenantId"
      and m."principalId" = r."createdByPrincipalId"
      and m."email" is not null
    limit 1
  ),
  jsonb_build_object(
    'schema', 'vasi-requester-snapshot/v1',
    'principalId', r."createdByPrincipalId",
    'email', null,
    'relationship', 'requesting_organization',
    'provenance', 'legacy_unavailable'
  )
);

alter table "vasi_engine"."request_instance"
  alter column "requesterSnapshot" set not null,
  add constraint "request_instance_requester_snapshot_valid" check (
    jsonb_typeof("requesterSnapshot") = 'object'
    and "requesterSnapshot" ?& array[
      'schema', 'principalId', 'email', 'relationship', 'provenance'
    ]
    and ("requesterSnapshot" - array[
      'schema', 'principalId', 'email', 'relationship', 'provenance'
    ]) = '{}'::jsonb
    and "requesterSnapshot" ->> 'schema' = 'vasi-requester-snapshot/v1'
    and "requesterSnapshot" ->> 'principalId' = "createdByPrincipalId"
    and "requesterSnapshot" ->> 'relationship' = 'requesting_organization'
    and "requesterSnapshot" ->> 'provenance' in (
      'authenticated_actor_at_issuance',
      'evidence_event_backfill',
      'membership_backfill',
      'legacy_unavailable'
    )
    and (
      ("requesterSnapshot" ->> 'email' is null
        and "requesterSnapshot" ->> 'provenance' = 'legacy_unavailable')
      or
      (length("requesterSnapshot" ->> 'email') between 3 and 320
        and "requesterSnapshot" ->> 'email' ~ '^[^@[:space:]]+@[^@[:space:]]+$')
    )
  );

create function "vasi_engine"."request_requester_snapshot_immutable"()
returns trigger language plpgsql as $$
begin
  if NEW."createdByPrincipalId" is distinct from OLD."createdByPrincipalId"
     or NEW."requesterSnapshot" is distinct from OLD."requesterSnapshot" then
    raise exception 'Request requester provenance is immutable.';
  end if;
  return NEW;
end;
$$;

create trigger "request_requester_snapshot_immutable"
  before update on "vasi_engine"."request_instance"
  for each row execute function "vasi_engine"."request_requester_snapshot_immutable"();
