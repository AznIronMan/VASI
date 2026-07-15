-- Bind at most one identity invitation to a replay-safe administrator company
-- provisioning command. Invitation lifecycle fields remain mutable, while the
-- command binding can never be reassigned to another invitation or email.

alter table "vasi_invitation"
  add column "sourceCommandId" uuid,
  add column "deliveryStatus" text not null default 'provider_accepted'
    check ("deliveryStatus" in ('pending', 'provider_accepted', 'failed'));

create unique index "vasi_invitation_source_command_idx"
  on "vasi_invitation" ("sourceCommandId")
  where "sourceCommandId" is not null;

create function "vasi_invitation_source_command_immutable"()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if NEW."sourceCommandId" is distinct from OLD."sourceCommandId" then
    raise exception 'VASI invitation command bindings are immutable.';
  end if;
  if OLD."sourceCommandId" is not null and (
    NEW."id" is distinct from OLD."id"
    or NEW."email" is distinct from OLD."email"
    or NEW."invitedBy" is distinct from OLD."invitedBy"
    or NEW."tokenHash" is distinct from OLD."tokenHash"
    or NEW."expiresAt" is distinct from OLD."expiresAt"
    or NEW."createdAt" is distinct from OLD."createdAt"
  ) then
    raise exception 'VASI command-bound invitation identity is immutable.';
  end if;
  if NEW."deliveryStatus" is distinct from OLD."deliveryStatus"
     and not (
       OLD."deliveryStatus" = 'pending'
       and NEW."deliveryStatus" in ('provider_accepted', 'failed')
     ) then
    raise exception 'VASI invitation delivery state transitions are invalid.';
  end if;
  return NEW;
end;
$$;

create trigger "vasi_invitation_source_command_immutable"
  before update on "vasi_invitation"
  for each row execute function "vasi_invitation_source_command_immutable"();

revoke all on function "vasi_invitation_source_command_immutable"() from PUBLIC;
