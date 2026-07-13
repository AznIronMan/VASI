-- VASI identity administration, invitations, and audit support.

alter table "user" add column "role" text not null default 'user';
alter table "user" add column "banned" boolean not null default false;
alter table "user" add column "banReason" text;
alter table "user" add column "banExpires" timestamptz;

alter table "session" add column "impersonatedBy" text;

create table "vasi_invitation" (
  "id" text not null primary key,
  "email" text not null,
  "tokenHash" text not null unique,
  "invitedBy" text references "user" ("id") on delete set null,
  "expiresAt" timestamptz not null,
  "acceptedBy" text references "user" ("id") on delete set null,
  "acceptedAt" timestamptz,
  "revokedAt" timestamptz,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP
);

create unique index "vasi_invitation_pending_email_idx"
  on "vasi_invitation" (lower("email"))
  where "acceptedAt" is null and "revokedAt" is null;

create index "vasi_invitation_tokenHash_idx"
  on "vasi_invitation" ("tokenHash");

create table "vasi_admin_audit" (
  "id" text not null primary key,
  "actorUserId" text references "user" ("id") on delete set null,
  "targetUserId" text references "user" ("id") on delete set null,
  "action" text not null,
  "metadata" jsonb not null default '{}'::jsonb,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "vasi_admin_audit_createdAt_idx"
  on "vasi_admin_audit" ("createdAt" desc);

create index "vasi_admin_audit_targetUserId_idx"
  on "vasi_admin_audit" ("targetUserId");
