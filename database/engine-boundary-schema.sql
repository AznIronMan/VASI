-- Private VASI engine boundary. Domain evidence tables arrive in later,
-- independently versioned engine migrations.

create schema "vasi_engine" authorization CURRENT_USER;

create table "vasi_engine"."actor_assertion_replay" (
  "jti" text primary key,
  "issuer" text not null,
  "subject" text not null,
  "expiresAt" timestamptz not null,
  "receivedAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "actor_assertion_replay_expires_idx"
  on "vasi_engine"."actor_assertion_replay" ("expiresAt");

create table "vasi_engine"."outbox_job" (
  "id" text primary key,
  "jobType" text not null,
  "payload" jsonb not null,
  "status" text not null default 'pending'
    check ("status" in ('pending', 'running', 'completed', 'failed')),
  "attempts" integer not null default 0 check ("attempts" >= 0),
  "availableAt" timestamptz not null default CURRENT_TIMESTAMP,
  "lockedAt" timestamptz,
  "lockedBy" text,
  "lastErrorCode" text,
  "createdAt" timestamptz not null default CURRENT_TIMESTAMP,
  "updatedAt" timestamptz not null default CURRENT_TIMESTAMP
);

create index "outbox_job_claim_idx"
  on "vasi_engine"."outbox_job" ("status", "availableAt", "createdAt");

revoke all on schema "vasi_engine" from PUBLIC;
revoke all on all tables in schema "vasi_engine" from PUBLIC;
