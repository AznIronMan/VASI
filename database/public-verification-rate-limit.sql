-- Durable, privacy-bounded throttling for unauthenticated manifest verification.

create table "vasi_public_verification_rate_limit" (
  "keyDigest" text primary key,
  "count" integer not null check ("count" > 0),
  "windowStartedAt" timestamptz not null,
  "expiresAt" timestamptz not null,
  "updatedAt" timestamptz not null,
  constraint "vasi_public_verification_rate_limit_digest_valid"
    check ("keyDigest" ~ '^[a-f0-9]{64}$'),
  constraint "vasi_public_verification_rate_limit_window_valid"
    check ("expiresAt" > "windowStartedAt")
);

create index "vasi_public_verification_rate_limit_expiry_idx"
  on "vasi_public_verification_rate_limit" ("expiresAt");

comment on table "vasi_public_verification_rate_limit" is
  'Mutable public-verification throttle state keyed by a domain-separated HMAC; raw client addresses are never stored.';
