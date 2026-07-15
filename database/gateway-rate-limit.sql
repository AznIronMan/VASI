-- Durable, privacy-bounded throttling for unauthenticated gateway operations.

create table "vasi_gateway_rate_limit" (
  "keyDigest" text primary key,
  "count" integer not null check ("count" > 0),
  "windowStartedAt" timestamptz not null,
  "expiresAt" timestamptz not null,
  "updatedAt" timestamptz not null,
  constraint "vasi_gateway_rate_limit_digest_valid"
    check ("keyDigest" ~ '^[a-f0-9]{64}$'),
  constraint "vasi_gateway_rate_limit_window_valid"
    check ("expiresAt" > "windowStartedAt")
);

create index "vasi_gateway_rate_limit_expiry_idx"
  on "vasi_gateway_rate_limit" ("expiresAt");

comment on table "vasi_gateway_rate_limit" is
  'Mutable public-gateway throttle state keyed only by domain-separated HMAC values; raw client addresses and request values are never stored.';
