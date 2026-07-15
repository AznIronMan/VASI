import { createHmac } from "node:crypto";

import type { Pool } from "pg";

import { clientAddressRateLimitIdentity } from "@/lib/client-address";
import { database } from "@/lib/database";

export const PUBLIC_VERIFICATION_RATE_LIMIT = 20;
export const PUBLIC_VERIFICATION_RATE_WINDOW_SECONDS = 60;

type QueryClient = Pick<Pool, "query">;

export async function consumePublicVerificationRateLimit({
  address,
  authSecret,
  client = database,
}: {
  address?: string;
  authSecret: string;
  client?: QueryClient;
}) {
  const identity = clientAddressRateLimitIdentity(address);
  const keyDigest = createHmac("sha256", authSecret)
    .update("vasi:public-verification-rate-limit:v1\0")
    .update(identity)
    .digest("hex");
  const result = await client.query<{ count: string; retryAfterSeconds: string }>(
    `with observation as (
       select clock_timestamp() as "observedAt"
     ), upserted as (
       insert into "vasi_public_verification_rate_limit" as current
         ("keyDigest", "count", "windowStartedAt", "expiresAt", "updatedAt")
       select $1, 1, "observedAt",
              "observedAt" + make_interval(secs => $2::double precision),
              "observedAt"
       from observation
       on conflict ("keyDigest") do update set
         "count" = case
           when current."expiresAt" <= excluded."updatedAt" then 1
           when current."count" = 2147483647 then current."count"
           else current."count" + 1
         end,
         "windowStartedAt" = case
           when current."expiresAt" <= excluded."updatedAt"
             then excluded."windowStartedAt"
           else current."windowStartedAt"
         end,
         "expiresAt" = case
           when current."expiresAt" <= excluded."updatedAt" then excluded."expiresAt"
           else current."expiresAt"
         end,
         "updatedAt" = excluded."updatedAt"
       returning "count", "expiresAt", "updatedAt"
     ), pruned as (
       delete from "vasi_public_verification_rate_limit"
       where "keyDigest" in (
         select "keyDigest"
         from "vasi_public_verification_rate_limit"
         where "keyDigest" <> $1
           and "expiresAt" < clock_timestamp() - interval '1 day'
         order by "expiresAt"
         limit 100
       )
       returning "keyDigest"
     )
     select "count"::text,
            greatest(1, ceil(extract(epoch from ("expiresAt" - "updatedAt"))))::text
              as "retryAfterSeconds"
     from upserted`,
    [keyDigest, PUBLIC_VERIFICATION_RATE_WINDOW_SECONDS],
  );
  if (result.rows.length !== 1) {
    throw new Error("Public verification rate-limit state is unavailable.");
  }
  const count = Number(result.rows[0].count);
  const retryAfterSeconds = Number(result.rows[0].retryAfterSeconds);
  if (!Number.isSafeInteger(count) || count < 1 || !Number.isSafeInteger(retryAfterSeconds)) {
    throw new Error("Public verification rate-limit state is invalid.");
  }
  return Object.freeze({
    accepted: count <= PUBLIC_VERIFICATION_RATE_LIMIT,
    retryAfterSeconds: Math.max(1, retryAfterSeconds),
  });
}
