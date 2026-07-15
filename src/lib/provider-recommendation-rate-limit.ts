import { createHmac } from "node:crypto";

import type { Pool } from "pg";

import { clientAddressRateLimitIdentity } from "@/lib/client-address";
import { database } from "@/lib/database";

export const PROVIDER_RECOMMENDATION_CLIENT_LIMIT = 30;
export const PROVIDER_RECOMMENDATION_GLOBAL_LIMIT = 600;
export const PROVIDER_RECOMMENDATION_RATE_WINDOW_SECONDS = 60;

type QueryClient = Pick<Pool, "query">;

export async function consumeProviderRecommendationRateLimit({
  address,
  authSecret,
  client = database,
}: {
  address?: string;
  authSecret: string;
  client?: QueryClient;
}) {
  const clientDigest = digest(
    authSecret,
    "client",
    clientAddressRateLimitIdentity(address),
  );
  const globalDigest = digest(authSecret, "installation", "global");
  const currentDigests = [clientDigest, globalDigest];
  const result = await client.query<{
    count: string;
    keyDigest: string;
    maximum: string;
    retryAfterSeconds: string;
  }>(
    `with observation as (
       select clock_timestamp() as "observedAt"
     ), limits ("keyDigest", "maximum") as (
       values ($1::text, $3::integer), ($2::text, $4::integer)
     ), upserted as (
       insert into "vasi_gateway_rate_limit" as current
         ("keyDigest", "count", "windowStartedAt", "expiresAt", "updatedAt")
       select limits."keyDigest", 1, observation."observedAt",
              observation."observedAt" + make_interval(secs => $5::double precision),
              observation."observedAt"
       from limits cross join observation
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
       returning "keyDigest", "count", "expiresAt", "updatedAt"
     ), pruned as (
       delete from "vasi_gateway_rate_limit"
       where "keyDigest" in (
         select "keyDigest"
         from "vasi_gateway_rate_limit"
         where not ("keyDigest" = any($6::text[]))
           and "expiresAt" < clock_timestamp() - interval '1 day'
         order by "expiresAt"
         limit 100
       )
       returning "keyDigest"
     )
     select upserted."keyDigest", upserted."count"::text,
            limits."maximum"::text,
            greatest(
              1,
              ceil(extract(epoch from (upserted."expiresAt" - upserted."updatedAt")))
            )::text as "retryAfterSeconds"
     from upserted
     join limits using ("keyDigest")`,
    [
      clientDigest,
      globalDigest,
      PROVIDER_RECOMMENDATION_CLIENT_LIMIT,
      PROVIDER_RECOMMENDATION_GLOBAL_LIMIT,
      PROVIDER_RECOMMENDATION_RATE_WINDOW_SECONDS,
      currentDigests,
    ],
  );
  if (result.rows.length !== 2) {
    throw new Error("Provider recommendation rate-limit state is unavailable.");
  }
  const expected = new Set(currentDigests);
  const decisions = result.rows.map((row) => {
    if (!expected.delete(row.keyDigest)) {
      throw new Error("Provider recommendation rate-limit state is invalid.");
    }
    const count = Number(row.count);
    const maximum = Number(row.maximum);
    const retryAfterSeconds = Number(row.retryAfterSeconds);
    if (
      !Number.isSafeInteger(count) || count < 1 ||
      !Number.isSafeInteger(maximum) || maximum < 1 ||
      !Number.isSafeInteger(retryAfterSeconds) || retryAfterSeconds < 1
    ) {
      throw new Error("Provider recommendation rate-limit state is invalid.");
    }
    return { accepted: count <= maximum, retryAfterSeconds };
  });
  if (expected.size) {
    throw new Error("Provider recommendation rate-limit state is invalid.");
  }
  const denied = decisions.filter((decision) => !decision.accepted);
  return Object.freeze({
    accepted: denied.length === 0,
    retryAfterSeconds: Math.max(...(denied.length ? denied : decisions)
      .map((decision) => decision.retryAfterSeconds)),
  });
}

function digest(authSecret: string, bucket: string, identity: string) {
  return createHmac("sha256", authSecret)
    .update("vasi:provider-recommendation-rate-limit:v1\0")
    .update(bucket)
    .update("\0")
    .update(identity)
    .digest("hex");
}
