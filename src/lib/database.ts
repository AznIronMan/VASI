import { Pool } from "pg";

import { resolveServerEnvironment } from "@/lib/server-environment";

const globalForDatabase = globalThis as unknown as {
  vasiPool?: Pool;
};

const { databaseURL } = resolveServerEnvironment();

export const database =
  globalForDatabase.vasiPool ??
  new Pool({
    connectionString: databaseURL,
    max: Number(process.env.DATABASE_POOL_MAX ?? "10"),
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    ssl:
      process.env.DATABASE_SSL === "require"
        ? { rejectUnauthorized: true }
        : undefined,
  });

if (process.env.NODE_ENV !== "production") {
  globalForDatabase.vasiPool = database;
}
