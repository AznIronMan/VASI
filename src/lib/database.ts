import { Pool } from "pg";

import { resolveDatabaseConnectionOptions } from "@/lib/database-config";
import { resolveServerEnvironment } from "@/lib/server-environment";

const globalForDatabase = globalThis as unknown as {
  vasiPool?: Pool;
};

const { databaseURL } = resolveServerEnvironment();
const connectionOptions = resolveDatabaseConnectionOptions(
  databaseURL,
  process.env.DATABASE_SSL,
);

export const database =
  globalForDatabase.vasiPool ??
  new Pool({
    ...connectionOptions,
    max: Number(process.env.DATABASE_POOL_MAX ?? "10"),
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
  });

if (process.env.NODE_ENV !== "production") {
  globalForDatabase.vasiPool = database;
}
