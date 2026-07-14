import { Pool } from "pg";

import { loadBootstrapSettings } from "@/lib/bootstrap-settings";
import { resolveDatabaseConnectionOptions } from "@/lib/database-config";

const globalForDatabase = globalThis as unknown as {
  vasiPool?: Pool;
};

export function getDatabase() {
  if (globalForDatabase.vasiPool) return globalForDatabase.vasiPool;

  const bootstrap = loadBootstrapSettings();
  const connectionOptions = resolveDatabaseConnectionOptions(
    bootstrap.databaseURL,
    bootstrap.databaseSSL,
  );
  const pool = new Pool({
    ...connectionOptions,
    max: bootstrap.databasePoolMax,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
  });
  globalForDatabase.vasiPool = pool;
  return pool;
}

export const database = new Proxy({} as Pool, {
  get(_target, property) {
    const pool = getDatabase();
    const value = Reflect.get(pool, property, pool);
    return typeof value === "function" ? value.bind(pool) : value;
  },
});
