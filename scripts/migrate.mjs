import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pg from "pg";

const { Pool } = pg;
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrations = [
  {
    name: "0001_auth_foundation",
    path: path.join(repositoryRoot, "database", "auth-schema.sql"),
  },
  {
    name: "0002_identity_administration",
    path: path.join(repositoryRoot, "database", "admin-schema.sql"),
  },
];

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required to run migrations.");
}

if (
  process.env.DATABASE_SSL !== undefined &&
  !["disable", "require"].includes(process.env.DATABASE_SSL)
) {
  throw new Error("DATABASE_SSL must be either require or disable.");
}

const databaseURL = new URL(process.env.DATABASE_URL);
if (process.env.DATABASE_SSL) {
  databaseURL.searchParams.set(
    "sslmode",
    process.env.DATABASE_SSL === "require" ? "verify-full" : "disable",
  );
}

const pool = new Pool({
  connectionString: databaseURL.toString(),
  ssl:
    process.env.DATABASE_SSL === "require"
      ? { rejectUnauthorized: true }
      : process.env.DATABASE_SSL === "disable"
        ? false
        : undefined,
});
const client = await pool.connect();

try {
  await client.query(`
    create table if not exists "_vasi_migrations" (
      "name" text primary key,
      "checksum" text not null,
      "appliedAt" timestamptz not null default CURRENT_TIMESTAMP
    )
  `);

  for (const migration of migrations) {
    const sql = await readFile(migration.path, "utf8");
    const checksum = createHash("sha256").update(sql).digest("hex");
    const existing = await client.query(
      'select "checksum" from "_vasi_migrations" where "name" = $1',
      [migration.name],
    );

    if (existing.rowCount) {
      if (existing.rows[0].checksum !== checksum) {
        throw new Error(`Migration ${migration.name} changed after it was applied.`);
      }

      console.info(`Migration ${migration.name} is already applied.`);
      continue;
    }

    await client.query("begin");
    try {
      await client.query(sql);
      await client.query(
        'insert into "_vasi_migrations" ("name", "checksum") values ($1, $2)',
        [migration.name, checksum],
      );
      await client.query("commit");
      console.info(`Applied migration ${migration.name}.`);
    } catch (error) {
      await client.query("rollback").catch(() => undefined);
      throw error;
    }
  }
} catch (error) {
  throw error;
} finally {
  client.release();
  await pool.end();
}
