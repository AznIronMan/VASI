import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pg from "pg";

const { Pool } = pg;
const migrationName = "0001_auth_foundation";
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationPath = path.join(repositoryRoot, "database", "auth-schema.sql");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required to run migrations.");
}

const sql = await readFile(migrationPath, "utf8");
const checksum = createHash("sha256").update(sql).digest("hex");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "require" ? { rejectUnauthorized: true } : undefined,
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

  const existing = await client.query(
    'select "checksum" from "_vasi_migrations" where "name" = $1',
    [migrationName],
  );

  if (existing.rowCount) {
    if (existing.rows[0].checksum !== checksum) {
      throw new Error(`Migration ${migrationName} changed after it was applied.`);
    }

    console.info(`Migration ${migrationName} is already applied.`);
  } else {
    await client.query("begin");
    await client.query(sql);
    await client.query(
      'insert into "_vasi_migrations" ("name", "checksum") values ($1, $2)',
      [migrationName, checksum],
    );
    await client.query("commit");
    console.info(`Applied migration ${migrationName}.`);
  }
} catch (error) {
  await client.query("rollback").catch(() => undefined);
  throw error;
} finally {
  client.release();
  await pool.end();
}
