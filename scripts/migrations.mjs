import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { createSettingsPool, loadBootstrapSettings } from "./settings-core.mjs";

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
  {
    name: "0003_encrypted_runtime_settings",
    path: path.join(repositoryRoot, "database", "settings-schema.sql"),
  },
];

export async function runMigrations(bootstrap = loadBootstrapSettings()) {
  const pool = createSettingsPool(bootstrap);
  const client = await pool.connect();
  const applied = [];

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
        applied.push(migration.name);
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw error;
      }
    }
    return applied;
  } finally {
    client.release();
    await pool.end();
  }
}
