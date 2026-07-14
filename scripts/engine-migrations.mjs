import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { createSettingsPool, loadBootstrapSettings } from "./settings-core.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const ENGINE_MIGRATIONS = Object.freeze([
  {
    name: "0001_engine_settings",
    path: path.join(repositoryRoot, "database", "settings-schema.sql"),
  },
  {
    name: "0002_engine_boundary",
    path: path.join(repositoryRoot, "database", "engine-boundary-schema.sql"),
  },
  {
    name: "0003_engine_evidence_slice",
    path: path.join(repositoryRoot, "database", "engine-evidence-slice.sql"),
  },
  {
    name: "0004_engine_workflow_control_plane",
    path: path.join(repositoryRoot, "database", "engine-workflow-control-plane.sql"),
  },
  {
    name: "0005_engine_document_activities",
    path: path.join(repositoryRoot, "database", "engine-document-activities.sql"),
  },
  {
    name: "0006_engine_media_evidence",
    path: path.join(repositoryRoot, "database", "engine-media-evidence.sql"),
  },
  {
    name: "0007_engine_evidence_reports",
    path: path.join(repositoryRoot, "database", "engine-evidence-reports.sql"),
  },
  {
    name: "0008_engine_lifecycle_governance",
    path: path.join(repositoryRoot, "database", "engine-lifecycle-governance.sql"),
  },
  {
    name: "0009_engine_productization",
    path: path.join(repositoryRoot, "database", "engine-productization.sql"),
  },
  {
    name: "0010_engine_activity_interaction",
    path: path.join(repositoryRoot, "database", "engine-activity-interaction.sql"),
  },
  {
    name: "0011_engine_participant_context",
    path: path.join(repositoryRoot, "database", "engine-participant-context.sql"),
  },
  {
    name: "0012_engine_document_malware_scanning",
    path: path.join(repositoryRoot, "database", "engine-document-malware-scanning.sql"),
  },
].map((migration) => Object.freeze(migration)));

export async function engineMigrationManifest() {
  return Promise.all(ENGINE_MIGRATIONS.map(async (migration) => ({
    checksum: createHash("sha256").update(await readFile(migration.path, "utf8")).digest("hex"),
    name: migration.name,
  })));
}

export async function runEngineMigrations(bootstrap = loadBootstrapSettings()) {
  const pool = createSettingsPool(bootstrap);
  const client = await pool.connect();
  const applied = [];

  try {
    // Once the engine-owned schema exists, PostgreSQL's default "$user"
    // search path would otherwise shadow the public migration ledger on the
    // next release. Keep the ledger and unqualified legacy settings migration
    // anchored to public for every run.
    await client.query("set search_path to public, pg_catalog");
    await client.query(`
      create table if not exists public."_vasi_engine_migrations" (
        "name" text primary key,
        "checksum" text not null,
        "appliedAt" timestamptz not null default CURRENT_TIMESTAMP
      )
    `);

    for (const migration of ENGINE_MIGRATIONS) {
      const sql = await readFile(migration.path, "utf8");
      const checksum = createHash("sha256").update(sql).digest("hex");
      const existing = await client.query(
        'select "checksum" from public."_vasi_engine_migrations" where "name" = $1',
        [migration.name],
      );
      if (existing.rowCount) {
        if (existing.rows[0].checksum !== checksum) {
          throw new Error(`Engine migration ${migration.name} changed after it was applied.`);
        }
        continue;
      }

      await client.query("begin");
      try {
        await client.query(sql);
        await client.query(
          'insert into public."_vasi_engine_migrations" ("name", "checksum") values ($1, $2)',
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
