import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import process from "node:process";
import { pathToFileURL } from "node:url";

import policy from "../config/assurance-policy.json" with { type: "json" };
import packageJSON from "../package.json" with { type: "json" };
import {
  evaluateGatewayOperationalReadiness,
  verifyAdminAuditChain,
} from "../packages/admin-audit/index.mjs";
import { GATEWAY_MIGRATIONS } from "./migrations.mjs";
import { createSettingsPool, loadBootstrapSettings } from "./settings-core.mjs";

export async function runGatewayOperationalReadinessProbe({
  bootstrap = loadBootstrapSettings(),
  thresholds = policy.gatewayOperations,
} = {}) {
  const expectedMigrations = await expectedMigrationChecksums();
  const database = createSettingsPool(bootstrap);
  const client = await database.connect();
  const started = performance.now();
  try {
    await client.query("begin isolation level repeatable read read only");
    const [chain, head, migrations, commands] = await Promise.all([
      client.query(`
        select "id", "actorUserId", "targetUserId", "action", "metadata", "createdAt",
               "commandId", "phase", "requestId", "actorSessionId", "ipAddress",
               "userAgent", "sequence", "previousHash", "canonicalPayload", "eventHash"
        from "vasi_admin_audit" order by "sequence"
      `),
      client.query(`
        select "lastSequence", "lastHash"
        from "vasi_admin_audit_chain_head" where "id" = 1
      `),
      client.query('select "name", "checksum" from "_vasi_migrations" order by "name"'),
      client.query(`
        with incomplete as (
          select started."createdAt"
          from "vasi_admin_audit" started
          where started."phase" = 'started'
            and not exists (
              select 1 from "vasi_admin_audit" terminal
              where terminal."commandId" = started."commandId"
                and terminal."phase" in ('succeeded', 'failed', 'ambiguous')
            )
        )
        select
          (select count(*)::text from incomplete) as "incomplete",
          coalesce((select greatest(0, extract(epoch from CURRENT_TIMESTAMP - min("createdAt")))::bigint::text from incomplete), '0') as "oldestIncompleteSeconds",
          (select count(*)::text from "vasi_admin_audit"
           where "phase" = 'ambiguous'
             and "createdAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "ambiguous24Hours"
      `),
    ]);
    await client.query("commit");
    const snapshot = buildGatewayOperationalSnapshot({
      chainRows: chain.rows,
      commandRow: commands.rows[0],
      expectedMigrations,
      generatedAt: new Date().toISOString(),
      headRow: head.rows[0],
      migrationRows: migrations.rows,
      queryMilliseconds: Math.ceil(performance.now() - started),
    });
    return Object.freeze({
      assessment: evaluateGatewayOperationalReadiness(snapshot, thresholds),
      snapshot,
    });
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await database.end();
  }
}

export function buildGatewayOperationalSnapshot({
  chainRows,
  commandRow,
  expectedMigrations,
  generatedAt,
  headRow,
  migrationRows,
  queryMilliseconds,
}) {
  const integrity = verifyAdminAuditChain(chainRows, headRow);
  const actual = new Map(migrationRows.map((row) => [row.name, row.checksum]));
  const migrationsValid = actual.size === expectedMigrations.size &&
    [...expectedMigrations].every(([name, checksum]) => actual.get(name) === checksum);
  return Object.freeze({
    audit: Object.freeze({
      events: integrity.count,
      failureCode: integrity.firstFailure?.code || null,
      headMatches: integrity.headMatches,
      lastSequence: integrity.lastSequence,
      valid: integrity.valid,
    }),
    commands: Object.freeze({
      ambiguous24Hours: nonnegativeSafeInteger(commandRow?.ambiguous24Hours, "ambiguous command count"),
      incomplete: nonnegativeSafeInteger(commandRow?.incomplete, "incomplete command count"),
      oldestIncompleteSeconds: nonnegativeSafeInteger(
        commandRow?.oldestIncompleteSeconds,
        "oldest incomplete command age",
      ),
    }),
    database: Object.freeze({ queryMilliseconds }),
    gatewayVersion: packageJSON.version,
    generatedAt,
    migrations: Object.freeze({
      applied: actual.size,
      expected: expectedMigrations.size,
      valid: migrationsValid,
    }),
    schema: "vasi-gateway-operational-readiness/v1",
  });
}

export function parseGatewayOperationalArguments(argumentsList) {
  const mapping = {
    "--maximum-database-ms": "maximumDatabaseQueryMilliseconds",
    "--maximum-incomplete-command-seconds": "maximumIncompleteCommandSeconds",
  };
  const thresholds = { ...policy.gatewayOperations };
  for (let index = 0; index < argumentsList.length; index += 2) {
    const key = mapping[argumentsList[index]];
    const value = Number(argumentsList[index + 1]);
    if (!key || !Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Invalid gateway operational-readiness option ${argumentsList[index] || "(missing)"}.`);
    }
    thresholds[key] = value;
  }
  return thresholds;
}

async function expectedMigrationChecksums() {
  return new Map(await Promise.all(GATEWAY_MIGRATIONS.map(async (migration) => [
    migration.name,
    createHash("sha256").update(await readFile(migration.path, "utf8")).digest("hex"),
  ])));
}

function nonnegativeSafeInteger(value, label) {
  const normalized = Number(value || 0);
  if (!Number.isSafeInteger(normalized) || normalized < 0) {
    throw new Error(`The gateway operational ${label} is invalid.`);
  }
  return normalized;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runGatewayOperationalReadinessProbe({
    thresholds: parseGatewayOperationalArguments(process.argv.slice(2)),
  }).then((result) => {
    console.info(JSON.stringify(result, null, 2));
    if (result.assessment.status !== "pass") process.exitCode = 1;
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : "VASI gateway operational readiness probe failed.");
    process.exitCode = 1;
  });
}
