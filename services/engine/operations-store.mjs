import { performance } from "node:perf_hooks";

import { engineMigrationManifest } from "../../scripts/engine-migrations.mjs";
import { EngineStoreError } from "./errors.mjs";

const SUMMARY_QUERY = `
  with latest_key_status as (
    select distinct on (k."keyId") k."sealRole", s."status"
    from "vasi_engine"."evidence_seal_key" k
    join "vasi_engine"."evidence_seal_key_status_event" s on s."keyId" = k."keyId"
    order by k."keyId", s."recordedAt" desc, s."id" desc
  )
  select
    CURRENT_TIMESTAMP as "observedAt",
    (select count(*)::integer from "vasi_engine"."tenant" where "status" = 'active') as "activeTenants",
    (select count(*)::integer from "vasi_engine"."tenant" where "status" = 'disabled') as "disabledTenants",
    (select count(*)::integer from "vasi_engine"."outbox_job" where "status" = 'pending') as "pendingJobs",
    (select count(*)::integer from "vasi_engine"."outbox_job" where "status" = 'running') as "runningJobs",
    (select count(*)::integer from "vasi_engine"."outbox_job"
      where "status" = 'running' and "lockedAt" < CURRENT_TIMESTAMP - interval '10 minutes') as "staleRunningJobs",
    (select count(*)::integer from "vasi_engine"."outbox_job"
      where "status" = 'failed' and "updatedAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "failedJobs24Hours",
    coalesce((select floor(extract(epoch from (CURRENT_TIMESTAMP - min("createdAt"))))::bigint
      from "vasi_engine"."outbox_job" where "status" = 'pending'), 0) as "oldestPendingSeconds",
    (select count(*)::integer from "vasi_engine"."notification_delivery_attempt"
      where "outcome" = 'delivered' and "completedAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "delivered24Hours",
    (select count(*)::integer from "vasi_engine"."notification_delivery_attempt"
      where "outcome" = 'failed' and "completedAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "deliveryFailures24Hours",
    (select count(*)::integer from "vasi_engine"."notification_delivery_attempt"
      where "outcome" = 'suppressed' and "completedAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "suppressed24Hours",
    (select count(*)::integer from "vasi_engine"."integration_gateway_attempt"
      where "outcome" = 'failed' and "completedAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "gatewayFailures24Hours",
    (select count(*)::integer from "vasi_engine"."integration_binding_revision" r
      join "vasi_engine"."integration_binding_pointer" p on p."activeRevisionId" = r."id"
      where r."status" = 'active') as "activeBindings",
    (select count(*)::integer from "vasi_engine"."integration_binding_revision" r
      join "vasi_engine"."integration_binding_pointer" p on p."activeRevisionId" = r."id"
      where r."status" = 'disabled') as "disabledBindings",
    (select count(*)::integer from "vasi_engine"."integration_adapter_registry"
      where "conformanceStatus" = 'built_in_verified') as "verifiedAdapters",
    (select count(*)::integer from "vasi_engine"."record_lifecycle_state"
      where "evidenceStatus" = 'purge_due') as "purgeDueRecords",
    (select count(*)::integer from "vasi_engine"."record_lifecycle_event"
      where "eventType" = 'purge.blocked' and "createdAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "purgeBlocked24Hours",
    (select count(*)::integer from "vasi_engine"."participant_data_request"
      where "status" = 'pending_review') as "pendingDataRequests",
    coalesce((select floor(extract(epoch from (CURRENT_TIMESTAMP - min("requestedAt"))))::bigint
      from "vasi_engine"."participant_data_request" where "status" = 'pending_review'), 0) as "oldestDataRequestSeconds",
    (select count(*)::integer from latest_key_status
      where "sealRole" = 'vasi_integrity' and "status" = 'active') as "activeIntegrityKeys",
    (select count(*)::integer from latest_key_status
      where "sealRole" <> 'vasi_integrity' and "status" = 'active') as "activeOptionalKeys",
    (select count(*)::integer from latest_key_status
      where "status" in ('compromised', 'revoked')) as "untrustedKeys",
    (select count(*)::integer from "vasi_engine"."installation_profile_pointer") as "installationProfiles",
    coalesce((select max("revision")::integer from "vasi_engine"."installation_profile_pointer"), 0) as "installationProfileRevision",
    (select count(*)::integer from "vasi_engine"."product_configuration_event"
      where "createdAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "configurationChanges24Hours",
    coalesce((select floor(extract(epoch from (CURRENT_TIMESTAMP - max("createdAt"))))::bigint
      from "vasi_engine"."product_configuration_event"), 0) as "lastConfigurationChangeSeconds",
    (select count(*)::integer from public."vasi_runtime_setting_audit"
      where "scope" = 'engine' and "createdAt" >= CURRENT_TIMESTAMP - interval '24 hours') as "settingChanges24Hours",
    coalesce((select floor(extract(epoch from (CURRENT_TIMESTAMP - max("createdAt"))))::bigint
      from public."vasi_runtime_setting_audit" where "scope" = 'engine'), 0) as "lastSettingChangeSeconds"`;

const RECENT_ERROR_QUERY = `
  select coalesce("errorCode", 'delivery_failed') as "code", count(*)::integer as "count"
  from "vasi_engine"."integration_gateway_attempt"
  where "outcome" = 'failed' and "completedAt" >= CURRENT_TIMESTAMP - interval '24 hours'
  group by coalesce("errorCode", 'delivery_failed')
  order by count(*) desc, coalesce("errorCode", 'delivery_failed')
  limit 10`;

export function createOperationsStore(database, {
  engineVersion = "unknown",
  migrationManifest = engineMigrationManifest,
} = {}) {
  return Object.freeze({
    async snapshot(actor) {
      requireAdministrator(actor);
      return collectOperationalSnapshot(database, { engineVersion, migrationManifest });
    },
  });
}

export async function collectOperationalSnapshot(database, {
  engineVersion = "unknown",
  migrationManifest = engineMigrationManifest,
} = {}) {
  const started = performance.now();
  const [summary, recentErrors, migrationLedger, expectedMigrations] = await Promise.all([
    database.query(SUMMARY_QUERY),
    database.query(RECENT_ERROR_QUERY),
    database.query('select "name", "checksum" from public."_vasi_engine_migrations" order by "name"'),
    migrationManifest(),
  ]);
  const queryMilliseconds = Math.max(0, performance.now() - started);
  if (summary.rowCount !== 1) throw new EngineStoreError("operations_snapshot_unavailable", 500);
  const row = summary.rows[0];
  const migrationDrift = !sameMigrationLedger(migrationLedger.rows, expectedMigrations);
  const snapshot = {
    configuration: {
      changes24Hours: safeNumber(row.configurationChanges24Hours),
      installationProfilePresent: safeNumber(row.installationProfiles) === 1,
      installationProfileRevision: safeNumber(row.installationProfileRevision),
      lastChangeSeconds: safeNumber(row.lastConfigurationChangeSeconds),
      lastSettingChangeSeconds: safeNumber(row.lastSettingChangeSeconds),
      migrationDrift,
      migrationsApplied: migrationLedger.rows.length,
      migrationsExpected: expectedMigrations.length,
      settingChanges24Hours: safeNumber(row.settingChanges24Hours),
    },
    database: {
      pool: {
        idle: safeNumber(database.idleCount),
        maximum: safeNumber(database.options?.max),
        total: safeNumber(database.totalCount),
        waiting: safeNumber(database.waitingCount),
      },
      queryMilliseconds: Number(queryMilliseconds.toFixed(2)),
    },
    delivery: {
      activeBindings: safeNumber(row.activeBindings),
      delivered24Hours: safeNumber(row.delivered24Hours),
      disabledBindings: safeNumber(row.disabledBindings),
      failed24Hours: safeNumber(row.deliveryFailures24Hours),
      gatewayFailures24Hours: safeNumber(row.gatewayFailures24Hours),
      recentErrorCodes: normalizeErrorCounts(recentErrors.rows),
      suppressed24Hours: safeNumber(row.suppressed24Hours),
      verifiedAdapters: safeNumber(row.verifiedAdapters),
    },
    engineVersion: boundedVersion(engineVersion),
    generatedAt: validDate(row.observedAt).toISOString(),
    lifecycle: {
      oldestPendingDataRequestSeconds: safeNumber(row.oldestDataRequestSeconds),
      pendingDataRequests: safeNumber(row.pendingDataRequests),
      purgeBlocked24Hours: safeNumber(row.purgeBlocked24Hours),
      purgeDueRecords: safeNumber(row.purgeDueRecords),
    },
    queue: {
      failed24Hours: safeNumber(row.failedJobs24Hours),
      oldestPendingSeconds: safeNumber(row.oldestPendingSeconds),
      pending: safeNumber(row.pendingJobs),
      running: safeNumber(row.runningJobs),
      staleRunning: safeNumber(row.staleRunningJobs),
    },
    schema: "vasi-operational-snapshot/v1",
    signing: {
      activeIntegrityKeys: safeNumber(row.activeIntegrityKeys),
      activeOptionalKeys: safeNumber(row.activeOptionalKeys),
      untrustedKeys: safeNumber(row.untrustedKeys),
    },
    tenancy: {
      active: safeNumber(row.activeTenants),
      disabled: safeNumber(row.disabledTenants),
    },
  };
  const assessment = operationalAssessment(snapshot);
  return Object.freeze({ ...snapshot, ...assessment });
}

export function operationalAssessment(snapshot) {
  const critical = [];
  const attention = [];
  if (snapshot.configuration.migrationDrift) critical.push("migration_drift");
  if (!snapshot.configuration.installationProfilePresent) critical.push("installation_profile_missing");
  if (snapshot.signing.activeIntegrityKeys < 1) critical.push("integrity_key_unavailable");
  if (snapshot.queue.staleRunning > 0) critical.push("stale_running_jobs");
  if (snapshot.queue.failed24Hours > 0) attention.push("recent_failed_jobs");
  if (snapshot.delivery.gatewayFailures24Hours > 0) attention.push("recent_delivery_failures");
  if (snapshot.lifecycle.purgeBlocked24Hours > 0) attention.push("recent_purge_blocks");
  if (snapshot.database.pool.waiting > 0) attention.push("database_pool_waiting");
  if (snapshot.tenancy.active < 1) attention.push("no_active_tenants");
  if (snapshot.delivery.activeBindings < 1) attention.push("no_active_delivery_binding");
  const reasons = Object.freeze([...critical, ...attention]);
  return Object.freeze({
    reasons,
    status: critical.length ? "critical" : attention.length ? "attention" : "ready",
  });
}

function sameMigrationLedger(actual, expected) {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  const normalized = new Map(actual.map((entry) => [entry.name, entry.checksum]));
  return expected.every((entry) => normalized.get(entry.name) === entry.checksum);
}

function normalizeErrorCounts(rows) {
  return Object.freeze(rows.slice(0, 10).map((row) => ({
    code: typeof row.code === "string" && /^[a-z0-9_]{1,64}$/.test(row.code)
      ? row.code
      : "delivery_failed",
    count: safeNumber(row.count),
  })));
}

function safeNumber(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : 0;
}

function validDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new EngineStoreError("operations_snapshot_unavailable", 500);
  return date;
}

function boundedVersion(value) {
  return typeof value === "string" && /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/.test(value)
    ? value
    : "unknown";
}

function requireAdministrator(actor) {
  if (!actor?.roles?.includes("admin")) throw new EngineStoreError("administrator_required", 403);
}
