import { describe, expect, it, vi } from "vitest";

import { createOperationsStore, operationalAssessment } from "./operations-store.mjs";

const summary = {
  activeBindings: 1,
  activeIntegrityKeys: 1,
  activeOptionalKeys: 0,
  activeTenants: 2,
  configurationChanges24Hours: 3,
  delivered24Hours: 4,
  deliveryFailures24Hours: 0,
  disabledBindings: 1,
  disabledTenants: 1,
  failedJobs24Hours: 0,
  gatewayFailures24Hours: 0,
  installationProfileRevision: 2,
  installationProfiles: 1,
  lastConfigurationChangeSeconds: 10,
  lastSettingChangeSeconds: 20,
  oldestDataRequestSeconds: 0,
  oldestPendingSeconds: 0,
  observedAt: new Date("2026-07-14T14:00:00.000Z"),
  pendingDataRequests: 0,
  pendingJobs: 0,
  purgeBlocked24Hours: 0,
  purgeDueRecords: 0,
  runningJobs: 0,
  settingChanges24Hours: 1,
  staleRunningJobs: 0,
  suppressed24Hours: 0,
  untrustedKeys: 0,
  verifiedAdapters: 4,
};

function database(overrides = {}, errors = []) {
  return {
    idleCount: 1,
    options: { max: 10 },
    query: vi.fn(async (query) => {
      if (query.includes("_vasi_engine_migrations")) {
        return { rowCount: 1, rows: [{ checksum: "checksum-1", name: "0001" }] };
      }
      if (query.includes("group by coalesce")) return { rowCount: errors.length, rows: errors };
      return { rowCount: 1, rows: [{ ...summary, ...overrides }] };
    }),
    totalCount: 1,
    waitingCount: 0,
  };
}

const dependencies = {
  engineVersion: "0.16.0",
  migrationManifest: async () => [{ checksum: "checksum-1", name: "0001" }],
};

describe("operational readiness store", () => {
  it("returns a bounded aggregate without participant, tenant, request, or credential data", async () => {
    const store = createOperationsStore(database({}, [
      { code: "graph_token_status", count: 2 },
      { code: "person@example.test secret-value", count: 1 },
    ]), dependencies);
    const snapshot = await store.snapshot({ roles: ["admin"] });
    expect(snapshot).toMatchObject({
      configuration: { migrationDrift: false, migrationsApplied: 1, migrationsExpected: 1 },
      delivery: {
        recentErrorCodes: [
          { code: "graph_token_status", count: 2 },
          { code: "delivery_failed", count: 1 },
        ],
      },
      engineVersion: "0.16.0",
      schema: "vasi-operational-snapshot/v1",
      status: "ready",
    });
    const serialized = JSON.stringify(snapshot);
    for (const forbidden of ["person@example.test", "secret-value", "tenantId", "requestId", "recipient", "payload"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("requires an administrator actor", async () => {
    const store = createOperationsStore(database(), dependencies);
    await expect(store.snapshot({ roles: ["owner"] })).rejects.toMatchObject({
      code: "administrator_required",
      status: 403,
    });
  });

  it("marks integrity, migration, and stuck-worker failures critical", async () => {
    const store = createOperationsStore(database({
      activeIntegrityKeys: 0,
      staleRunningJobs: 1,
    }), {
      ...dependencies,
      migrationManifest: async () => [{ checksum: "different", name: "0001" }],
    });
    const snapshot = await store.snapshot({ roles: ["admin"] });
    expect(snapshot.status).toBe("critical");
    expect(snapshot.reasons).toEqual([
      "migration_drift",
      "integrity_key_unavailable",
      "stale_running_jobs",
    ]);
  });

  it("distinguishes actionable attention from a critical failure", () => {
    const assessment = operationalAssessment({
      configuration: { installationProfilePresent: true, migrationDrift: false },
      database: { pool: { waiting: 0 } },
      delivery: { activeBindings: 0, gatewayFailures24Hours: 0 },
      lifecycle: { purgeBlocked24Hours: 0 },
      queue: { failed24Hours: 0, staleRunning: 0 },
      signing: { activeIntegrityKeys: 1 },
      tenancy: { active: 0 },
    });
    expect(assessment).toEqual({
      reasons: ["no_active_tenants", "no_active_delivery_binding"],
      status: "attention",
    });
  });
});
