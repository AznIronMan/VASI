import { describe, expect, it } from "vitest";

import { evaluateOperationalReadiness } from "./probe-operational-readiness.mjs";

function snapshot(overrides = {}) {
  return {
    configuration: { installationProfilePresent: true, migrationDrift: false },
    database: { pool: { waiting: 0 }, queryMilliseconds: 12 },
    delivery: { activeBindings: 1, gatewayFailures24Hours: 0 },
    lifecycle: { oldestPendingDataRequestSeconds: 0, pendingDataRequests: 0 },
    queue: { failed24Hours: 0, oldestPendingSeconds: 0, pending: 0, staleRunning: 0 },
    reasons: [],
    signing: { activeIntegrityKeys: 1 },
    ...overrides,
  };
}

const thresholds = {
  maximumDatabaseQueryMilliseconds: 100,
  maximumDatabaseWaitingClients: 0,
  maximumFailedJobs24Hours: 0,
  maximumGatewayFailures24Hours: 0,
  maximumOldestPendingDataRequestSeconds: 1000,
  maximumOldestPendingSeconds: 60,
  maximumStaleRunningJobs: 0,
};

describe("operational readiness policy", () => {
  it("passes a healthy snapshot while retaining non-blocking setup warnings", () => {
    expect(evaluateOperationalReadiness(snapshot({
      reasons: ["no_active_delivery_binding", "no_active_tenants"],
    }), thresholds)).toEqual({
      failures: [],
      status: "pass",
      warnings: ["no_active_delivery_binding", "no_active_tenants"],
    });
  });

  it("fails bounded queue, delivery, database, migration, and review-age thresholds", () => {
    const result = evaluateOperationalReadiness(snapshot({
      database: { pool: { waiting: 1 }, queryMilliseconds: 101 },
      delivery: { activeBindings: 1, gatewayFailures24Hours: 1 },
      lifecycle: { oldestPendingDataRequestSeconds: 1001, pendingDataRequests: 1 },
      queue: { failed24Hours: 1, oldestPendingSeconds: 61, pending: 1, staleRunning: 1 },
      reasons: ["migration_drift", "recent_delivery_failures", "recent_failed_jobs", "stale_running_jobs"],
    }), thresholds);
    expect(result.status).toBe("fail");
    expect(result.failures).toEqual([
      "data_request_age_threshold_exceeded",
      "database_query_threshold_exceeded",
      "database_waiting_threshold_exceeded",
      "delivery_failure_threshold_exceeded",
      "failed_job_threshold_exceeded",
      "migration_drift",
      "pending_job_age_threshold_exceeded",
      "stale_running_jobs",
    ]);
    expect(result.warnings).toEqual([]);
  });
});
