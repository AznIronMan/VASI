import { describe, expect, it } from "vitest";

import { evaluateOperationalReadiness } from "./probe-operational-readiness.mjs";

function snapshot(overrides = {}) {
  return {
    configuration: { installationProfilePresent: true, migrationDrift: false },
    database: { pool: { waiting: 0 }, queryMilliseconds: 12 },
    delivery: { activeBindings: 1, gatewayFailures24Hours: 0 },
    lifecycle: {
      failedDataExportPreparations: 0,
      oldestPendingDataRequestSeconds: 0,
      oldestPreparingDataExportSeconds: 0,
      pendingDataRequests: 0,
      preparingDataExports: 0,
    },
    queue: { failed24Hours: 0, oldestPendingSeconds: 0, pending: 0, staleRunning: 0 },
    scanning: { failed24Hours: 0, retryable: 0, threats24Hours: 0 },
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
  maximumRetryableScans: 0,
  maximumScanFailures24Hours: 0,
  maximumScanThreats24Hours: 0,
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

  it("fails scanner failure, retry, and threat thresholds without retaining customer detail", () => {
    expect(evaluateOperationalReadiness(snapshot({
      reasons: ["documents_awaiting_scan_retry", "recent_document_threats", "recent_scan_failures"],
      scanning: { failed24Hours: 1, retryable: 1, threats24Hours: 1 },
    }), thresholds)).toEqual({
      failures: [
        "scan_failure_threshold_exceeded",
        "scan_retry_threshold_exceeded",
        "scan_threat_threshold_exceeded",
      ],
      status: "fail",
      warnings: [],
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

  it("fails terminal or stale participant-data export preparation", () => {
    const failed = evaluateOperationalReadiness(snapshot({
      lifecycle: {
        failedDataExportPreparations: 1,
        oldestPendingDataRequestSeconds: 0,
        oldestPreparingDataExportSeconds: 1001,
        pendingDataRequests: 0,
        preparingDataExports: 1,
      },
      reasons: ["participant_data_export_preparation_failed"],
    }), thresholds);
    expect(failed.failures).toEqual([
      "data_export_preparation_age_threshold_exceeded",
      "data_export_preparation_failed",
    ]);
    expect(failed.warnings).toEqual([]);
  });
});
