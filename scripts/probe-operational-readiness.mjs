import process from "node:process";
import { pathToFileURL } from "node:url";

import policy from "../config/assurance-policy.json" with { type: "json" };
import packageJSON from "../package.json" with { type: "json" };
import { createOperationsStore } from "../services/engine/operations-store.mjs";
import { createSettingsPool, loadBootstrapSettings } from "./settings-core.mjs";

export function evaluateOperationalReadiness(snapshot, thresholds = policy.operations) {
  const failures = new Set();
  const warnings = new Set(snapshot.reasons || []);
  for (const reason of snapshot.reasons || []) {
    if ([
      "installation_profile_missing",
      "integrity_key_unavailable",
      "migration_drift",
      "stale_running_jobs",
    ].includes(reason)) {
      failures.add(reason);
      warnings.delete(reason);
    }
  }
  if (snapshot.database.queryMilliseconds > thresholds.maximumDatabaseQueryMilliseconds) {
    failures.add("database_query_threshold_exceeded");
  }
  if (snapshot.database.pool.waiting > thresholds.maximumDatabaseWaitingClients) {
    failures.add("database_waiting_threshold_exceeded");
    warnings.delete("database_pool_waiting");
  }
  if (snapshot.queue.failed24Hours > thresholds.maximumFailedJobs24Hours) {
    failures.add("failed_job_threshold_exceeded");
    warnings.delete("recent_failed_jobs");
  }
  if (snapshot.queue.staleRunning > thresholds.maximumStaleRunningJobs) {
    if (!failures.has("stale_running_jobs")) failures.add("stale_job_threshold_exceeded");
  }
  if (
    snapshot.queue.pending > 0 &&
    snapshot.queue.oldestPendingSeconds > thresholds.maximumOldestPendingSeconds
  ) {
    failures.add("pending_job_age_threshold_exceeded");
  }
  if (snapshot.delivery.gatewayFailures24Hours > thresholds.maximumGatewayFailures24Hours) {
    failures.add("delivery_failure_threshold_exceeded");
    warnings.delete("recent_delivery_failures");
  }
  if ((snapshot.scanning?.failed24Hours || 0) > thresholds.maximumScanFailures24Hours) {
    failures.add("scan_failure_threshold_exceeded");
    warnings.delete("recent_scan_failures");
  }
  if ((snapshot.scanning?.retryable || 0) > thresholds.maximumRetryableScans) {
    failures.add("scan_retry_threshold_exceeded");
    warnings.delete("documents_awaiting_scan_retry");
  }
  if ((snapshot.scanning?.threats24Hours || 0) > thresholds.maximumScanThreats24Hours) {
    failures.add("scan_threat_threshold_exceeded");
    warnings.delete("recent_document_threats");
  }
  if (
    snapshot.lifecycle.pendingDataRequests > 0 &&
    snapshot.lifecycle.oldestPendingDataRequestSeconds > thresholds.maximumOldestPendingDataRequestSeconds
  ) {
    failures.add("data_request_age_threshold_exceeded");
  }
  return Object.freeze({
    failures: Object.freeze([...failures].sort()),
    status: failures.size ? "fail" : "pass",
    warnings: Object.freeze([...warnings].sort()),
  });
}

export async function runOperationalReadinessProbe({
  bootstrap = loadBootstrapSettings(),
  thresholds = policy.operations,
} = {}) {
  const database = createSettingsPool(bootstrap);
  try {
    const snapshot = await createOperationsStore(database, { engineVersion: packageJSON.version })
      .snapshot({ roles: ["admin"] });
    return Object.freeze({
      assessment: evaluateOperationalReadiness(snapshot, thresholds),
      snapshot,
    });
  } finally {
    await database.end();
  }
}

function parseArguments(argumentsList) {
  const mapping = {
    "--maximum-database-ms": "maximumDatabaseQueryMilliseconds",
    "--maximum-database-waiting": "maximumDatabaseWaitingClients",
    "--maximum-failed-jobs": "maximumFailedJobs24Hours",
    "--maximum-gateway-failures": "maximumGatewayFailures24Hours",
    "--maximum-oldest-data-request-seconds": "maximumOldestPendingDataRequestSeconds",
    "--maximum-oldest-pending-seconds": "maximumOldestPendingSeconds",
    "--maximum-retryable-scans": "maximumRetryableScans",
    "--maximum-scan-failures": "maximumScanFailures24Hours",
    "--maximum-scan-threats": "maximumScanThreats24Hours",
    "--maximum-stale-running": "maximumStaleRunningJobs",
  };
  const thresholds = { ...policy.operations };
  for (let index = 0; index < argumentsList.length; index += 2) {
    const key = mapping[argumentsList[index]];
    const value = Number(argumentsList[index + 1]);
    if (!key || !Number.isSafeInteger(value) || value < 0) {
      throw new Error(`Invalid operational-readiness option ${argumentsList[index] || "(missing)"}.`);
    }
    thresholds[key] = value;
  }
  return thresholds;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runOperationalReadinessProbe({ thresholds: parseArguments(process.argv.slice(2)) })
    .then((result) => {
      console.info(JSON.stringify(result, null, 2));
      if (result.assessment.status !== "pass") process.exitCode = 1;
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : "VASI operational readiness probe failed.");
      process.exitCode = 1;
    });
}
