"use client";

import { useEffect, useState } from "react";

import type { OperationalSnapshot } from "@/lib/operational-readiness";

export function OperationalReadinessPanel() {
  const [snapshot, setSnapshot] = useState<OperationalSnapshot>();
  const [message, setMessage] = useState<string>();
  const [pending, setPending] = useState(true);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let active = true;
    fetch("/api/admin/operations", { cache: "no-store" })
      .then(async (response) => {
        const body = await response.json() as OperationalSnapshot & { error?: string };
        if (!response.ok) throw new Error(body.error || "Operational snapshot unavailable.");
        if (body.schema !== "vasi-operational-snapshot/v1") throw new Error("Operational snapshot is incompatible.");
        if (active) setSnapshot(body);
      })
      .catch((error) => {
        if (active) setMessage(error instanceof Error ? error.message : "Operational snapshot unavailable.");
      })
      .finally(() => { if (active) setPending(false); });
    return () => { active = false; };
  }, [refresh]);

  function refreshSnapshot() {
    setPending(true);
    setMessage(undefined);
    setRefresh((value) => value + 1);
  }

  return <section className="operations-panel" aria-labelledby="operations-title">
    <div className="operations-heading">
      <div>
        <p className="eyebrow eyebrow--green">OPERATIONAL READINESS</p>
        <h2 id="operations-title">Private engine and governed work</h2>
        <p>Aggregate health only. Participant identity, content, responses, links, and credentials are excluded.</p>
      </div>
      <div className="operations-heading__actions">
        {snapshot && <span className={`operations-status operations-status--${snapshot.status}`}>{statusLabel(snapshot.status)}</span>}
        <button className="secondary-button" disabled={pending} onClick={refreshSnapshot} type="button">
          {pending ? "Checking…" : "Refresh"}
        </button>
      </div>
    </div>
    {message && <p className="admin-message admin-message--error" role="alert">{message}</p>}
    {snapshot && <>
      <div className="admin-overview operations-overview">
        <OperationsMetric label="Engine release" value={snapshot.engineVersion} detail={`${snapshot.configuration.migrationsApplied}/${snapshot.configuration.migrationsExpected} migrations`} />
        <OperationsMetric label="Pending work" value={snapshot.queue.pending} detail={`oldest ${duration(snapshot.queue.oldestPendingSeconds)} · ${snapshot.queue.staleRunning} stale`} />
        <OperationsMetric label="Provider accepted (24h)" value={snapshot.delivery.delivered24Hours} detail={`${snapshot.delivery.gatewayFailures24Hours} failed · ${snapshot.delivery.suppressed24Hours} suppressed`} />
        <OperationsMetric label="Document scanning" value={snapshot.scanning.retryable} detail={`${snapshot.scanning.failed24Hours} failed · ${snapshot.scanning.threats24Hours} threats (24h)`} />
        <OperationsMetric label="Integrity keys" value={snapshot.signing.activeIntegrityKeys} detail={`${snapshot.signing.activeOptionalKeys} optional active`} />
        <OperationsMetric label="Lifecycle" value={snapshot.lifecycle.purgeDueRecords} detail={`${snapshot.lifecycle.purgeBlocked24Hours} purge blocks · ${snapshot.lifecycle.pendingDataRequests} reviews · ${snapshot.lifecycle.preparingDataExports} exports preparing · ${snapshot.lifecycle.failedDataExportPreparations} preparation failures`} />
        <OperationsMetric label="Company tenants" value={snapshot.tenancy.active} detail={`${snapshot.tenancy.admitted} admitted · ${snapshot.tenancy.pendingAdmission} pending`} />
      </div>
      <div className="operations-footnote">
        <span>Database check {snapshot.database.queryMilliseconds.toFixed(2)} ms · pool {snapshot.database.pool.total}/{snapshot.database.pool.maximum} · {snapshot.database.pool.waiting} waiting</span>
        <span>Profile revision {snapshot.configuration.installationProfileRevision} · migration drift {snapshot.configuration.migrationDrift ? "detected" : "none"}</span>
        <span>Observed {new Date(snapshot.generatedAt).toLocaleString()}</span>
      </div>
      {snapshot.reasons.length > 0 && <p className="operations-reasons"><strong>Attention:</strong> {snapshot.reasons.map(reasonLabel).join("; ")}.</p>}
    </>}
    {!snapshot && pending && <p>Checking the private operational boundary…</p>}
  </section>;
}

function OperationsMetric({ detail, label, value }: { detail: string; label: string; value: number | string }) {
  return <article><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function duration(seconds: number) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3_600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3_600)}h`;
}

function statusLabel(status: OperationalSnapshot["status"]) {
  if (status === "ready") return "Ready";
  if (status === "critical") return "Critical";
  return "Attention";
}

function reasonLabel(reason: string) {
  const labels: Record<string, string> = {
    database_pool_waiting: "database clients are waiting",
    documents_awaiting_scan_retry: "quarantined documents are awaiting a scan retry",
    installation_profile_missing: "installation profile is missing",
    integrity_key_unavailable: "the integrity seal key is unavailable",
    migration_drift: "the database migration ledger differs from this release",
    no_active_delivery_binding: "no company delivery adapter is active",
    no_active_tenants: "no company tenant has been provisioned",
    recent_delivery_failures: "delivery failures occurred in the last 24 hours",
    recent_document_threats: "a scanner reported malicious or suspicious document content",
    recent_failed_jobs: "outbox jobs failed in the last 24 hours",
    recent_purge_blocks: "retention purge attempts were blocked",
    recent_scan_failures: "document scanner calls failed in the last 24 hours",
    stale_running_jobs: "a worker job exceeded its lock window",
    tenants_pending_admission: "one or more company tenants are not admitted for production work",
  };
  return labels[reason] || "an unrecognized operational condition was reported";
}
