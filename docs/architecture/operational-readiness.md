# Privacy-safe operational readiness

## Decision

VASI exposes operational state as a bounded aggregate contract owned by the
private engine. The contract is useful for an operator and monitoring system,
but it is not an evidence-record search surface and never returns customer or
participant rows.

The snapshot is available only through the existing mTLS, HMAC service-request,
short-lived actor-assertion, and replay defenses at `GET
/v1/admin/operations`. The private-ingress service identity is explicitly
authorized for the action, and the engine separately requires the actor's
`admin` role. The public hostname continues to return 404 for every admin API.

## Aggregate contract

`vasi-operational-snapshot/v1` reports:

- release version and exact migration-ledger count/checksum agreement;
- PostgreSQL query latency and pool total, idle, waiting, and maximum counts;
- pending/running/stale/failed outbox counts and oldest pending age;
- 24-hour provider-accepted, failed, suppressed, and gateway-failure counts
  plus at most ten syntax-bounded error codes (the stable JSON field remains
  `delivered24Hours` for contract compatibility);
- active/disabled delivery-binding and verified-adapter counts;
- active scanner-binding, 24-hour failed/threat-verdict, and currently
  retryable-quarantine counts;
- purge-due, recent purge-block, pending data-request, and oldest review age;
- active standard/optional signing-key and untrusted historical-key counts;
- installation-profile presence/revision and aggregate configuration/settings
  change recency; and
- active, admitted, pending-admission, and disabled company-tenant counts.

The engine derives `ready`, `attention`, or `critical` from structural
conditions. Migration drift, a missing installation profile, an unavailable
standard integrity key, or a stale worker lock is critical. Recent delivery or
scanner failures, scanner threat verdicts, retryable quarantines, purge blocks,
pool waiting, or an installation with no active tenant/delivery binding receives
attention without inventing a customer impact claim.
An active tenant without a complete current production admission also receives
attention; the aggregate does not reveal which tenant or any gate evidence.

## Privacy boundary

The contract excludes tenant IDs/names, user or participant identity, email
addresses, request/assignment IDs, participant paths, correlation values,
documents, answers, signatures, media metadata, provider responses, outbox
payloads, credentials, keys, and hashes. Error codes accept only a fixed
lowercase syntax and otherwise become `delivery_failed`. Counts and ages are
nonnegative bounded numbers; malformed dates fail the request rather than being
guessed.

These exclusions apply equally to the internal console, CLI output, logs, alert
labels, and retained monitoring data. Operators must investigate customer-level
events through the separately authorized audit/evidence surfaces.

## Host probe and thresholds

The non-root engine-maintenance image packages
`scripts/probe-operational-readiness.mjs`. It reads the protected engine
bootstrap, calls the same store locally, prints only the bounded snapshot and
assessment, then closes its PostgreSQL pool. It can run before the first browser
administrator signs in.

The default versioned policy fails on:

- any release migration drift or missing integrity/profile prerequisite;
- database snapshot latency over 2,000 ms or any waiting pool client;
- any failed outbox job or integration-gateway failure in the prior 24 hours;
- any failed scanner call, scanner threat verdict, or retryable quarantined
  artifact under the default zero-tolerance thresholds;
- a pending job older than 900 seconds or a stale worker lock; or
- a pending participant data request older than 30 days.

Every numeric threshold has a bounded command-line override for an approved
installation policy. Setup warnings such as no first tenant or no active
delivery binding remain visible but do not make a pre-onboarding host probe
fail.

## Alerting and limits

VASI emits vendor-neutral JSON and a deterministic exit status. VASI 0.24.0
ships an independent hardened systemd service/timer pair that executes the
engine probe every five minutes by default. The deployment still chooses its
alert transport, on-call destination, result retention, and escalation policy.
This keeps the deployable product independent from a proprietary monitoring
service and prevents application credentials from being copied into an
alerting SDK.

VASI 0.15.0 adds a separate scheduler-neutral matched-backup freshness and
verification probe. VASI 0.16.0 adds a separate deployment-perimeter probe for
public HTTPS/version, public and service-certificate windows, and one
operator-selected filesystem. VASI 0.20.0 adds a separate capacity probe for
aggregate Linux CPU/load/memory/pressure, fixed-code filesystem byte/inode
state, and PostgreSQL saturation/replication posture. The operational snapshot
does not duplicate those probes, because the engine must not receive host
paths, storage credentials, or public-topology configuration. These contracts
still do not replace encrypted off-host backup custody, sustained customer
capacity tests, network/replica-lag monitoring, external alert delivery, or an
incident-response owner. Those remain deployment responsibilities and pilot
admission evidence.
