# Recurring operational scheduler contract

Status: implemented in VASI 0.24.0 and extended through VASI 0.41.0.

VASI ships the recurring host controls needed to keep a healthy release from
silently degrading after deployment. The portable contract uses hardened
systemd one-shot services and independent persistent timers. It does not choose
an alert transport, external backup custodian, customer thresholds, or a
customer-specific path.

## Packaged controls

| Role | Control | Default recurrence | Failure meaning |
|---|---|---:|---|
| Gateway and engine | Matched backup creation | 24 hours | A new verified PostgreSQL/bootstrap pair was not created |
| Gateway and engine | Backup freshness check | 12 hours | The newest managed pair is missing, stale, malformed, future-dated, or corrupt |
| Gateway and engine | Capacity readiness | 1 hour | A bounded host, filesystem, PostgreSQL, or configured replication threshold failed |
| Gateway and engine | Deployment perimeter | 6 hours | Public health/version, public TLS, service certificates, or selected storage failed |
| Gateway | Identity operational readiness | 5 minutes | Gateway migration drift, administrator audit-chain failure, slow database read, or stale incomplete command |
| Engine | Operational readiness | 5 minutes | Migration, signing, queue, delivery, scanning, lifecycle, or database thresholds failed |
| Engine | Exact egress policy refresh | 2 minutes | The fixed database/private-ingress host policy could not be applied |
| Engine | Egress boundary verification | 5 minutes | Private denial, integration egress, listener replies, health, or database transport failed |
| Public edge | Exact live-image assurance | 24 hours | The live image drifted or its fresh SBOM/vulnerability evidence is missing, mismatched, corrupt, or blocking |
| Public edge | Runtime and evidence readiness | 15 minutes | Container/rollback/listener/Nginx/public/retired-route state drifted or exact scan evidence is stale |

Every timer has boot-relative and activation-relative first runs plus an
`OnUnitInactiveSec` recurrence. `Persistent=yes` makes missed wall-clock work
run after the timer becomes active again. Backup creation and backup checking
are deliberately separate; a stopped creation schedule cannot make its own
freshness claim.

## Configuration boundary

The units contain no environment files, credentials, customer hostnames,
private addresses, or installation task data. They assume these sanitized
filesystem roots:

- gateway release: `/opt/vasi/current` with releases under `/opt/vasi/releases`;
- engine release: `/opt/vasi-engine/current` with releases under
  `/opt/vasi-engine/releases`;
- gateway backups: `/var/lib/vasi/backups/maintenance/scheduled`;
- engine backups: `/var/lib/vasi-engine/backups/maintenance/scheduled`; and
- an empty capacity sentinel at `/var/lib/vasi-capacity`;
- edge release: `/opt/vasi-edge/current` with exact releases under
  `/opt/vasi-edge/releases`; and
- root-owned edge monitor state under `/var/lib/vasi-edge` and scanner cache
  under `/var/cache/vasi-edge`.

Deployment readiness accepts an explicit credential-free HTTPS origin for
interactive use. When the origin is omitted, it reads `BETTER_AUTH_URL` for the
gateway scope or `ENGINE_PARTICIPANT_ORIGIN` for the engine scope through the
existing SQLite-bootstrap/PostgreSQL settings boundary. Origin selection is
therefore versioned and encrypted with the rest of runtime configuration rather
than duplicated in a unit or environment file.

An installation using different roots or an ignored Compose override must use
a root-owned systemd drop-in that replaces `WorkingDirectory` and the complete
`ExecStart` line. Do not edit the tracked unit, add an environment file, embed a
secret, or weaken the service sandbox. The override is deployment state and
must be covered by the installation's configuration review and recovery plan.

VASI 0.41.0 replaces a copied ignored override inside each selected release
with a release-local `compose.live.yaml` symbolic link to one stable,
mode-`0600` protected overlay. The fail-closed activator validates the exact
merged model before establishing that link and changing `current`. This keeps
all Compose-driven one-shots on the same reviewed listener decision after an
upgrade or rollback. See the
[production activation decision](fail-closed-release-activation.md).

## Installation

On each applicable Linux host, prepare only the role-specific roots. The backup
directory must be writable by the maintenance container UID; the capacity
sentinel must be empty and search-only.

```bash
sudo install -d -o 1000 -g 1000 -m 0700 /var/lib/vasi/backups/maintenance/scheduled
sudo install -d -o root -g root -m 0111 /var/lib/vasi-capacity
sudo install -m 0644 deployment/systemd/vasi-gateway-* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/vasi-gateway-*.service \
  /etc/systemd/system/vasi-gateway-*.timer
```

Use `/var/lib/vasi-engine/backups/maintenance/scheduled` on the engine role.
Before installing `vasi-engine-*` units or changing the engine `current`
symlink, prepare each exact extracted release from its own directory:

```bash
cd /opt/vasi-engine/releases/RELEASE_ID
sudo -H /bin/sh scripts/prepare-engine-host-runtime.sh
```

The helper requires root because it atomically replaces the stable verifier at
`/usr/local/libexec/vasi/verify-engine-host-runtime.mjs`. It runs `npm ci`
against the exact lockfile with engine-version enforcement, production-only
installation, development and optional packages omitted, lifecycle scripts
disabled, and audit/update side effects disabled. It then validates the
installed dependency versions, rejects physically present declared or
lock-marked nonproduction packages, and imports the protected settings runtime
before returning a bounded
`vasi-engine-host-runtime/v1` result. A failure must stop cutover.

For an isolated installation, provision a trusted npm cache containing every
required lockfile production tarball and use `--offline`. Offline mode never
contacts a registry and fails rather than silently falling back when an
artifact is missing. Source archives intentionally do not vendor
`node_modules`; retain the prepared immediate-rollback release and its required
production packages. The stable verifier is release-independent for the
current manifest contract and checks whichever release `current` selects.

Review any required drop-ins before the first run. Install the packaged units
only after host preparation, then run `systemctl daemon-reload` and
`systemd-analyze verify`. Start every one-shot service manually and treat any
nonzero result as a deployment failure before enabling its timer. Enable only
after the service has passed:

```bash
sudo systemctl start vasi-gateway-backup-create.service
sudo systemctl start vasi-gateway-backup-check.service
sudo systemctl start vasi-gateway-capacity-readiness.service
sudo systemctl start vasi-gateway-deployment-readiness.service
sudo systemctl start vasi-gateway-operational-readiness.service
sudo systemctl enable --now vasi-gateway-backup-create.timer \
  vasi-gateway-backup-check.timer \
  vasi-gateway-capacity-readiness.timer \
  vasi-gateway-deployment-readiness.timer \
  vasi-gateway-operational-readiness.timer
```

Repeat with the applicable engine services and timers, including operational
readiness and both egress controls. Confirm every timer is both `enabled` and
`active`, has a future trigger, and still points at the current release after a
cutover or rollback.

The public edge adds two more services and timers. Its strict protected
configuration and complete installation/proof sequence are defined in the
[recurring public-edge assurance decision](recurring-public-edge-assurance.md).
Run exact image assurance before runtime readiness, and enable either timer
only after both manual runs pass.

## Hardening and assurance

Docker-driven one-shots are restricted to the local Unix socket address family;
the Docker socket is never mounted into a container. The edge runtime probe
also receives Internet address families for its certificate-verified public
and retired HTTPS checks. The trusted-host engine
deployment probe alone receives Internet address families because it must
inspect public TLS while keeping private containers deny-by-default. Services
use a read-only host view, private temporary and device namespaces, bounded
capabilities, no privilege escalation, native syscall architecture, restrictive
umask, and idle scheduling where applicable. Containers retain their separate
non-root, read-only, capability-dropped Compose contracts. Their release-time
image assurance separately checks the physical filesystem for npm/npx and
every declared-development or lock-marked development/optional dependency,
with only the exact application `sharp` runtime closure explicitly allowed.

The engine deployment-perimeter service runs Node directly on the trusted host
because it must inspect public TLS and protected host storage. It intentionally
does not use systemd `MemoryDenyWriteExecute`; V8 requires executable memory at
isolate startup. An `ExecStartPre` call to the stable bounded verifier refuses
the check when Node is unsupported, package/lock state drifts, a direct
production dependency is missing or mismatched, a declared or lock-marked
nonproduction package is physically present, or the protected settings runtime
cannot load. Its remaining namespace, filesystem, capability, address family,
and no-new-privileges controls stay mandatory, and source assurance rejects
removing the preflight or reintroducing the incompatible flag.

Source assurance enumerates the complete reviewed unit set and fails on a
missing or extra unit, absent persistence/recurrence/hardening lines,
installation-specific origin or home path, environment file, ignored live
override, Docker-socket reference, privileged mode, or host networking. The
release gate complements—rather than replaces—`systemd-analyze verify` and a
manual run on the target distribution.

## Output, alerts, and limits

The probes emit only their existing bounded aggregate JSON. Backup results do
not disclose paths or database identity; readiness results do not disclose
participants, tenants, requests, content, credentials, endpoints, or private
topology. Forward service failure and bounded output to an installation-chosen
monitor without adding sensitive labels.

Same-host backups do not satisfy encrypted off-host custody. VASI 0.35.0
provides recipient-encrypted packaging, structural/freshness checking, and
custodian-side authentication, but deliberately does not add that command to
the sanitized timer set: no portable unit can prove its destination mount is
actually off-host. An installation-reviewed custody scheduler, destination,
private-key owner, and alert route remain required. First-party scheduling does
not select an incident owner, support window, RPO/RTO, customer-specific
threshold, or independent assessor. Those remain explicit pilot-admission
decisions.
