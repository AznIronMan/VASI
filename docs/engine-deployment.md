# Private engine deployment

The VASI engine is deployed separately from V·Sign. Use a dedicated PostgreSQL
database and login role, a dedicated deployment directory, and a unique
`data/VASI.settings`. Do not copy the gateway bootstrap.

## Network contract

- `engine` exposes port 8080 only to its internal Docker network and has no host
  port mapping.
- `worker` has no listener or host port.
- `integration-gateway` has no host port and is the only application process
  that decrypts integration credentials or contacts external Microsoft Graph,
  SMTP, webhook, or malware-scanner endpoints.
- `engine` and `worker` join internal networks only. Persistent PostgreSQL
  sessions cross the non-terminating `database-gateway`; only that minimal
  process joins the separately firewalled database-egress network.
- `integration-gateway` alone joins the provider-egress network. The engine,
  worker, and private ingress cannot route through it as a general proxy.
- `private-ingress` exposes only the approved route table and is the only host
  listener. It also joins a dedicated single-stack listener bridge so Docker
  can publish the port; an exact host policy permits established replies and
  denies every new outbound flow from that bridge.
- The tracked Compose binds the facade to loopback. Put a private address in an
  ignored override only after confirming the address and port are reserved.
- Public reverse proxies must not receive the client certificate or key and
  must not target private ingress at all. A historical engine hostname loses
  DNS or terminates in a content-free no-proxy denial server. Independently
  validate that edge state with the
  [public ingress contract](architecture/public-ingress-boundary.md); TLS
  handshake failure is defense in depth, not an approved public route.

Approved routes are:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Authenticated service health proof |
| `POST` | `/v1/whoami` | Validate and return bounded actor context |
| `GET/POST` | `/v1/owner/tenants` | List or create an authorized company space |
| `POST` | `/v1/owner/tenant-profile-read` | Read the active immutable company profile |
| `POST` | `/v1/owner/tenant-profiles` | Append/activate a branding or policy revision |
| `POST` | `/v1/owner/tenant-usage` | Read transactionally calculated quota use |
| `POST` | `/v1/owner/integration-list` | List redacted tenant integration bindings |
| `POST` | `/v1/owner/integrations` | Append/activate an allowlisted binding revision |
| `GET/POST` | `/v1/admin/installation-profile` | Read or revision the operator-controlled installation profile |
| `GET/POST` | `/v1/admin/tenant-admissions` | Read or revision immutable tenant assurance gates |
| `POST` | `/v1/admin/tenant-production-stops` | Atomically stop non-terminal tenant production work |
| `GET` | `/v1/admin/operations` | Read the bounded privacy-safe operational snapshot |
| `POST` | `/v1/owner/member-list` | List engine-authorized company members and grants |
| `POST` | `/v1/owner/members` | Grant or change company roles by verified email |
| `POST` | `/v1/owner/retention-policy-list` | List system and tenant retention-policy revisions |
| `POST` | `/v1/owner/retention-policies` | Append and activate a policy revision optimistically |
| `POST` | `/v1/owner/lifecycle-record-list` | List authorized record lifecycle, deadlines, and holds |
| `POST` | `/v1/owner/legal-holds` | Place or release an append-only legal hold |
| `POST` | `/v1/owner/data-request-review-list` | List participant data scopes for tenant review |
| `POST` | `/v1/owner/data-request-reviews` | Approve/redact or deny one tenant scope |
| `POST` | `/v1/owner/artifact-list` | List tenant-authorized artifact metadata and state |
| `POST` | `/v1/owner/artifacts` | Create a quarantined artifact revision |
| `POST` | `/v1/owner/artifact-chunks` | Append one bounded ordered artifact chunk |
| `POST` | `/v1/owner/artifact-finalizations` | Verify, inspect, hash, and publish/reject an artifact |
| `POST` | `/v1/owner/artifact-aborts` | Finalize an interrupted quarantine as rejected |
| `POST` | `/v1/owner/artifact-open` | Authorize and audit owner document streaming |
| `POST` | `/v1/owner/artifact-read` | Return one authorized owner artifact chunk |
| `POST` | `/v1/owner/workflow-list` | List authorized workflow drafts and publications |
| `POST` | `/v1/owner/workflows` | Create a validated workflow draft |
| `POST` | `/v1/owner/workflow-drafts` | Update a draft with optimistic version control |
| `POST` | `/v1/owner/workflow-publications` | Publish an immutable workflow revision |
| `POST` | `/v1/owner/requests` | Issue an immutable revision now or on a schedule |
| `POST` | `/v1/owner/request-list` | List tenant-authorized request lifecycle state |
| `POST` | `/v1/owner/request-actions` | Remind, revoke, or reissue idempotently |
| `POST` | `/v1/owner/records` | Verify and return an owner-authorized structured record |
| `POST` | `/v1/participant/open` | Bind/open an opaque participant assignment |
| `GET` | `/v1/participant/history` | List participant-bound records with lifecycle state |
| `GET/POST` | `/v1/participant/data-requests` | List or create a participant data request |
| `POST` | `/v1/participant/data-exports` | Open an approved sealed participant data export |
| `POST` | `/v1/participant/data-export-chunks` | Return one authorized verified export chunk |
| `POST` | `/v1/participant/respond` | Record one authoritative response and seal its manifest |
| `POST` | `/v1/participant/receipt` | Return a participant-safe verified receipt |
| `POST` | `/v1/participant/artifact-open` | Authorize/audit exact participant document access |
| `POST` | `/v1/participant/artifact-read` | Return one assignment-authorized artifact chunk |

Everything else returns 404 after service authentication.

VASI 0.28.0 adds engine migration
`0017_engine_tenant_provision_replay` and gateway migration
`0005_invitation_provision_command`. The first creates the immutable,
installation-scoped provisioning command/result index. The second adds the
immutable invitation-command binding and monotonic delivery state. Both
migrations are backward-compatible with the 0.27.0 runtimes: old engine code
does not use the new table, and old gateway inserts inherit the safe historical
`provider_accepted` default with no source command. Apply both migrations
before rollout, then replace the engine before the gateway so a command-bearing
gateway never reaches an engine that rejects the new strict field. Deploying
the release does not create a tenant or approve production admission.

VASI 0.29.0 adds no database migration. It persists only the browser's opaque
provisioning UUID, normalized-input digest, and timestamp in per-tab session
storage so an unchanged retry can survive reload. The gateway continues to use
the 0.28 engine command contract; engine-first rollout remains the supported
version-aligned procedure. No storage value is authoritative, and deployment
does not create a tenant or invitation.

VASI 0.29.1 adds gateway migration
`0006_connector_authentication_health`. It creates the dedicated per-provider
authentication timestamp and provenance, backfills exact attributed session
history when available, and marks the account-update fallback as a legacy
estimate. The migration does not change tokens, credentials, sessions, or the
private-engine schema. Apply it before replacing the gateway; the usual
version-aligned engine-first rollout remains supported, and deployment creates
no identity, tenant, invitation, or evidence record.

VASI 0.30.0 adds no database migration. It reads existing immutable participant
open events, activity responses, lifecycle rows, workflow access policy, and
notification state to produce a privacy-bounded durable history summary. The
usual engine-first rollout is required because the gateway workspace consumes
the expanded response after the engine is replaced. Deployment does not create
or modify a tenant, request, participant, notification, or evidence record.

VASI 0.31.0 adds no database migration. Authentication-assurance policy is
stored inside the existing immutable workflow/request JSONB snapshots, while
accepted evaluations use the existing append-only event payload and sealed
manifest. Deploy the engine before the gateway so enforcement, manifest v10,
participant disclosure, and deliberate reauthentication behavior remain
version-aligned. Existing workflow snapshots normalize to `any_verified` with
no additional freshness limit; deployment does not rewrite them or create an
identity, tenant, request, notification, or evidence record.

VASI 0.32.0 adds no database migration. It reuses the signed actor
`authenticatedAt` value and existing participant-data-request hash-chain event
payloads to enforce and audit the fixed 15-minute privacy-access gate. Deploy
the engine before the gateway so stale request creation/export access is denied
before the participant UI begins handling the bounded reauthentication code.
Deployment does not rewrite a request, export, session, tenant, or evidence
record.

VASI 0.33.0 adds engine migration `0018_engine_participant_data_delivery`. It
binds privacy-status outbox jobs to participant-data requests, extends the
bounded request and notification state sets, and adds immutable preparation and
delivery audit purposes. Run the engine migration before starting the 0.33.0
engine, worker, or integration gateway. The prior 0.32.0 runtime can operate
after this additive migration for rollback, but it does not prepare newly
reviewed exports. New privacy-status jobs remain in the dedicated
`participant_pending` state, which the prior worker deliberately cannot claim,
until the current worker returns.

VASI 0.37.0 adds gateway migration
`0008_public_verification_rate_limit`. It creates only mutable, expiry-indexed
public-verification throttle state keyed by a domain-separated HMAC; it stores
no raw client address and changes no identity or private-engine table. Apply the
gateway migration before replacing the gateway. The prior runtime can operate
after this additive migration for immediate rollback, but it retains only its
process-local throttle. Configure and verify the trusted reverse-proxy boundary
before cutover; no engine migration or engine-first compatibility dependency is
introduced by this release.

VASI 0.38.0 adds gateway migration `0009_gateway_rate_limit`. It creates a
separate mutable, expiry-indexed table for atomic public-gateway client and
installation counters. Only domain-separated HMAC keys are stored. The table
is used first by custom-domain provider recommendation; it changes no identity
or engine row. Apply the gateway migration before replacing the gateway. The
0.37.0 runtime ignores the additive table and remains rollback-compatible, but
does not enforce the new durable DNS-work boundary. No engine migration or
engine-first compatibility dependency is introduced.

## Initialize

Requirements are Docker Engine with Compose, PostgreSQL 15 or newer, an HTTPS
server identity for the private engine hostname, a dedicated V·Sign client
certificate, and an Ed25519 assertion key pair.

```bash
install -d -m 700 data
docker compose -f compose.engine.yaml --profile tools run --rm --build settings init
```

The engine initializer prompts for the dedicated PostgreSQL connection, creates
the bootstrap, applies the engine settings/boundary migrations, generates the
internal HMAC secret and evidence-seal key pair, and stores portable defaults.
Complete these `engine` scope settings before startup:

- `ENGINE_ASSERTION_PUBLIC_JWK`
- `ENGINE_ASSERTION_ISSUER`
- `ENGINE_ASSERTION_AUDIENCE`
- `ENGINE_INGRESS_TLS_CERT`
- `ENGINE_INGRESS_TLS_KEY`
- `ENGINE_AUTHORIZED_CLIENT_CA_CERT`
- `ENGINE_AUTHORIZED_CLIENT_FINGERPRINT_SHA256`
- `ENGINE_OUTBOX_ENCRYPTION_SECRET`
- `ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET`
- `ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET`
- `EVIDENCE_SEAL_PRIVATE_JWK`
- `EVIDENCE_SEAL_PUBLIC_JWK`
- `EVIDENCE_SEAL_KEY_ID`

Evidence reporting accepts optional bounds `ENGINE_EXPORT_MAX_BYTES` (default
64 MiB) and `ENGINE_EXPORT_CHUNK_BYTES` (default 256 KiB). A second
certificate-backed seal is enabled only when all three optional settings are
present:

- `EVIDENCE_CERTIFICATE_KEY_ID`
- `EVIDENCE_CERTIFICATE_PRIVATE_KEY_PEM`
- `EVIDENCE_CERTIFICATE_CHAIN_PEM`

Participant data access accepts `ENGINE_PARTICIPANT_DATA_EXPORT_MAX_BYTES`
(default 64 MiB), `ENGINE_DATA_REQUEST_REVIEW_DAYS` (default 30), and
`ENGINE_DATA_EXPORT_DELIVERY_DAYS` (default 7). Review and delivery bounds are
enforced by the engine and worker; export bytes remain in bounded PostgreSQL
chunks until controlled expiry.

Privacy-bounded participant browser/device context accepts
`ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY` (default `16`, allowed
range `2` through `64`). This is a storage/abuse bound, not permission to add
fields beyond the fixed `vasi-participant-context/v1` schema.

The certificate private key is secret. Its chain is public verification
material. Use signing material distinct from the service TLS identity. Local
certificate verification proves the leaf signature and key match, not public
chain trust, revocation status, qualified-signature status, or trusted time.

Notification delivery starts with a disabled per-tenant binding. An operator
must first allow either the exact Microsoft tenant UUID, application UUID, and
sender mailbox; the exact SMTP host; or the exact webhook host in the
installation profile. An owner can then configure the matching binding in the
company console. Graph and webhook secrets and optional SMTP credentials are
encrypted in PostgreSQL and decrypted only by `integration-gateway`. Graph
uses client-credentials tokens with the fixed Microsoft identity and Graph
origins and requires mailbox-scoped Exchange Application RBAC or an equally
restrictive provider policy. Set `ENGINE_PARTICIPANT_ORIGIN` when Graph or SMTP
issue/reminder messages should contain the VASI request link. Pre-0.11 global
`ENGINE_NOTIFICATION_*` values are consumed only for one-time compatibility
conversion and should be unset after the new binding is verified.

The owner console reports `provider accepted` when Graph, SMTP, or the webhook
adapter accepts a notification. That state does not prove inbox placement,
receipt, reading, attention, or identity. VASI 0.22.0 stores explicit
invitation/reminder/completion purpose outside the encrypted payload, suppresses
obsolete pending invitation/reminder jobs at terminal lifecycle transitions,
and seals only the bounded attempts available when a participant transaction
completes. See the
[notification delivery decision](architecture/notification-delivery-evidence.md).

VASI 0.23.0 requires migration `0014_engine_requester_provenance` before the
new engine starts. It backfills the requester's immutable snapshot from sealed
issuance evidence where possible, then freezes it. New issuance requires an
authenticated actor email. The snapshot identifies the accountable user and is
separate from the configured Graph or SMTP sender mailbox. See the
[requester provenance decision](architecture/requester-provenance-and-participant-disclosure.md).
The migration retains a bounded prior-release insert trigger so a full rollback
can still issue requests; those fallback snapshots are labeled
`membership_backfill` or `legacy_unavailable`, never authenticated issuance.

VASI 0.25.0 requires migration `0015_engine_tenant_admission`. The engine
creates a pending immutable admission revision for every new or existing
tenant. Record all eight approvals in the internal admin console before
production issuance or active integration configuration. Unlike migration
`0014`, migration `0015` deliberately makes an admission-unaware rollback
read/recovery-only: PostgreSQL rejects a new request without the exact current
admitted snapshot and rejects an active integration revision while pending.
See the [tenant production admission decision](architecture/tenant-production-admission.md).

VASI 0.26.0 requires migration `0016_engine_tenant_production_stop`. It extends
the immutable tenant configuration event contract and adds global replay
protection for production-stop command IDs. Apply it before the 0.26.0 engine
starts. A stop is administrator-only and requires an expected admission
revision, selected gate, fixed reason, and opaque incident reference. It
atomically revokes non-terminal tenant work; do not replace it with manual SQL
updates or direct queue deletion.

Document scanning also starts with a disabled per-tenant
`document.malware_scan` binding. An operator must add
`https_malware_scanner` and the exact scanner hostname to the active
installation profile before an owner can activate a binding. The owner enters
an exact HTTPS URL without credentials, query, or fragment, a hard wall-clock
timeout from 5 through 300 seconds, a write-only HMAC secret, and optionally a
private CA certificate bundle. Scanner credentials are
encrypted in PostgreSQL and decrypted only by `integration-gateway`.

The scanner endpoint must accept raw document bytes with the fixed signed
headers and return the bounded `vasi-malware-scan-verdict/v1` JSON contract
documented in the [document artifact decision](architecture/document-artifacts-and-activities.md).
Use a publicly trusted certificate or an explicitly configured private CA;
never disable verification. The scanner must compare the HMAC without timing
leaks, reject stale timestamps using an explicitly monitored clock-skew window,
and deduplicate the scan request ID. VASI follows no redirects. Ensure private
network egress permits only the approved scanner destination and that any
reverse proxy in front of the company console allows the configured
finalization timeout. Transient scanner failures leave bytes quarantined and
owners can retry from the artifact inventory without uploading again.

Document storage defaults to `ENGINE_DOCUMENT_MAX_BYTES=26214400` (25 MiB) and
`ENGINE_DOCUMENT_CHUNK_BYTES=262144` (256 KiB). The engine accepts only the
document media allowlist, and the authenticated chunk action alone receives a
512 KiB JSON envelope allowance; every other private action retains the 64 KiB
body limit. Increasing either setting requires target-deployment database/WAL,
replication, concurrency, backup/restore, and vacuum evidence. See the
[document artifact decision](architecture/document-artifacts-and-activities.md)
for inspection limitations and supported formats.

The gateway scope needs the corresponding `ENGINE_ORIGIN`, server CA, client
certificate/key, assertion private JWK/key ID, issuer, and audience. PEM values
may be entered on one line with newlines encoded as `\n`. For automated
provisioning, stream one JSON object directly to `settings import-json -`; never
write the object to disk or put values in command arguments.

Use separate signing and certificate material for development and production.
The service client certificate is not a participant signature and must never be
described as one.

The evidence-seal key is a separate Ed25519 identity. Keep an offline recovery
copy or use a higher-assurance external signing-key adapter; do not reuse the
gateway assertion key or TLS key. The private JWK is encrypted in the engine
settings scope, while public material is embedded in each seal and registered
with an immutable key/status history. Rotation uses a new key ID and retains
historical verification material.

## Outbound isolation

VASI 0.21.2 requires Linux `iptables` with Docker's `DOCKER-USER` chain for
the packaged host adapter. The sanitized database-egress and private-ingress
listener bridges have stable private IPv4 subnets and IPv6 disabled. All six
engine bridges reserve distinct `/28` allocations inside
`172.29.254.0/24`; this prevents Docker's automatic subnet allocation order
from colliding with the firewall-controlled bridges. Before startup, confirm
that the whole `/24` does not overlap any host, VPN, container, or routed
network. Override all six allocations as one non-overlapping private block in
ignored installation Compose and keep them stable, single-stack, dedicated,
and distinct.

Fresh initialization creates the protected bootstrap before an exact policy
can be rendered. Immediately after `settings init`, and before migration or
persistent startup, create the stopped transport container and apply the
policy:

```bash
docker compose -f compose.engine.yaml build database-gateway engine maintenance settings
docker compose -f compose.engine.yaml up --no-start --no-deps database-gateway private-ingress
sudo /bin/sh scripts/apply-database-egress-policy.sh apply
```

The policy command runs non-root, read-only renderers, writes both temporary
rule sets under `/run` with mode `0600`, validates them, loads the custom
chains, and only then installs one Docker forwarding jump per chain. The
database chain allows only the protected PostgreSQL target; the listener chain
allows established replies and rejects new forwarded traffic. It prints no
subnet, address, hostname, URL, or credential. Do not start the persistent
services if it fails.

For a systemd installation using `/opt/vasi-engine/current`, install the two
egress service/timer pairs before engine startup. VASI 0.24.0 also ships the
engine backup, capacity, deployment, and operational service/timer pairs; the
[recurring scheduler contract](architecture/recurring-operational-schedulers.md)
defines their directories, validation, first-run, and enablement sequence.

```bash
sudo install -m 0644 deployment/systemd/vasi-engine-database-egress-policy.* /etc/systemd/system/
sudo install -m 0644 deployment/systemd/vasi-engine-egress-boundary.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vasi-engine-database-egress-policy.timer
sudo systemctl start vasi-engine-database-egress-policy.service
```

If the release symlink is elsewhere, change `WorkingDirectory` and the matching
`Documentation` path in the installed service units before enabling them; do
not use an environment or credentials file. For a release below `/home`, add a
systemd drop-in to both service units with `ProtectHome=read-only` and
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH`, then run
`systemd-analyze verify` and both one-shots manually before enabling timers.
This permits traversal of protected release parents without a writable home.
Order any local engine-stack unit
after and requiring `vasi-engine-database-egress-policy.service`. Enable the
boundary timer only after the stack is healthy:

```bash
sudo systemctl enable --now vasi-engine-egress-boundary.timer
sudo /usr/bin/env node scripts/probe-engine-egress-boundary.mjs
```

For multiple dedicated instances on one host, pass the same unique lowercase
Compose project and two distinct uppercase firewall chains to both commands,
and add them to the two installed service `ExecStart` lines:

```bash
sudo /bin/sh scripts/apply-database-egress-policy.sh apply \
  --project-name vasi-example \
  --database-chain VASI_EXAMPLE_DATABASE --ingress-chain VASI_EXAMPLE_INGRESS
sudo node scripts/probe-engine-egress-boundary.mjs \
  --project-name vasi-example \
  --database-chain VASI_EXAMPLE_DATABASE --ingress-chain VASI_EXAMPLE_INGRESS
```

The timers schedule an activation-relative first run, then refresh the policy
two minutes after its one-shot exits and rerun the proof five minutes after its
one-shot exits. A PostgreSQL
DNS change can cause a bounded connection pause while the new address is still
denied; it must never cause a broader allow. Alert on either unit's nonzero
result. See the
[outbound-isolation decision](architecture/private-engine-egress.md) for the
policy semantics, privacy contract, assurance limits, and failure behavior.

## Release

This network change requires one controlled engine maintenance window. Take
and verify a matched backup first. Stop the complete old Compose project so
Docker can replace the former external data network with the internal one;
never reuse an old network whose `Internal` value is false.

```bash
docker compose -f compose.engine.yaml down
docker compose -f compose.engine.yaml build database-gateway engine maintenance settings
docker compose -f compose.engine.yaml up --no-start --no-deps database-gateway private-ingress
sudo /bin/sh scripts/apply-database-egress-policy.sh apply
docker compose -f compose.engine.yaml --profile release run --rm migrate
docker compose -f compose.engine.yaml up -d --no-build \
  database-gateway engine integration-gateway worker private-ingress
docker compose -f compose.engine.yaml ps
sudo /usr/bin/env node scripts/probe-engine-egress-boundary.mjs
```

Use the same ignored live override on every command when one exists. Verify
that the database gateway, engine, and integration gateway are healthy and the
worker/private ingress are running before returning traffic. Then rerun the
mTLS/replay, operational, deployment, capacity, backup, load, and accessibility
proofs.

Run the gateway proof after every trust, key, network, or engine release:

```bash
npm run engine:probe
npm run engine:probe:evidence # disposable conformance database only
npm run engine:probe:workflow # disposable conformance database only
npm run engine:probe:documents # documents plus disposable HTTPS scanner proof
npm run engine:probe:scanning # scanner proof alone in the engine-tools image
npm run engine:probe:media # disposable conformance database only
npm run engine:probe:reports # disposable conformance database only
npm run engine:probe:lifecycle # disposable conformance database only
npm run engine:probe:productization # disposable conformance database only
npm run engine:probe:context # disposable conformance database only
```

Before any migration or cutover, run image assurance against every exact
release image. In addition to SBOM/vulnerability evidence, it requires the
declared configured user, derives prohibited package paths from the exact
package/lock graph, rejects npm/npx and physically present development or
optional residue outside the reviewed application-only `sharp` closure, and
runs `node --check` on every declared runtime command as the intended UID/GID
with no network, a read-only root filesystem, all capabilities dropped, and no
privilege escalation. An unrecognized image role, malformed dependency
inventory, prohibited path, or unreadable runtime command stops the release.
This also protects builds from source archives extracted with overly
restrictive permissions.

Run the privacy-safe operational probe on the engine host after migration and
cutover, and from the installation's scheduler/monitor thereafter:

```bash
docker compose -f compose.engine.yaml --profile tools run --rm \
  maintenance scripts/probe-operational-readiness.mjs
```

The command exits nonzero when the release migration ledger drifts, the
integrity key or installation profile is unavailable, worker locks are stale,
or the configured database, queue-age, delivery-failure, scanner-failure,
failed-job, data-request-age, export-preparation-age, or terminal
export-preparation-failure thresholds are exceeded. Its JSON output
contains aggregate counts, ages, versions, status codes, scan retry/threat
counts, and pool pressure only. Forward that output to the
installation-selected monitor; do not add participant fields or secrets to
alert labels.

Run the deployment-perimeter probe separately on both the gateway and engine
hosts. The engine's maintenance container is deliberately limited to exact
database egress, while this probe must also reach the public health/TLS origin.
Before selecting a newly extracted engine release, install its exact production
dependency graph and stable preflight from that release directory:

```bash
sudo -H /bin/sh scripts/prepare-engine-host-runtime.sh
```

This command uses the exact lockfile, omits development and optional packages,
disables npm lifecycle scripts, rejects an unsupported Node engine, and
verifies required installed packages, absence of nonproduction residue, and
the protected settings import. Use `--offline` only after a trusted process has
populated the root npm cache with every required lockfile production artifact;
a missing cached artifact fails the preparation. Retain the prepared prior
release for rollback. The systemd perimeter unit runs the stable verifier
before every scheduled check.

Then run the engine scope from the trusted host with root access to the
protected bootstrap and pass the operator-selected host storage path directly:

```bash
sudo node scripts/probe-deployment-readiness.mjs \
  --scope engine --storage /secure/vasi-engine-storage
```

Do not attach provider/public egress to `maintenance` to make this check work.
The trusted host is already inside the deployment boundary and must protect
the probe output and selected path under the installation's operations policy.
With no explicit origin, the command reads `ENGINE_PARTICIPANT_ORIGIN` from the
protected engine runtime settings; interactive diagnostics may still pass an
explicit credential-free HTTPS origin as the first argument.

The versioned defaults require 30 certificate days, 5 GiB free, and no more
than 85 percent filesystem use. The result exposes only aggregate versions,
latency, expiry windows, filesystem capacity, thresholds, scope, and bounded
reason codes. Schedule it independently from the operational and backup probes
so one stopped job cannot conceal another failure.

Run capacity readiness separately on both Linux hosts. First create an empty,
root-owned, search-only sentinel on each filesystem to measure; do not expose a
filesystem root or data directory only for capacity inspection:

```bash
sudo install -d -o root -g root -m 0111 /var/lib/vasi-capacity

docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /var/lib/vasi-capacity:/host/storage/system:ro \
  capacity --scope engine --storage system=/host/storage/system
```

The service mounts only aggregate `/proc/stat`, `/proc/loadavg`,
`/proc/meminfo`, and `/proc/pressure`; it cannot enumerate host processes. It
also reads the protected bootstrap to query bounded PostgreSQL size, query,
connection, transaction-age, and replication metrics. Fixed reason codes and
the result omit paths, endpoints, processes, credentials, and customer data.
Schedule this independently from operational, deployment-perimeter, and backup
checks. Use `--require-primary-replica true` only where the approved topology
promises a streaming replica.

The proof verifies server trust, the V·Sign client certificate, engine health,
a signed actor identity, the operational-snapshot privacy contract, and
rejection of a replayed assertion. Also verify:

1. unauthenticated TLS fails;
2. the public route remains unavailable;
3. `docker port` is empty for engine, integration gateway, and worker;
4. the running containers contain no application secrets in their environment;
5. the admin engine diagnostic is 404 on the public gateway host and requires
   an allowlisted administrator on the private host; and
6. the bootstrap and PostgreSQL database are covered by matched backup/restore
   tests.

For a containerized matched backup, prepare a protected destination writable
by UID `1000`, then mount it only for that invocation:

```bash
docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /secure/vasi-backups:/backup maintenance \
  scripts/backup.mjs create /backup/vasi-YYYYMMDD
```

For recurring continuity, mount a dedicated existing mode-`0700` root and run
the create and independent freshness checks from the installation scheduler:

```bash
docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /secure/vasi-backups:/backup maintenance \
  scripts/backup-continuity.mjs create /backup

docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /secure/vasi-backups:/backup:ro maintenance \
  scripts/backup-continuity.mjs check /backup
```

The default policy retains 14 verified timestamped copies and fails freshness
after 26 hours. The shipped persistent timers run `create` daily and `check`
independently every 12 hours so a stopped create timer becomes a visible stale
backup failure. The check mount may be read-only. If a process is confirmed
dead after leaving `.vasi-backup.lock`, remove only that lock before retrying;
never bypass verification or delete a failed backup manually until its recovery
value has been assessed. Local same-host copies do not satisfy
encrypted off-host custody or establish an RPO/RTO. Configure only X25519
public recipients in the engine settings scope, then stream the newest matched
copy to an installation-approved mounted destination:

```bash
docker compose -f compose.engine.yaml --profile tools run --rm -T \
  -v /secure/vasi-backups:/matched:ro \
  -v /approved/off-host-mount/vasi-engine:/custody maintenance \
  scripts/backup-custody.mjs create /matched /custody --scope engine

docker compose -f compose.engine.yaml --profile tools run --rm -T \
  -v /approved/off-host-mount/vasi-engine:/custody:ro maintenance \
  scripts/backup-custody.mjs check /custody
```

Keep recipient private keys off this host. VASI does not ship an active custody
timer because a sanitized default cannot prove a destination is off-host. Add
an installation-reviewed scheduler only after the remote mount, independent
check, alert route, key owners, and offline recovery drill are approved. See
the [recipient-encrypted custody runbook](architecture/encrypted-backup-custody.md).

Changing service trust or runtime settings requires restarting the affected
processes. Migration remains an explicit, repeatable release step.

For rollback from 0.26.0, first stop the complete engine stack and every
role-local recurring timer, then switch the whole release—not selected files.
Migrations `0015_engine_tenant_admission` and
`0016_engine_tenant_production_stop` remain forward-only. The admission
triggers intentionally prevent an admission-unaware prior binary from creating
requests or active integration revisions, and the stop-command index preserves
replay history. A prior release may be used only for bounded read/recovery
operations. Normal production issuance with the atomic stop contract requires
0.26.0 or later. Never remove the admission triggers, stop-command index, or
rewrite immutable history to make an older binary write. Reinstall or override
the target
release's scheduler units as a complete reviewed set, manually run them, and
only then re-enable their timers. Keep the exact egress policy in place unless
the target version's documented network procedure explicitly requires removal;
never remove or broaden it while the database gateway or a database tool
remains running.
