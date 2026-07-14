# VASI

Verified Authorized Signing Infrastructure

Version: `0.17.0`

A product-neutral service that can be branded and deployed for a single organization or as a multi-tenant service.

## Current milestone

VASI currently provides the V·Sign identity gateway: public authentication and
SSO-first onboarding, private identity administration, invitations, account
lifecycle controls, and transactional email. Microsoft, Google, Yahoo, and
username/password sign-in are available; Zoho is implemented and awaits a
production client; Apple is implemented but hidden until Apple Developer
approval is complete.

This release includes the independently deployed private engine boundary behind
that gateway: separate engine, private-ingress, worker, and integration-gateway
processes; an engine-owned PostgreSQL database/schema and migration history;
mutual TLS from V·Sign; HMAC-authenticated service requests; and short-lived,
replay-protected EdDSA actor assertions. The engine, worker, and integration
gateway publish no host ports.

Version 0.5.0 adds the first deliberately narrow evidence transaction. An
authorized company owner can issue immutable text/terms with acknowledgement or
yes/no response and receive a one-time opaque participant link. V·Sign returns
an authenticated, email-verified participant to that request. The engine binds
the account, exact content, available authentication/browser/network context,
server timing, and response into an append-only per-assignment event chain,
then signs a deterministic manifest with the standard VASI integrity seal.
Participants receive a readable receipt; authorized owners can retrieve the
verified structured record.

Version 0.6.0 adds the VASI-owned workflow and company control plane. Company
roles are separate from identity administration; owners and managers can create
optimistically versioned drafts, publish immutable revisions, issue scheduled
multi-step requests, use restricted forward-only response branches, and manage
reminder, revocation, reissue, due, expiration, and post-completion access
policies. The worker advances lifecycle state and a retry-safe encrypted outbox;
version 0.11 routes delivery through the isolated integration gateway. New
V·Sign sessions also preserve
session-specific authentication provenance rather than guessing from linked
accounts.

Version 0.7.0 adds the VASI-owned PostgreSQL document store and rich electronic
activity contracts. Non-media uploads are quarantined, bounded into ordered
`bytea` chunks, individually and completely hashed, transparently inspected,
and atomically published or rejected without an authoritative loose file.
Workflow revisions bind exact artifact revisions and now support approvals,
single/multiple choice, free-form responses, typed/drawn electronic signatures,
document review, and deterministic questionnaires/tests. Saved responses are
append-only revisions included in the version 3 sealed evidence manifest.

Version 0.8.0 adds immutable provider-hosted media descriptors and bounded
duration evidence without moving authoritative media bytes into VASI. YouTube
and Vimeo use instrumented player adapters; SharePoint/OneDrive, Google Drive,
Dropbox, installation-allowlisted embeds, and external links degrade to the
presentation or departure evidence each provider can actually expose. The
engine records strict idempotent event batches, rejects seeks/gaps and hidden or
implausible playback from credited duration, unions unique intervals across
sessions, preserves every calculation revision, and seals raw media evidence
in the version 4 manifest. Browser telemetry remains explicitly supporting
evidence rather than proof of attention or comprehension.

Version 0.9.0 adds deterministic participant, plain-language, technical
forensic, and structured evidence reports in JSON, text, and printable HTML.
Authorized owners can download sealed portable ZIP bundles containing the
record, event chain, all report forms, and exact PostgreSQL document revisions;
participants can download a privacy-reduced report. The bundled offline
verifier recomputes every entry, report, event hash, manifest binding, and seal
without a private key, LLM, network, or VASI account. An exact-fingerprint
public verifier exposes no record identity or content. Export bytes, signing-key
history, and access events remain immutable in PostgreSQL. Installations can
add a separate X.509 certificate seal while the Ed25519 VASI integrity seal
remains the required portable baseline.

Version 0.10.0 adds independent original-content, participant-history,
archive, and deletion horizons through immutable named retention-policy
revisions bound at issuance. The worker enforces access expiration, logical
archive, legal-hold and participant-data-request blockers, controlled physical
purge, and signed integrity tombstones that preserve privacy-minimized public
verification after source evidence is removed. The company console manages
policies, record lifecycle, holds, and privacy reviews. The participant
workspace now shows request history and supports a reviewed, redacted, sealed,
time-limited JSON export of the participant's own VASI data.

Version 0.11.0 productizes the installation and tenant boundaries. Installation
and company profiles are immutable, validated revisions with product-neutral
branding, capacity limits, outbound adapter allowlists, and hash-chained audit
events. Every request binds the governing tenant profile snapshot into its
evidence. A separate internal integration gateway is now the only component
that decrypts stored tenant delivery credentials or contacts outbound provider endpoints;
workers submit a narrow signed contract and immutable attempts record the exact
adapter revision and outcome. Sanitized self-hosted/SaaS profiles, matched
backup verification, and encrypted tenant export/import support portable
deployments without environment files or customer-specific source forks.

Version 0.12.1 supplies configured branding during server rendering and repairs
the release workflow version-output step. Version 0.12.0 added a first-party
assurance and pilot-readiness gate. Release
tooling now rejects tracked private/runtime material, known secret signatures,
version drift, weakened Compose boundaries, blocking dependency or image
vulnerabilities, and dirty release source; it emits hashed source/image
inventories, npm audit evidence, and CycloneDX SBOMs outside the repository. A
digest-pinned scanner examines exact image tar exports without receiving the
Docker socket. Browser-rendered WCAG automation and a bounded read-only load
probe cover the public readiness surface. Runtime images no longer contain the
unused npm toolchain, reducing their attack surface. The threat model and pilot
contract explicitly separate first-party evidence from independent security,
legal/privacy, accessibility, custody, and customer approvals.

Version 0.13.0 adds governed Microsoft Graph mail to tenant workflow delivery.
The private engine remains provider-independent: its worker still submits the
same narrow signed notification contract, while the isolated integration
gateway alone acquires a cached app-only token and contacts fixed Microsoft
endpoints. Installation administrators must allow the exact Entra tenant,
application ID, and sender mailbox before a tenant owner can activate a
revisioned binding. Client secrets are write-only, encrypted in PostgreSQL,
redacted from every read path, and provider failure bodies never enter VASI
responses or delivery records.

Version 0.14.0 adds privacy-safe operational readiness monitoring. The private
engine now exposes an administrator-only aggregate snapshot covering migration
drift, queue depth and age, delivery outcomes, lifecycle pressure, signing-key
readiness, configuration changes, tenant/binding counts, and PostgreSQL pool
pressure. The snapshot deliberately contains no tenant IDs, participant or
request identity, email addresses, content, responses, links, payloads, or
credentials. The internal console renders the same bounded view, while a
host-side probe applies versioned failure thresholds before a browser
administrator exists and can feed installation-selected alerting systems.

Version 0.15.0 adds recurring matched-backup continuity. A scheduler-neutral
maintenance command takes an exclusive backup-root lock, creates the
PostgreSQL dump and exact `VASI.settings` atomically, verifies checksums and the
custom archive, and only then prunes recognized older backups beyond the
versioned retention count. A separate read-only check verifies the newest
managed backup and fails on missing, stale, malformed, future-dated, or corrupt
state. Both commands emit bounded operational JSON without paths, installation
identities, database endpoints, credentials, or customer data. Gateway and
engine Compose contracts now include the same non-root, read-only maintenance
boundary; encrypted off-host custody and customer RPO/RTO remain deployment
decisions.

Version 0.16.0 adds privacy-safe deployment-perimeter readiness monitoring. A
vendor-neutral probe verifies the public HTTPS health/version boundary and
publicly trusted certificate window, measures an operator-selected filesystem,
and reads the expected gateway or engine service-certificate set through the
existing protected settings boundary. Versioned defaults require at least 30
certificate days, 5 GiB free, and no more than 85 percent filesystem use. The
bounded JSON and exit status omit origins, paths, certificate identities,
settings, topology, credentials, and customer data so installations can attach
their own scheduler and alert transport without changing VASI.

Version 0.17.0 adds privacy-bounded generalized activity-interaction evidence
to every workflow step. The participant browser emits only fixed presentation,
visibility, focus, heartbeat, coarse-interaction, and disconnect events—never
keys, input contents, pointer coordinates, plugins, or invasive fingerprinting
signals. The private engine enforces participant/activity/session binding,
strict event shapes, idempotent batch hashes, ordering, and installation
bounds; PostgreSQL retains immutable raw batches, events, and deterministic
summary revisions. Open, foreground-visible, engaged, idle, background, and
uncredited-gap durations are sealed in manifest version 5, shown with honest
confidence limits in human reports, included in approved participant data
exports, independently recalculated by the offline verifier, and removed only
through the existing controlled retention purge.

The standard seal proves that the manifest and covered chain have not changed
and were signed by the configured VASI seal key. An optional certificate seal
can establish an additional configured certificate identity, but local
verification alone does not establish chain trust, revocation status, trusted
time, legal enforceability, or long-term validation. Comprehensive replaceable
malware scanning, external KMS/HSM/TSA trust profiles, deployment-specific
legal/privacy approval, and independent security assessment remain subsequent
milestones.

## Included

- Next.js 16 and Better Auth with PostgreSQL-backed users, accounts, sessions,
  verification records, and rate limits.
- Microsoft, Google, Yahoo, Zoho, Apple-ready, and manual authentication with an
  SSO-first participant experience.
- Internal-host-only identity administration, operator allowlisting,
  invitations, connector health/disconnection, password controls, account
  disablement, session revocation, and audit records.
- Microsoft Graph transactional delivery restricted to its configured mailbox,
  with SMTP as an optional fallback.
- A local SQLite bootstrap at `data/VASI.settings` containing only the
  PostgreSQL connection, installation identity, pool/transport selection, and
  the key that decrypts runtime settings.
- AES-256-GCM encrypted runtime configuration in PostgreSQL, audited settings
  changes, explicit gateway/engine scopes, forward-only migrations, and a
  value-redacting settings CLI.
- A non-root application image, loopback-only published port, health check,
  read-only application filesystem, and explicit release migration.
- Framework-independent engine contracts, service authorization, request
  signing, actor-assertion validation, and gateway-client packages.
- Private engine, worker, and integration-gateway containers with no published
  ports, plus an mTLS facade, PostgreSQL outbox, and persistent assertion replay
  defense.
- An admin-host-only engine identity diagnostic at `/api/admin/engine`; it
  translates the authenticated V·Sign administrator session into a one-minute
  internal actor assertion without forwarding provider tokens or cookies.
- An internal first-slice issuance console at `/admin/evidence`, public opaque
  request paths under `/r/`, authenticated participant response/receipt pages,
  tenant membership enforcement, immutable workflow snapshots, append-only
  evidence chains, deterministic manifests, and Ed25519 VASI integrity seals.
- A private-origin company console at `/owner` with engine-owned roles,
  structured workflow drafts, immutable publication, ordered/conditional
  activity execution, request lifecycle controls, and revision-bound access and
  notification policies.
- AES-256-GCM encrypted outbox envelopes, immutable delivery-attempt records,
  bounded retry and stale-lock recovery, tenant-scoped mailbox-restricted
  Microsoft Graph, generic SMTP, and HMAC-signed HTTPS webhook adapters behind
  exact installation allowlists, and session-level authentication provenance.
- Revisioned installation/tenant profiles, transactional capacity enforcement,
  evidence-bound branding/policy snapshots, encrypted integration credentials,
  hash-chained configuration events, and owner/operator control panels.
- Sanitized self-hosted/SaaS profiles, matched PostgreSQL/bootstrap backup and
  restore verification, plus passphrase-authenticated streaming tenant archives
  that re-encrypt credentials and establish a destination owner grant.
- PostgreSQL-only authoritative non-media artifacts with bounded chunk upload
  and delivery, immutable source/derived/replacement revisions, SHA-256
  verification, quarantine/inspection, exact workflow binding, and access
  auditing.
- Declarative approvals, questions, free-form answers, typed/drawn electronic
  signatures, document review, and server-scored questionnaires/tests with
  append-only response revisions and participant answer-key redaction.
- Provider-independent external media activities with immutable descriptors,
  YouTube/Vimeo playback telemetry, honest generic-frame/external-link
  downgrades, strict replay-safe event batches, unique-duration calculations,
  accessibility acknowledgement, and version 4 sealed evidence.
- Privacy-bounded presentation, visibility, focus, heartbeat, coarse
  interaction, idle, gap, and disconnect evidence for every activity, with
  replay-safe batch envelopes, immutable deterministic revisions, version 5
  sealing, human-readable timing summaries, offline recalculation, participant
  data access, and controlled purge.
- Deterministic human and machine evidence reports, immutable PostgreSQL export
  chunks, portable sealed ZIP bundles with authoritative document revisions,
  an offline verifier, a privacy-minimized public fingerprint verifier, key
  rotation history, optional X.509 seals, and append-only export/access audits.
- Versioned retention profiles with immutable per-record snapshots, independent
  content/history/archive/delete horizons, append-only legal holds and releases,
  hold-safe worker enforcement, controlled PostgreSQL purge, and signed
  verification tombstones.
- A participant record-history workspace and organization-scoped data-request
  review that produces a privacy-redacted, sealed, bounded PostgreSQL JSON
  export with audited access and automatic content expiry.
- A release assurance gate with tracked-source policy, complete and production
  dependency audits, CycloneDX source/image SBOMs, digest-pinned image scanning,
  runtime version alignment, sanitized Compose hardening checks, browser WCAG
  automation, and bounded read-only readiness load testing.
- An administrator-only operational snapshot and host probe with explicit
  migration, queue, delivery, signing, lifecycle, and database thresholds that
  exclude customer evidence and identity data.
- Concurrency-safe recurring matched backups with post-create verification,
  bounded retention, freshness assessment, and hardened gateway/engine
  maintenance containers.
- A privacy-safe deployment-perimeter probe for public health/version, public
  and service-certificate expiry, and filesystem pressure, with bounded
  policy thresholds and vendor-neutral scheduler/alerting handoff.

## Configuration model

VASI does not use environment files. A populated `data/VASI.settings` is local
installation state and must never be committed, copied into an image, or sent
with a support bundle. It contains the minimum information needed to reach
PostgreSQL and decrypt the remaining settings. Provider credentials, auth and
mailer secrets, origins, allowlists, and other runtime configuration are
encrypted in PostgreSQL and scoped to the installation ID and process family.

The bootstrap database and PostgreSQL must be backed up together. Losing
`VASI.settings` loses the decryption key for the PostgreSQL settings; restoring
the file against the wrong database or installation will not decrypt them.
Keep the file at mode `0600` and its directory private.

Settings are loaded once per application process. Restart the app after a
settings change. The settings listing command reports names and versions but
never values.

Disaster recovery to a different PostgreSQL endpoint uses the confirmed
`settings rebind-database - --confirm-recovery-endpoint` command on a copy of
the matched backup bootstrap after the database restore. It validates required
encrypted settings against the recovered database before atomically changing
only connection fields; run `settings validate` before starting services. See
the productized deployment decision for the exact recovery order and custody
requirements.

## Local setup

Requirements: Node.js 24 or newer and PostgreSQL 15 or newer. Docker is
optional and can provide PostgreSQL with the development Compose file.

```bash
npm install
docker compose up -d postgres
npm run settings:init
npm run dev
```

The initializer prompts privately for the PostgreSQL credential, creates
`data/VASI.settings`, applies the database migrations, generates a strong auth
secret, and stores the required gateway settings in PostgreSQL. Open
`http://localhost:3000` after initialization.

Without provider credentials, provider actions identify that configuration is
required. Apple remains hidden until its login flag is enabled. Manual sign-in
is under `Other methods`. Development verification and reset URLs are written
to the server console when no mail transport is configured; production fails
closed when the selected transport is incomplete.

Useful commands:

```bash
npm run settings:list
npm run settings -- set GOOGLE_CLIENT_ID
npm run settings -- set GOOGLE_CLIENT_SECRET
npm run settings -- unset GOOGLE_CLIENT_ID
npm run db:migrate
npm run check
npm run build
npm run evidence:verify -- /path/to/vasi-evidence-bundle.zip
npm run deployment:profile -- self-hosted
npm run backup -- create /secure/backups/vasi-YYYYMMDD
npm run backup:continuity -- create /secure/backups
npm run backup:continuity -- check /secure/backups
npm run assurance:deployment -- https://vasi.example --scope gateway --storage /secure
npm run tenant:transfer -- export TENANT_ID /secure/transfers/tenant
```

Both production Compose files provide a hardened maintenance image with the
matching PostgreSQL client tools. Mount an operator-controlled encrypted
destination when running backup or tenant-transfer commands; no backup or
archive volume is attached by default. The mounted destination must be writable
by the maintenance container user (UID `1000` by default).
The continuity command defaults to 14 verified copies and a 26-hour freshness
threshold. Schedule `create` daily and monitor the exit status; run `check`
independently so a scheduler failure cannot look like backup success.
Tenant-transfer automation can use a read-only mode-`0600`
`--passphrase-file`; the passphrase itself is never accepted in an argument or
environment value.

Secret values are accepted only through hidden interactive input. Do not place
them in command arguments, shell history, source files, build arguments, or
logs.

## Production containers

Create the deployment directory and initialize it from an interactive terminal:

```bash
install -d -m 700 data
docker compose -f compose.production.yaml --profile tools run --rm --build settings init
docker compose -f compose.production.yaml --profile release run --rm --build migrate
docker compose -f compose.production.yaml up -d --build app
```

The settings tool performs the one-time ownership transition needed for the
non-root runtime container. Run later changes through the same tool service:

```bash
docker compose -f compose.production.yaml --profile tools run --rm settings list
docker compose -f compose.production.yaml --profile tools run --rm settings set YAHOO_CLIENT_SECRET
```

The app publishes only `127.0.0.1:3000` and expects a trusted HTTPS reverse
proxy. The liveness endpoint is `GET /api/health`. Database migrations are an
explicit, repeatable release step and never run automatically at app startup.
Recurring backups are also explicit: create a protected mode-`0700` destination
and invoke the tools-profile maintenance container from the installation's
scheduler. The repository never attaches or chooses a backup destination.

For a one-time migration from an older container, stream its configuration to
`settings import-env -`; no temporary environment file is required. A protected
legacy file can instead be mounted and imported by path, then securely retired
only after the new application passes its checks. This compatibility command is
not the continuing configuration mechanism.

## Private engine

The sanitized private-engine Compose contract is separate from the public
gateway contract:

```bash
install -d -m 700 data
docker compose -f compose.engine.yaml --profile tools run --rm --build settings init
docker compose -f compose.engine.yaml --profile release run --rm --build migrate
docker compose -f compose.engine.yaml up -d --build engine integration-gateway worker private-ingress
```

`engine`, `integration-gateway`, and `worker` have no `ports` mappings.
`private-ingress` is the narrow service facade and binds only
`127.0.0.1:11121` in the sanitized template. A
deployment-specific, untracked Compose override may replace that with an
approved private address. Never bind it to a public interface or configure a
public reverse proxy to supply the V·Sign client certificate.

The engine uses its own PostgreSQL database or role/schema boundary and its own
`data/VASI.settings`; do not reuse the gateway bootstrap. Service TLS keys,
client trust, internal HMAC material, assertion keys, and evidence-seal keys are
encrypted in the appropriate PostgreSQL settings scope. Run
`npm run engine:probe` from the gateway deployment to verify mTLS, actor
identity, and replay rejection. The disposable conformance environment also
runs `npm run engine:probe:evidence` for issuance, isolation, response, receipt,
seal, replay, and tamper checks, plus `npm run engine:probe:workflow` for roles,
drafts, immutable revisions, branching, lifecycle, encrypted outbox, and
multi-step sealing. `npm run engine:probe:documents` adds artifact ingestion,
inspection, streaming, rich activities, response revisions, scoring, and
version 3 manifest verification in that disposable environment.
`npm run engine:probe:media` verifies provider descriptors, bounded telemetry,
duration calculations, and version 4 sealing. `npm run engine:probe:reports`
verifies deterministic report reuse, PostgreSQL export streaming, certificate
and standard seals when configured, portable offline verification, public
lookup privacy, isolation, and tamper rejection.
`npm run engine:probe:interaction` verifies generalized activity presence,
strict privacy bounds, idempotency and changed-replay denial, deterministic
open/visible/engaged/idle/gap calculations, resumed sessions, version 5 sealing,
and offline tamper rejection.
`npm run engine:probe:lifecycle` verifies named retention-policy binding,
legal-hold enforcement and release, sealed purge tombstones, retired public
verification, participant history, reviewed data export, controlled expiry,
immutability, isolation, and lifecycle-chain integrity.
`npm run engine:probe:productization` verifies profile revisions, tenant
isolation, transactional quotas, exact destination allowlists, integration
credential redaction/kill-switch behavior, and evidence-bound tenant policy.
Run `npm run assurance:source -- /new/protected/directory` from a clean release
commit to create the source assurance manifest. Run
`npm run assurance:images -- /new/protected/directory IMAGE...` on a Docker host
to export and scan exact images without mounting the Docker socket into the
scanner. The output directories must not already exist and must remain outside
the repository.

See [Authentication setup](docs/authentication.md) for callbacks, provider and
mailer settings, administration behavior, and the release checklist. See
[Private engine deployment](docs/engine-deployment.md) and the
[engine boundary decision](docs/architecture/private-engine-boundary.md) for
the service trust and deployment contract. The
[sealed evidence slice](docs/architecture/sealed-evidence-slice.md) defines the
first transaction, record, and assurance limits. The
[workflow control plane](docs/architecture/workflow-control-plane.md) defines
the company roles, state machine, publication, lifecycle, and outbox contracts.
The [document and electronic activity decision](docs/architecture/document-artifacts-and-activities.md)
defines the PostgreSQL artifact lifecycle, supported contracts, streaming
boundary, assurance language, and inspection limitations.
The [generalized activity interaction evidence decision](docs/architecture/generalized-activity-interaction-evidence.md)
defines its fixed privacy-bounded events, authorization and replay controls,
deterministic duration model, PostgreSQL evidence, report and verifier
behavior, lifecycle integration, and assurance limits.
The [evidence report and verification decision](docs/architecture/evidence-reports-and-verification.md)
defines deterministic report profiles, portable bundle contents, offline and
online verification, PostgreSQL persistence, key rotation, certificate seals,
and assurance limits.
The [lifecycle governance and participant data decision](docs/architecture/lifecycle-governance-and-participant-data.md)
defines independent retention horizons, hold-safe deletion, integrity
tombstones, participant history, reviewed data access, and remaining legal and
operational approvals.
The [productized tenancy and integration decision](docs/architecture/productized-tenancy-and-integrations.md)
defines profile revisions, quotas, outbound isolation, deployment profiles,
backup/restore, and tenant transfer constraints.
The [operational readiness decision](docs/architecture/operational-readiness.md)
defines the aggregate-only snapshot, authorization boundary, host-probe
thresholds, privacy exclusions, and external-alerting handoff.
The [backup continuity decision](docs/architecture/backup-continuity.md)
defines atomic matched creation, verification, concurrency, retention,
freshness monitoring, scheduler handoff, and off-host custody limits.
The [deployment-perimeter readiness decision](docs/architecture/deployment-perimeter-readiness.md)
defines the public health/version, public and internal certificate, filesystem,
privacy, threshold, and scheduler handoff contract.
The [assurance and pilot-readiness contract](docs/assurance-and-pilot-readiness.md)
defines the threat register, repeatable release evidence, recovery/key drills,
observability limits, and the first-party, independent, legal, and customer
approval gates for a bounded pilot.
