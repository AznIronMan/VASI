# VASI

Verified Authorized Signing Infrastructure

Version: `0.36.3`

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
Docker socket. Each known release image must also pass its explicit runtime
contract: the intended UID reads and parses every declared runtime command inside a no-network,
read-only, capability-dropped container, and an unknown image role fails closed.
Browser-rendered WCAG automation and a bounded read-only load probe cover the
public readiness surface. Runtime images no longer contain the unused npm
toolchain, reducing their attack surface. The threat model and pilot contract
explicitly separate first-party evidence from independent security,
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

Version 0.18.0 adds immutable, privacy-bounded participant browser/device
context observations at activity presentation and immediately before saves or
submissions. A strict schema accepts only reported locale/time zone,
viewport/screen, pixel/color, touch, cookie/storage/PDF capability,
accessibility preference, online, and coarse connection values. It explicitly
excludes plugin/font enumeration, invasive fingerprinting, precise location,
hardware identifiers, hidden media, keys, input contents, coordinates, and
secrets. Authenticated context rows are replay-safe, sealed in manifest version
6, independently hash/chain verified, summarized by audience, included only in
approved technical participant exports, governed by retention, and transferred
with every generalized interaction table in encrypted tenant archives.

Version 0.19.0 adds a vendor-neutral, fail-closed document malware-scanning
boundary. A tenant may activate a signed HTTPS scanner only after an
installation administrator allowlists its exact host. The evidence engine
never contacts the scanner or reads its credential: it submits a narrow,
digest-bound command to the isolated integration gateway, which revalidates
the active revision, streams ordered quarantined PostgreSQL chunks over
certificate-verified HTTPS, rejects redirects and oversized or extended
responses, and requires the verdict to repeat the exact SHA-256 digest. Clean
documents publish, malicious or suspicious documents reject, and transport,
protocol, or scanner failures remain quarantined for an authorized retry.
Every call creates an immutable, idempotent, privacy-bounded attempt without
document bytes, filenames, credentials, or raw provider bodies. Workflow
snapshots and evidence-bundle indexes bind the inspection profile and result
hash; owner and administrator consoles expose governed configuration, retry,
and aggregate operational state.

Version 0.19.1 makes release-image executability a blocking assurance check.
Every supported image declares its expected configured user, intended runtime
UID/GID, and bounded runtime commands. The gate parses every command with no network, a
read-only root filesystem, all capabilities dropped, and privilege escalation
disabled, catching unreadable source archives or image-user drift before a
migration or service cutover.

Version 0.20.0 adds privacy-safe host and PostgreSQL capacity readiness. A
hardened maintenance profile samples only aggregate Linux CPU, load, memory,
swap, and pressure-stall files; measures byte and inode capacity through
explicit empty sentinel mounts; and queries aggregate PostgreSQL size,
latency, connection, transaction-age, and replication posture. Fixed reason
codes and bounded JSON omit host paths, database endpoints, processes,
credentials, and customer data. The portable default reports replication
posture without requiring a replica; an installation can make primary-replica
presence a blocking approved threshold.

Version 0.21.0 introduces deny-by-default private-engine outbound access. The
engine and worker join internal networks only; the integration gateway alone
receives a dedicated provider-egress network. Persistent
PostgreSQL clients preserve end-to-end TLS hostname verification through a
minimal raw transport gateway whose dedicated bridge is restricted by an
exact resolved IPv4-and-port host policy. Packaged refresh and verification
timers cover boot, network recreation, and bounded DNS change. Release
assurance blocks network drift, missing read-only transport markers, host
networking, Docker-socket mounts, `NET_ADMIN`, IPv6 expansion, unrecognized
gateway images, or weakened persistence units. A privacy-safe live probe proves
the exact firewall, private denial, integration egress, runtime health, and
database transport without exposing route, endpoint, credential, or customer
details.

Version 0.21.1 makes the database-gateway image a mandatory target in the
commit-pinned CI build, runtime-contract check, SBOM export, and vulnerability
scan. Source assurance derives the complete release-image set from the
versioned policy and rejects a workflow that omits any declared image.

Version 0.21.2 gives private ingress a dedicated single-stack listener bridge
so Docker can publish its approved private listener without giving the process
general outbound access. A second exact host chain permits established reply
traffic from that bridge and rejects every new forwarded flow. The recurring
boundary proof now requires both host chains, four private-service denial
canaries, a reachable published listener, integration egress, runtime health,
and database transport.

Version 0.21.3 corrects the engine deployment-perimeter runbook: that probe
must contact the public health/TLS origin, so engine scope runs from the
trusted host with protected bootstrap access. The maintenance container keeps
its exact-database-only egress boundary; no private container is broadened for
an operational check.

Version 0.21.4 makes recurring host enforcement robust for one-shot services.
Both systemd timers now schedule a first run relative to timer activation and
subsequent runs relative to the service becoming inactive, preventing an
enabled timer from remaining elapsed with no future trigger.

Version 0.22.0 makes workflow notification delivery visible, lifecycle-safe,
and part of the sealed record. Every notification job carries an explicit
invitation, reminder, or completion purpose outside its encrypted payload.
Company owners see a bounded per-request state while recipient links, message
bodies, credentials, and provider responses remain excluded. Revocation,
reissue, expiration, and completion suppress obsolete queued invitations and
reminders without suppressing a valid completion notice. Manifest version 7
seals the immutable adapter attempts available at completion, and reports use
the accurate term “provider accepted” because Graph, SMTP, or webhook success
does not prove inbox delivery, receipt, reading, attention, or identity.

Version 0.23.0 makes the accountable requesting user an immutable part of each
request. The engine snapshots the authenticated issuer's stable principal and
issuance-time email, PostgreSQL prevents later mutation, and manifest version 8
binds that snapshot to the scheduled-or-issued evidence actor. Participant
request pages now disclose the company, requester, purpose, due and expiration
times, post-completion access policy, audit-record meaning, and reviewed data
access before an action is submitted. Receipts, reports, participant history,
and approved data exports use the snapshot rather than mutable company
membership, so disabling or removing a requester cannot rewrite history.

Version 0.24.0 packages the complete recurring operations contract instead of
leaving scheduler parity to each installation. Hardened, independent systemd
service/timer pairs now cover matched backup creation and freshness, aggregate
capacity, public/service-certificate deployment readiness, private-engine
operational readiness, and the existing outbound policy/boundary controls.
Release assurance rejects missing, weakened, installation-specific, or
non-persistent units. Deployment readiness can derive its public origin from
the encrypted PostgreSQL settings for its gateway or engine scope, so the
portable units contain no environment file, customer hostname, credential, or
private deployment path.

Version 0.25.0 adds product-owned tenant production admission. Every new and
existing tenant starts pending until an installation administrator records an
attributable, digest-bound approval for all eight release, security, identity,
legal/privacy, accessibility, content-safety, recovery/custody, and
capacity/support gates. Immutable optimistic revisions and the tenant
configuration chain preserve the decisions. The engine and PostgreSQL block
request issuance and active integration revisions while pending, and the
integration gateway rechecks admission immediately before outbound work so a
later revocation suppresses queued delivery. Each new request binds the exact
admitted snapshot into manifest version 9; the offline verifier and reports
validate and explain that binding. The internal console manages approvals, and
the privacy-safe operations snapshot reports admitted versus pending tenants.

Version 0.26.0 closes the production-stop gap for requests that were already
issued. An installation administrator can now execute one replay-resistant,
optimistically locked tenant stop that revokes an accountable admission gate,
every scheduled/issued/in-progress request, and every pending invitation or
reminder in one PostgreSQL transaction. Each affected assignment receives a
hash-chained revocation event, the request lifecycle retains an immutable
command record, and the tenant configuration chain preserves only a bounded
reason code and opaque incident reference. Completed evidence, participant
history, retention state, and legal holds remain intact. The internal console
shows the last stop outcome; recovery requires fresh gate approval and newly
issued participant work.

Version 0.27.0 makes first-company provisioning and owner handoff a supported
internal-administrator workflow. A strict gateway command sends only the
normalized company name, identifier, and initial owner email to the private
engine. In one engine transaction VASI creates the company, administrator
membership, requested owner grant, immutable tenant profile, disabled
integration bindings, pending production-admission record, and hash-chained
configuration events. The optional login invitation is deliberately attempted
only after that durable transaction. The admin console distinguishes sent,
existing-account, not-required, skipped, and delivery-failed outcomes, so an
email outage cannot cause an operator to create a duplicate company or mistake
mail delivery for owner authorization. Provisioning never admits production;
all eight assurance gates still require independent attributable approval.

Version 0.28.0 makes that provisioning workflow safe to retry after an
ambiguous gateway, engine, or browser network outcome. Each browser submission
uses a UUID command that remains stable while the normalized form is unchanged.
The private engine serializes concurrent reuse, binds the command to the exact
input digest and administrator principal, and stores an immutable,
integrity-checked bounded result in the engine database transaction. An exact
retry returns that result without creating a second company; changed-input or
cross-administrator reuse fails closed. The optional identity invitation is
bound to the same command and records `pending`, `provider_accepted`, or
`failed` delivery state. A confirmed retry never sends twice, while the
unavoidable provider-acceptance/receipt gap is reported as `delivery_unknown`
instead of being misrepresented or automatically redelivered. Replay records
contain no plaintext input command, remain installation-scoped, and are
excluded from tenant transfer archives.

Version 0.29.0 extends the same recovery guarantee across an administrator tab
reload or renderer crash. Before provider contact, both company-provisioning
forms normalize the durable choices and compute a SHA-256 digest with browser
Web Crypto. Per-tab session storage may retain only the opaque UUID command,
the 64-character digest, and a bounded creation timestamp—never the company
name, owner email, identifier, or invitation choice. Strict parsing removes
unknown, corrupt, more-than-one-minute-future, or older-than-24-hour state. An unchanged form
recovers its command after reload; changed input receives a new command;
success or a definite client rejection clears it; ambiguous transport/server
outcomes retain it. Storage or digest unavailability never blocks the
server-enforced provisioning contract.

Version 0.29.1 makes connector health an authentication observation rather
than an account-maintenance heuristic. Each supported provider account has a
dedicated timestamp and bounded provenance. Only the post-create hook of a
completed, provider-attributed federated session can advance the live value;
password and verification sessions, token refreshes, and generic provider
account updates cannot. Migration preserves the latest exact attributed
session where available and labels an older account-update timestamp only as a
legacy estimate until the next successful provider sign-in replaces it. The
internal console holds that estimate in the red/unknown state rather than
presenting it as an active login. Exact observations retain the configured,
connected, 90-day, and error status-light contract.

Version 0.30.0 completes the participant-facing durable transaction-history
summary. Each authenticated history entry now derives its bounded sign-in
method/provider, invitation state, schedule, state-transition time, activity
progress, last interaction, and exact submitted response labels from the
authoritative engine record. The workspace deliberately omits provider
subjects, raw browser/network telemetry, answer keys, credentials, and internal
delivery details. Post-completion content availability is evaluated against
both the immutable workflow policy and the independent retention horizon, so a
`receipt_only` record can never be presented as having retained source content.
Missing legacy observations remain visibly unrecorded rather than inferred.

Version 0.31.0 adds immutable, provider-neutral authentication assurance to
each workflow. Owners can require federated SSO, selected verified sign-in
classes, and an optional recent-authentication window; new owner-console
workflows default toward federated SSO. The private engine evaluates the exact
gateway-session method and authentication time after participant authorization
and before assignment access, protected document/media delivery, or response
mutation. A deliberate sign-out and return flow handles stale or disallowed
sessions without exposing request existence to another user. Accepted material
events carry privacy-bounded evaluations, manifest version 10 seals their policy
and event bindings, and the offline verifier independently recomputes every
result. Human reports summarize the requirement without exposing provider
subjects, tokens, credentials, or additional identity-provider claims.

Version 0.32.0 applies a separate product-mandated recent-authentication gate
to participant privacy access. The private engine requires an authentication no
more than 15 minutes old before creating a `Request my VASI data` case, opening
its reviewed technical export, or reading every export chunk. Successful
creation, open, and completed-download events bind the bounded assurance
evaluation to the immutable data-request audit chain; stale, missing, invalid,
or future-skewed observations fail closed. V·Sign presents an explicit sign-out,
sign-in-again, and `/workspace` return path without exposing provider subjects,
tokens, secrets, or another participant's request.

Version 0.33.0 makes reviewed participant-data delivery an engine-owned durable
workflow. The private worker—not a participant download request—atomically
builds, seals, chunks, and marks each fully reviewed export ready in PostgreSQL;
deterministic size-limit failures become visible terminal states instead of
worker retry loops. Each reviewing company owns its readiness, scope-denial,
preparation-failure, and export-expiry notice through its admitted tenant
integration binding. Payloads remain encrypted until dispatch and are redacted
at terminal state. Queueing and final provider acceptance, suppression, or
failure join the immutable participant-data request chain, while the participant
workspace exposes truthful delivery status and requires the existing recent
authentication gate before any ready artifact can open. The isolated integration
gateway independently binds every delivery to the exact running outbox job and
locks the current source status through provider submission.

Version 0.34.0 makes identity administration tamper-evident and operationally
observable. Gateway migration 0007 deterministically backfills the existing
administrator history into an immutable SHA-256 chain and serializes all later
appends at the database boundary. Privileged commands now carry server-generated
command/request IDs, actor-session and bounded request context, and explicit
started plus succeeded, failed, or ambiguous outcomes. Local mutations commit
their terminal evidence atomically; provider-side uncertainty remains visible
instead of being reported as a clean failure. The internal console independently
recomputes integrity and exposes recent evidence and unfinished commands only to
allowlisted administrators. A separate privacy-safe gateway probe and persistent
timer detect exact migration drift, chain/head mismatch, slow reads, and stale
incomplete commands without emitting identity or request details.

Version 0.35.0 adds provider-neutral recipient-encrypted backup custody. A
verified matched PostgreSQL/bootstrap directory streams directly into one
authenticated `.vbc` package without a plaintext aggregate archive. Fixed
8 MiB independently authenticated AES-256-GCM chunks protect the content;
ephemeral X25519, HKDF-SHA-256, and per-recipient
AES-256-GCM wraps let up to eight independently controlled custodians recover
without placing a private key on the VASI host. Copy-digest/structure and
freshness checks, fail-closed retention, protected recipient generation, and
offline authenticated extraction are included. VASI still does not select or
claim an off-host destination, private-key custodian, transfer completion,
geographic separation, RPO, RTO, or recovery approval.

Version 0.36.0 adds an application-owned byte boundary before gateway request
parsing. Every VASI JSON mutation route and the Better Auth POST catch-all now
stream at most 64 KiB, reject an oversized declared length before reading,
count actual UTF-8/wire bytes across chunks, and return a generic no-store 413
on overflow. Invalid encoding, malformed JSON, non-object JSON, unreadable or
truncated streams, and declared/actual length disagreement fail with a generic
400. Accepted authentication bodies are rebuilt without forwarding an
untrusted `Content-Length`, preserving JSON and provider form-post callbacks.
PostgreSQL document upload keeps its separate bounded streaming contract.

Version 0.36.2 makes the trusted-host engine deployment-perimeter probe
repeatably deployable. A root-only preparation helper installs only the exact
lockfile's required production packages, omits development and optional
packages, disables npm lifecycle scripts, supports a fail-closed pre-seeded
offline cache, and installs a stable host verifier. The verifier proves the
Node version, package/lock agreement, installed top-level production versions,
absence of declared or lock-marked nonproduction residue, and protected
settings runtime import. The recurring systemd service runs it before every
perimeter check, so a fresh cutover or rollback cannot silently depend on
missing or stale host packages.

Version 0.36.3 minimizes the physical dependency surface of every production
container role. Production-only Docker stages now use exact-lockfile installs
that omit development and optional packages, disable lifecycle scripts, and
avoid audit/funding network side effects. Release assurance derives every
declared-development and lock-marked development/optional package path from the
exact manifests and checks the filesystem of each hardened image as its
intended user. npm, npx, undeclared exceptions, and residue such as build/test
tooling stop the release before scanning or deployment. The standalone Next.js
application has a six-path, role-specific exception for its required Alpine
x64 `sharp` image runtime; the unrelated optional PostgreSQL Cloudflare adapter
is explicitly removed. Source assurance also rejects weakened Docker install
or pruning instructions.

The standard seal proves that the manifest and covered chain have not changed
and were signed by the configured VASI seal key. An optional certificate seal
can establish an additional configured certificate identity, but local
verification alone does not establish chain trust, revocation status, trusted
time, legal enforceability, or long-term validation. Scanner selection,
signature quality/update policy, external KMS/HSM/TSA trust profiles,
deployment-specific legal/privacy approval, and independent security
assessment remain installation or pilot gates.

## Included

- Next.js 16 and Better Auth with PostgreSQL-backed users, accounts, sessions,
  verification records, rate limits, and a pre-parser 64 KiB authentication
  request-body boundary.
- Microsoft, Google, Yahoo, Zoho, Apple-ready, and manual authentication with an
  SSO-first participant experience.
- Internal-host-only identity administration, operator allowlisting,
  invitations, connector health/disconnection, password controls, account
  disablement, session revocation, command-correlated immutable audit evidence,
  independent chain verification, and bounded internal forensic context.
- Administrator-only company provisioning with a transactionally durable
  initial-owner grant, separately reported login invitation outcome, and an
  explicit pending-production handoff to the eight assurance gates.
- Administrator-only, immutable tenant production admission with eight exact
  digest-bound assurance gates, fail-closed issuance/outbound enforcement, and
  an atomic audited stop for all non-terminal tenant work.
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
- Provider-neutral workflow authentication assurance with SSO-first owner
  defaults, optional sign-in freshness, private-engine enforcement across
  content and material actions, deliberate participant reauthentication,
  manifest v10 evidence, report summaries, and offline recomputation.
- AES-256-GCM encrypted outbox envelopes, immutable delivery-attempt records,
  explicit notification purpose, bounded retry and stale-lock recovery,
  lifecycle-safe suppression, owner-visible provider-acceptance state, and
  manifest-sealed attempt snapshots; tenant-scoped mailbox-restricted Microsoft
  Graph, generic SMTP, and HMAC-signed HTTPS webhook adapters remain behind
  exact installation allowlists.
- Revisioned installation/tenant profiles, transactional capacity enforcement,
  evidence-bound branding/policy snapshots, encrypted integration credentials,
  hash-chained configuration events, and owner/operator control panels.
- Sanitized self-hosted/SaaS profiles, matched PostgreSQL/bootstrap backup and
  restore verification, plus passphrase-authenticated streaming tenant archives
  that re-encrypt credentials and establish a destination owner grant.
- A provider-neutral single-file matched-backup custody envelope with
  multi-recipient X25519 key wrapping, streaming fixed-size authenticated
  AES-256-GCM content chunks, copy-digest/freshness checks, fail-closed retention, and offline
  authenticated extraction without application-host private keys.
- PostgreSQL-only authoritative non-media artifacts with bounded chunk upload
  and delivery, immutable source/derived/replacement revisions, SHA-256
  verification, quarantine/inspection, exact workflow binding, and access
  auditing.
- Optional fail-closed signed HTTPS malware scanning through the isolated
  integration gateway, with exact-host policy, certificate validation,
  digest-matched verdicts, immutable privacy-bounded attempts, safe quarantine
  retry, and no authoritative loose file.
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
- Immutable presentation/save/submission browser-context snapshots with fixed
  passive browser-reported fields, explicit provenance, participant
  and session binding, version 6 sealing, audience-reduced reports, forensic
  verification, reviewed data access, purge, and encrypted tenant transfer.
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
  export with recent-authentication enforcement at request creation and every
  export access, audited assurance, and automatic content expiry.
- A release assurance gate with tracked-source policy, complete and production
  dependency audits, CycloneDX source/image SBOMs, digest-pinned image scanning,
  fail-closed non-root runtime-command smoke checks, runtime version alignment,
  sanitized Compose hardening checks, browser WCAG automation, and bounded
  read-only readiness load testing; direct unbounded JSON parsing in gateway
  request-handling source fails the release gate.
- An administrator-only operational snapshot and host probe with explicit
  migration, queue, delivery, document-scanning, signing, lifecycle, and
  database thresholds that exclude customer evidence and identity data.
- A separate aggregate-only gateway identity-operations probe that verifies
  exact migration checksums, the administrator audit chain/head, incomplete
  command age, ambiguous-command count, and database latency.
- Concurrency-safe recurring matched backups with post-create verification,
  bounded retention, freshness assessment, and hardened gateway/engine
  maintenance containers.
- A privacy-safe deployment-perimeter probe for public health/version, public
  and service-certificate expiry, and filesystem pressure, with bounded
  policy thresholds and vendor-neutral scheduler/alerting handoff.
- A privacy-safe capacity probe for bounded aggregate Linux CPU, load, memory,
  swap, pressure stalls, fixed-code filesystem byte/inode state, and
  PostgreSQL size, latency, connection, transaction, and replication posture.
- A tracked hardened scheduler suite with independent persistent timers for
  gateway/engine backup creation and checks, capacity, deployment perimeter,
  gateway identity operations, private-engine operational readiness, and
  private outbound enforcement.

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
npm run backup:custody -- recipient OPAQUE_KEY_ID /secure/offline/private.jwk
npm run backup:custody -- create /secure/backups /approved/off-host-mount --scope gateway
npm run backup:custody -- check /approved/off-host-mount
npm run backup:custody -- authenticate /approved/off-host-mount/PACKAGE.vbc --key-id OPAQUE_KEY_ID --private-key-file /secure/offline/private.jwk
npm run assurance:deployment -- --scope gateway --storage /secure
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
After configuring only the generated public record in
`BACKUP_CUSTODY_RECIPIENTS`, the custody command streams the newest matched
copy into a recipient-encrypted `.vbc` package and defaults to 30 managed
packages plus the same 26-hour source-age threshold. Keep private JWKs off the
VASI host, monitor custody creation and checking independently, and prove the
mounted destination is genuinely off-host. See the
[encrypted custody decision](docs/architecture/encrypted-backup-custody.md) for
rotation, offline extraction, metadata disclosure, and recovery requirements.
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
After each gateway migration, run `npm run assurance:gateway-operations`; its
aggregate result must pass before enabling or re-enabling the gateway identity
operational-readiness timer.
Recurring safeguards are explicit but packaged: create the protected backup
and capacity sentinel directories, install the applicable tracked units under
`deployment/systemd`, validate them with `systemd-analyze verify`, manually run
every service once, and then enable its timer. The sanitized units select only
portable `/opt` and `/var/lib` defaults; installations using other roots must
apply reviewed systemd drop-ins. The repository never attaches a backup volume
to a long-running container or chooses external custody.

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
docker compose -f compose.engine.yaml build database-gateway engine maintenance settings
docker compose -f compose.engine.yaml up --no-start --no-deps database-gateway private-ingress
sudo /bin/sh scripts/apply-database-egress-policy.sh apply
docker compose -f compose.engine.yaml --profile release run --rm --build migrate
docker compose -f compose.engine.yaml up -d --no-build database-gateway engine integration-gateway worker private-ingress
sudo /usr/bin/env node scripts/probe-engine-egress-boundary.mjs
```

`engine`, `integration-gateway`, and `worker` have no `ports` mappings.
`private-ingress` is the narrow service facade and binds only
`127.0.0.1:11121` in the sanitized template. A
deployment-specific, untracked Compose override may replace that with an
approved private address. Never bind it to a public interface or configure a
public reverse proxy to supply the V·Sign client certificate. Its dedicated
listener bridge is externally routable at Docker's network layer only so port
publication works; the required host chain allows established replies and
denies every new outbound flow from that bridge.

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
built-in and external inspection, signed HTTPS streaming,
clean/threat/outage/retry/replay/tamper cases, immutable scan-attempt privacy,
rich activities, response revisions, scoring, and version 3 manifest
verification in that disposable environment.
`npm run engine:probe:media` verifies provider descriptors, bounded telemetry,
duration calculations, and version 4 sealing. `npm run engine:probe:reports`
verifies deterministic report reuse, PostgreSQL export streaming, certificate
and standard seals when configured, portable offline verification, public
lookup privacy, isolation, and tamper rejection.
`npm run engine:probe:interaction` verifies generalized activity presence,
strict privacy bounds, idempotency and changed-replay denial, deterministic
open/visible/engaged/idle/gap calculations, resumed sessions, version 5 sealing,
and offline tamper rejection.
`npm run engine:probe:context` verifies participant-context schema privacy,
participant isolation, idempotency and changed-replay denial, sequence binding,
current manifest sealing, report audience reduction, and offline tamper
rejection.
`npm run engine:probe:lifecycle` verifies named retention-policy binding,
legal-hold enforcement and release, sealed purge tombstones, retired public
verification, participant history, worker-prepared reviewed data export,
encrypted and controller-scoped status delivery, controlled expiry,
immutability, isolation, and lifecycle-chain integrity.
`npm run engine:probe:productization` verifies profile revisions, tenant
isolation, transactional quotas, exact destination allowlists, integration
credential redaction/kill-switch behavior, and evidence-bound tenant policy.
Run `npm run assurance:source -- /new/protected/directory` from a clean release
commit to create the source assurance manifest. Run
`npm run assurance:images -- /new/protected/directory IMAGE...` on a Docker host
to verify the configured/runtime user contract, parse every declared command in
a no-network hardened container, and export/scan exact images without mounting
the Docker socket into the scanner. Unknown image roles are rejected. The
output directories must not already exist and must remain outside the
repository.

See [Authentication setup](docs/authentication.md) for callbacks, provider and
mailer settings, administration behavior, and the release checklist. See
[Private engine deployment](docs/engine-deployment.md) and the
[engine boundary decision](docs/architecture/private-engine-boundary.md) for
the service trust and deployment contract. The
[private-engine outbound-isolation decision](docs/architecture/private-engine-egress.md)
defines the deny-by-default networks, raw PostgreSQL bridge, exact host policy,
persistence, failure, rollback, and bounded verification contract. The
[sealed evidence slice](docs/architecture/sealed-evidence-slice.md) defines the
first transaction, record, and assurance limits. The
[workflow control plane](docs/architecture/workflow-control-plane.md) defines
the company roles, state machine, publication, lifecycle, and outbox contracts.
The [workflow authentication-assurance decision](docs/architecture/workflow-authentication-assurance.md)
defines the provider-neutral policy, enforcement order, reauthentication flow,
privacy-bounded manifest v10 evidence, independent verification, and limits.
The [notification delivery evidence decision](docs/architecture/notification-delivery-evidence.md)
defines explicit delivery purpose, lifecycle suppression, bounded owner status,
manifest version 7 evidence, provider-acceptance wording, and at-least-once
limits.
The [requester provenance and participant disclosure decision](docs/architecture/requester-provenance-and-participant-disclosure.md)
defines the immutable issuance-time requesting user, manifest binding,
participant pre-action notice, history/data-export behavior, and assurance
limits.
The [document and electronic activity decision](docs/architecture/document-artifacts-and-activities.md)
defines the PostgreSQL artifact lifecycle, supported contracts, streaming
boundary, assurance language, and inspection limitations.
The [generalized activity interaction evidence decision](docs/architecture/generalized-activity-interaction-evidence.md)
defines its fixed privacy-bounded events, authorization and replay controls,
deterministic duration model, PostgreSQL evidence, report and verifier
behavior, lifecycle integration, and assurance limits.
The [participant context evidence decision](docs/architecture/participant-context-evidence.md)
defines its fixed browser-reported schema, explicit exclusions, authenticated
binding, PostgreSQL immutability, manifest version 6 introduction and version 8
carriage, report/data-access behavior, lifecycle and transfer integration, and
assurance limits.
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
The [identity-administration audit decision](docs/architecture/identity-administration-audit.md)
defines privileged command correlation, atomic/ambiguous outcomes, immutable
gateway chaining, bounded internal context, independent verification, and the
aggregate gateway monitor.
The [backup continuity decision](docs/architecture/backup-continuity.md)
defines atomic matched creation, verification, concurrency, retention,
freshness monitoring, scheduler handoff, and off-host custody limits.
The [recipient-encrypted backup custody decision](docs/architecture/encrypted-backup-custody.md)
defines public-recipient configuration, streaming envelope cryptography,
copy/freshness verification, fail-closed retention, offline extraction,
rotation, metadata disclosure, and remaining off-host ownership.
The [deployment-perimeter readiness decision](docs/architecture/deployment-perimeter-readiness.md)
defines the public health/version, public and internal certificate, filesystem,
privacy, threshold, and scheduler handoff contract.
The [capacity-readiness decision](docs/architecture/capacity-readiness.md)
defines aggregate host, filesystem-inode, PostgreSQL-saturation, privacy,
threshold, sentinel-mount, and scheduler handoff contracts.
The [recurring operations decision](docs/architecture/recurring-operational-schedulers.md)
defines the packaged unit set, independent schedules, hardening, path override,
PostgreSQL-origin, installation, validation, and alerting contract.
The [assurance and pilot-readiness contract](docs/assurance-and-pilot-readiness.md)
defines the threat register, repeatable release evidence, recovery/key drills,
observability limits, and the first-party, independent, legal, and customer
approval gates for a bounded pilot.
