# Workflow and company-owner control plane

Status: implemented in VASI 0.6.0 and extended through VASI 0.29.0.

## Ownership boundary

VASI company authorization is engine-owned and independent of V·Sign identity
administration. An identity administrator may bootstrap a company and its first
owner, but an `admin` identity role grants no workflow or evidence permission.
Company roles are `owner`, `manager`, `author`, and `auditor`; the engine maps
them to explicit member, workflow, request, and record permissions on every
command. Owners grant access by verified email. The engine binds that grant to
the stable V·Sign principal when the recipient first lists their companies.

The productized owner gateway is restricted to the configured private origin
and uses the same engine contracts without direct engine or database access.

VASI 0.27.0 exposes that bootstrap in the internal administrator console. The
requested owner receives a transactionally durable email grant in the private
engine. A separately attempted V·Sign invitation only helps the owner establish
or reuse an identity account; invitation delivery is not membership evidence
and does not change tenant admission. See
[Company provisioning and owner handoff](company-provisioning-and-owner-handoff.md).
VASI 0.28.0 makes the same bootstrap safely replayable across ambiguous network
outcomes without weakening the engine-owned membership or pending-admission
boundaries.

## Draft, publication, and execution

A workflow definition is durable. Its draft is mutable only through an
optimistic expected-version command. Publishing creates a new immutable
`workflow_revision` snapshot and never changes an earlier revision. Issued
requests retain their exact revision even when a newer draft is published.

The `vasi-workflow/v1` schema accepts ordered built-in activity contracts. VASI
0.6.0 introduced version 1 `terms_response` activities; VASI 0.7.0 adds the
separately documented approval, choice, free-form, electronic-signature,
PostgreSQL document-review, and deterministic questionnaire/test reducers.
Branches can compare the current validated response or reducer outcome for
equality and can move only to a later declared activity or a terminal outcome.
Unknown fields, activity types, contract versions, response values, backward
edges, cycles, and tenant-provided code are rejected before publication.

Each assignment receives immutable activity definitions and hashes. The engine,
not the browser, selects the current activity, validates its response, evaluates
the next transition, marks bypassed activities as skipped, and decides when the
request is complete. The current version 8 evidence manifest covers the full
workflow snapshot, ordered activity outcomes and response revisions, exact
artifact bindings, notification state and attempts available at completion,
policies, immutable requester snapshot, timestamps, event chain, and standard
VASI integrity seal.

## Request lifecycle and access

Requests support scheduled, issued, in-progress, completed, revoked, and
expired states; explicit due and expiration dates; revocation, reminder, and
reissue commands; and idempotency keys. The private worker advances scheduled
and expired requests under row locks and records both lifecycle and chained
evidence events. Reissue creates a new assignment and one-time opaque link bound
to the same immutable revision.

VASI 0.23.0 snapshots the authenticated requesting user's stable principal and
issuance-time email on every request. The participant sees that requester,
material schedule, post-completion access, and audit/data-access meaning before
acting. Current membership changes cannot alter receipts, reports, participant
history, or approved data exports. See the
[requester provenance decision](requester-provenance-and-participant-disclosure.md).

Post-completion access policy is revision-bound: receipt only, original content
until request expiration, or continuing content access. In VASI 0.10.0, the
workflow also names a versioned retention profile whose active revision is
snapshotted at issuance. The authenticated participant history/report horizon,
original content horizon, evidence archive, and optional evidence deletion are
then enforced independently.

## Notification outbox

Issue, reminder, and completion notifications are transactional PostgreSQL
outbox jobs. Sensitive delivery payloads, including a pending participant path,
are AES-256-GCM envelopes under a dedicated engine setting; plaintext paths are
not stored in the assignment or outbox row. Terminal jobs redact the envelope
while preserving its payload hash and immutable delivery attempts.

VASI 0.22.0 gives every job an explicit invitation, reminder, or completion
purpose outside the encrypted envelope. Revoked, reissued, expired, and
completed requests suppress obsolete pending invitations and reminders;
completion notices remain eligible only for completed requests. The owner
request list exposes a privacy-bounded normalized state and the evidence
manifest seals attempts completed before the transaction seal. Adapter success
is described as provider acceptance, not proof of inbox delivery or reading.
The complete contract and race limits are documented in the
[notification delivery decision](notification-delivery-evidence.md).

The worker submits a signed, bounded, versioned delivery contract to the
internal integration gateway. That gateway resolves the tenant binding,
decrypts credentials, rechecks the installation host allowlist, and supports
disabled/suppressed delivery, mailbox-scoped Microsoft Graph app-only mail,
generic SMTP, and an HTTPS webhook signed with HMAC-SHA256 over its timestamp
and canonical body. Microsoft Graph additionally requires exact
installation-approved tenant, application, and sender values and uses only
fixed Microsoft HTTPS endpoints. Claims use row locking,
idempotency keys, bounded exponential retry, maximum attempts, and stale-lock
recovery. Provider-specific mail or workflow products are not engine
dependencies.

## Authentication provenance

New V·Sign sessions store the authentication method, provider, provider subject,
and capture provenance on the session row. Actor assertions distinguish that
session-specific evidence from a separately labeled most-recent linked-provider
context. Older sessions without these columns populated are reported as
unspecified rather than guessed. Provider tokens, cookies, and credentials are
never forwarded to the engine.

## Current limits

PostgreSQL documents, questions/tests, typed/drawn signatures, and append-only
response revisions are implemented in VASI 0.7.0. Provider-hosted media and
duration evidence are implemented in VASI 0.8.0. Deterministic reports,
portable bundles, offline/public verification, and optional X.509 leaf seals
are implemented in VASI 0.9.0. Retention, legal holds, controlled purge,
participant history, and reviewed participant data exports are implemented in
VASI 0.10.0. Advanced trust-service/timestamp profiles remain separate
milestones. The
standard integrity seal still does not claim an external CA identity, trusted
timestamp, or legal conclusion.
