# Workflow and company-owner control plane

Status: implemented in VASI 0.6.0 and extended in VASI 0.7.0.

## Ownership boundary

VASI company authorization is engine-owned and independent of V·Sign identity
administration. An identity administrator may bootstrap a company and its first
owner, but an `admin` identity role grants no workflow or evidence permission.
Company roles are `owner`, `manager`, `author`, and `auditor`; the engine maps
them to explicit member, workflow, request, and record permissions on every
command. Owners grant access by verified email. The engine binds that grant to
the stable V·Sign principal when the recipient first lists their companies.

The current owner gateway is restricted to the configured private origin. A
future productized owner/integration gateway can use the same engine contracts
without direct engine or database access.

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
request is complete. The final version 3 evidence manifest covers the full
workflow snapshot, ordered activity outcomes and response revisions, exact
artifact bindings, policies, timestamps, event chain, and standard VASI
integrity seal.

## Request lifecycle and access

Requests support scheduled, issued, in-progress, completed, revoked, and
expired states; explicit due and expiration dates; revocation, reminder, and
reissue commands; and idempotency keys. The private worker advances scheduled
and expired requests under row locks and records both lifecycle and chained
evidence events. Reissue creates a new assignment and one-time opaque link bound
to the same immutable revision.

Post-completion policy is revision-bound: receipt only, original content until
request expiration, or continuing content access. The authenticated participant
receipt remains available even when the original content is no longer returned.

## Notification outbox

Issue, reminder, and completion notifications are transactional PostgreSQL
outbox jobs. Sensitive delivery payloads, including a pending participant path,
are AES-256-GCM envelopes under a dedicated engine setting; plaintext paths are
not stored in the assignment or outbox row. Terminal jobs redact the envelope
while preserving its payload hash and immutable delivery attempts.

The worker supports disabled/suppressed delivery, generic SMTP, and an HTTPS
webhook signed with HMAC-SHA256 over its timestamp and canonical body. Claims use
row locking, idempotency keys, bounded exponential retry, maximum attempts, and
stale-lock recovery. Provider-specific mail or workflow products are not engine
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
duration evidence are implemented in VASI 0.8.0. Reports, retention/legal hold,
and participant data requests remain separate milestones.
The standard integrity seal still does not claim an external CA identity,
trusted timestamp, or legal conclusion.
