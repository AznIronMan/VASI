# Lifecycle governance and participant data access

Status: implemented in VASI 0.10.0 and extended through VASI 0.30.0.

VASI 0.18.0 includes eligible participant-context snapshots and provenance in
approved technical participant exports and removes their PostgreSQL rows only
through the same hold/data-request-guarded purge.

## Purpose and boundaries

VASI treats original-content access, participant history, evidence archival,
and evidence deletion as separate lifecycle decisions. A workflow names a
retention profile; issuance binds the active immutable profile revision and its
hash to each assignment. Editing the profile later affects only records issued
after the new revision. A missing non-default profile fails issuance instead of
silently changing the record policy.

The portable system default keeps participant history available, makes original
content available only until request expiration, logically archives evidence
after 365 days, and never automatically deletes evidence. This is a conservative
software default, not legal advice or a substitute for an organization's
documented retention schedule.

## Independent lifecycle horizons

Each record stores a policy snapshot and separately calculated deadlines for:

- original workflow and document content access;
- the participant-facing history entry and report;
- logical evidence archival; and
- optional physical evidence deletion.

Completion anchors policies expressed as days after the terminal event. Request
expiration remains the anchor when that content mode is selected. Logical
archival preserves verification and does not itself remove evidence. Participant
history can remain available even after original content access ends.

The owner console permits versioned profile administration and shows the policy
hash, state, deadlines, and active or released holds for each bound record.
Owners and managers receive lifecycle-management permission; auditors receive
read-only lifecycle visibility.

## Append-only lifecycle audit and legal holds

Policy binding, terminal anchoring, access expiration, history expiration,
logical archival, purge eligibility, blockers, legal-hold placement/release,
and final purge are recorded in a per-assignment hash chain. Material lifecycle
events, hold placements, hold releases, and purge tombstones are immutable.

A hold is placed with a case or matter reference, a preservation reason, the
authorized actor, time, and idempotent command ID. Release is a separate row and
chain event with its own actor, time, command ID, and required reason. The
original hold is never edited to look released. An active hold blocks physical
purge regardless of the policy deadline.

## Controlled purge and integrity tombstones

The worker processes one due state transition under a row lock. Physical purge
requires all of the following:

1. A bound policy with a deletion deadline that is due.
2. No active legal hold.
3. No unexpired participant data request that includes the assignment.
4. A complete evidence chain and its last authoritative manifest reference.
5. An appended `record.purged` lifecycle event.
6. A detached, signed purge tombstone whose hash matches the database command.

Only a `SECURITY DEFINER` PostgreSQL function can perform the controlled delete.
It rechecks the deadline, state, blockers, and tombstone within the same
transaction. Transaction and participant rows are removed in dependency order;
request-level purge also removes immutable outbox and integration-gateway
delivery attempts before their parent jobs under the same tombstone-authorized
transaction. The immutable lifecycle chain, hold history, policy revision, and sealed
tombstone remain. Purging one assignment in a multi-participant request does not
delete request-level rows needed by another assignment.

The public exact-fingerprint verifier recognizes a retired manifest through its
tombstone and verifies every configured VASI and optional X.509 seal without
revealing participant, tenant, request, or content details. A tombstone proves
the retained purge assertion has not changed; it does not recreate deleted
evidence or establish that a retention decision was legally correct.

## Participant history and reviewed data requests

The V·Sign workspace lists records bound to the stable principal or verified
email. It shows the requesting organization, immutable issuance-time requester
email when available, issuance/invitation/authentication/open/activity/
completion chronology, current state, schedule, bounded activity progress,
exact submitted response labels and outcomes, effective content availability,
and the participant report. The participant report is privacy-reduced and
remains distinct from the fuller data-request workflow.

The authentication summary uses the earliest immutable participant-open event
and returns only the bounded method, provider, provenance, authenticated time,
and engine-observation time. Provider subjects, linked-account context, tokens,
request headers, IP addresses, browser context, and raw telemetry are not part
of the normal history response. The response summary uses final submitted
activity rows, not mutable UI state or saved drafts. Missing legacy observations
remain absent and the interface says they were not recorded.

Content availability is an intersection, never a union. A completed request
must first allow `content_always` or unexpired `content_until_expiration`; its
independent retention content horizon must also remain active. `receipt_only`,
revoked, expired, or retention-expired records report content unavailable while
their authorized history and sealed participant report remain separately
governed. The effective displayed deadline is the earlier applicable workflow
or retention deadline.

The workspace places `Request my VASI data` in a secondary privacy panel. A
request discovers matching assignments and creates one review scope per
requesting organization. Each organization can approve its own scope with the
mandatory redaction policy or deny it with a reason. The participant cannot
open an export while any scope remains pending. Approved exports:

- include the participant's matching assignments, responses, authentication
  provenance, participant-related evidence events, access events, lifecycle
  policy, generalized activity summary revisions, approved raw generalized
  activity/media telemetry, fingerprints, and public seal material;
- exclude requesting-organization secrets and internal-only metadata, workflow
  answer keys and source content, and unrelated third-party personal data;
- use canonical JSON, bounded PostgreSQL chunks, SHA-256 integrity, and detached
  VASI plus optional certificate seals; and
- expire after the configured delivery window, when chunks are deleted but
  request/export metadata and the access audit remain.

Request creation, every organization decision, export creation/open/download,
and expiration form a separate immutable hash chain. Metadata and chunks cannot
be altered; expiration is the one controlled chunk-deletion path. This workflow
supports transparent access to VASI-held information but does not automatically
determine jurisdiction-specific data-subject rights, exemptions, identity
requirements, response deadlines, litigation duties, or deletion rights.

## Storage and service independence

Authoritative lifecycle records, policies, holds, request scopes, exports,
chunks, seals, and audits live in engine-owned PostgreSQL. VASI does not create
an authoritative loose export file. The engine/domain/worker implementation is
framework-neutral and imports no Next.js, Better Auth, provider SDK, proprietary
workflow engine, hosted queue, or customer product. V·Sign remains the public
authentication and presentation gateway; it streams verified chunks but never
exposes the engine or its credentials.

## Runtime bounds and verification

The engine settings are:

- `ENGINE_PARTICIPANT_DATA_EXPORT_MAX_BYTES` (default 64 MiB);
- `ENGINE_EXPORT_CHUNK_BYTES` (default 256 KiB, shared with evidence exports);
- `ENGINE_DATA_REQUEST_REVIEW_DAYS` (default 30, accepted range 1–90); and
- `ENGINE_DATA_EXPORT_DELIVERY_DAYS` (default 7, accepted range 1–30).

The disposable integration environment proves optimistic policy revisions,
named-profile binding, hold idempotency, hold-safe purge, immutable hash chains,
standard and certificate tombstone seals, retired fingerprint verification,
participant history chronology and content-policy truthfulness,
cross-participant isolation, reviewed/redacted export,
controlled expiry, immutable metadata, and backup/restore fingerprints.

## Remaining assurance work

Before a customer relies on destructive retention, its legal/compliance owner
must approve the policy schedule, hold authority, release procedure, data-access
review process, and incident/recovery controls. Production deployments still
need deployment-specific backup retention, restore drills, monitoring, capacity
evidence, key-custody decisions, privacy documentation, and independent security
assessment. External KMS/HSM, trusted timestamp, revocation archival, and
long-term validation remain replaceable higher-assurance profiles.
