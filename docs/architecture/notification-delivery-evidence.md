# Notification delivery lifecycle and evidence

Status: implemented in VASI 0.22.0.

## Decision and assurance boundary

VASI treats notification transport as an operational and supporting-evidence
channel, not as proof that a person received or read a message. A successful
Microsoft Graph, SMTP, or webhook call is presented as `provider_accepted`.
Provider acceptance does not prove inbox placement, receipt, reading,
attention, identity, or a legally effective notice.

The private engine owns notification intent and lifecycle. The worker submits a
bounded signed command, and only the isolated integration gateway resolves the
active tenant binding, decrypts its credential, and contacts the allowlisted
provider. Provider tokens, response bodies, message bodies, recipient links,
and credentials never enter an owner status response or sealed delivery
evidence.

## Explicit purpose and bounded queue

Migration `0013_engine_notification_delivery` adds an indexed
`notificationType` to each outbox job. New notification jobs must be exactly
one of:

- `request.issued` for the invitation;
- `request.reminder` for scheduled or manual reminders; or
- `request.completed` for the participant's completion notice.

Purpose remains available after the AES-256-GCM message envelope is redacted,
so lifecycle decisions never need to decrypt a participant link. A request can
retain at most 32 notification jobs. Invitations and reminders reserve the
last slot for an optional completion notice. Workflow publication already
limits scheduled reminder offsets to eight; the remaining bound also prevents
unbounded manual-reminder history and sealed-manifest growth.

## Lifecycle behavior

Invitation and reminder jobs may run only while a request is scheduled, issued,
or in progress. A completion notice may run only after completion. Manual
reminders for a future request are held until its scheduled start rather than
sending a link that cannot yet be opened.

Revocation, reissue, expiration, and completion atomically suppress pending
invitations and reminders, redact their envelopes, and retain a bounded
suppression result. A worker sweep repeats that rule after stale-lock recovery,
covering a job that was running during a prior process failure. Completion
suppression occurs before the evidence manifest is sealed; the valid completion
notice is queued afterward and is not mistaken for an obsolete reminder.

Notification transport remains at-least-once. A provider call already in flight
when an owner revokes or a participant completes cannot be recalled. The
idempotency key and provider-specific controls reduce duplicate effects but do
not make an external email or webhook transactional with PostgreSQL.

## Company status projection

The owner request list returns only the latest invitation, reminder, and
completion state, plus a bounded reminder count. Each state may contain its
normalized status, adapter name, attempt count, scheduled/updated/completed
times, and a syntax-bounded error code. It excludes:

- encrypted or plaintext message payloads and participant paths;
- recipient fields beyond the request's separately authorized intended email;
- provider response metadata, message IDs, tokens, and response bodies;
- binding configuration and credentials; and
- unrelated tenant or request data.

The company console explains the provider-acceptance limit next to these
states. A workflow with issue delivery disabled is shown as a manual-link flow
rather than as a successful email.

## Manifest version 7

At completion, the engine snapshots every bounded notification job created for
the request up to the sealing time and every immutable adapter attempt completed
by that time. `vasi-evidence-manifest/v7` adds
`vasi-notification-delivery-evidence/v1`, containing only:

- job ID, explicit notification type, queue/schedule time, and normalized state;
- attempt number, bounded adapter, normalized outcome, optional fixed-syntax
  failure code, and start/completion times; and
- fixed limitations and the exact capture time.

The offline verifier requires the capture time to equal the manifest completion
time, rejects unknown fields, duplicate or excessive jobs, reordered or
excessive attempts, malformed or post-seal timestamps, unsupported adapters or
outcomes, false provider-acceptance state, and failure attempts without a
bounded error code. The manifest seal makes the captured snapshot tamper
evident. Later completion-notice attempts remain available in the authorized
live owner status but cannot be retroactively inserted into an already sealed
record.

When a record reaches its configured physical-retention purge, the existing
sealed tombstone authorization removes both outbox delivery attempts and their
integration-gateway attempts before deleting the parent jobs. Normal updates or
deletes of either immutable attempt history remain denied.

Participant and plain-language reports receive a reduced delivery summary
without internal job IDs or error codes. Technical and structured reports keep
the complete bounded sealed snapshot. All report forms repeat the limitation
that provider acceptance does not prove human receipt or review.

## Operational and legal limits

The administrator operational snapshot retains only aggregate 24-hour counts
and fixed-syntax failure codes. Customer-level investigation uses the
tenant-authorized request and evidence surfaces, not the aggregate monitoring
contract. Delivery receipts, bounce processing, mailbox read receipts, and
provider-specific tracking pixels are deliberately absent. They would require
new privacy, reliability, provider, and legal review and still could not prove
that the intended person read or understood the content.
