# Identity-administration audit integrity

Status: implemented in VASI 0.34.0.

## Decision

Every privileged identity mutation is represented by an append-only gateway
audit command. The public authentication origin never exposes this history. An
allowlisted administrator can inspect recent events and independently
recomputed integrity only through the internal administrator origin.

This is gateway control-plane evidence. It complements, but does not replace,
the private engine's participant evidence chains and VASI integrity seals.

## Chain and command model

Gateway migration `0007_admin_audit_chain` converts every existing
`vasi_admin_audit` row into one deterministic sequence ordered by its original
creation time and ID. A PostgreSQL insert trigger serializes all later appends
under a transaction-scoped advisory lock. Each event stores:

- a positive sequence and the previous event hash;
- a canonical JSON payload containing the event ID, action, phase, command and
  request IDs, actor/user/session references, target reference, bounded request
  context, metadata, and creation time; and
- `SHA-256(previousHash || canonicalPayload)` plus a separately maintained chain
  head.

The genesis previous hash is 64 zeroes. Row update, row delete, and table
truncate are rejected by database triggers. User foreign keys are deliberately
removed from this table so account deletion cannot rewrite actor or target
history. The independent Node verifier recomputes sequence continuity,
canonical-payload agreement, every event hash, and the final chain head.

A privileged command has a server-generated command ID and request ID. It first
records `started`, then exactly one of:

- `succeeded` when the operation and its required local audit event committed;
- `failed` when a known local transaction rolled back; or
- `ambiguous` when an external provider may have committed but VASI cannot
  prove the final outcome.

Database-local connector disconnection, password disablement, invitation state,
and invitation acceptance commit their associated mutation and terminal/event
audit in one transaction. Better Auth and email-provider calls cannot share a
database transaction. Those paths record the start before the call, preserve an
ambiguous outcome on call uncertainty, and return an explicit incomplete-command
warning if the provider operation succeeded but its terminal audit append did
not. Operators must review current state before retrying an ambiguous command.

## Privacy and interpretation

Command context may contain the authenticated administrator user and session
references, first trusted-proxy-reported source address, and a bounded user-agent
string. These are supporting observations, not independent proof of a person,
device, location, or MFA. Reverse-proxy trust configuration remains part of the
deployment boundary.

Metadata must be a bounded JSON object. Application validation rejects secret,
credential, authorization, cookie, password, token, private-key, message-body,
and content-like field names; oversized strings, lists, nesting, and unsafe
numbers also fail. Audit events do not retain provider tokens, invitation
tokens, password values, credentials, or email bodies.

The internal console shows chain status, aggregate incomplete/ambiguous state,
and the latest 50 events. Detailed request context is collapsed by default. No
public API or health response contains these values.

## Independent operations

`npm run assurance:gateway-operations` reads the gateway database through the
protected bootstrap settings, verifies exact migration names and checksums,
recomputes the full administrator chain, and measures incomplete-command age.
Its `vasi-gateway-operational-readiness/v1` output contains only release,
migration, event-count/sequence, integrity, command-count/age, and query-latency
aggregates. It contains no user, email, session, request, address, user-agent,
metadata, or hash value.

The default policy fails on any migration or chain/head mismatch, a database
read over 2,000 ms, or an incomplete command older than 300 seconds. Recent
incomplete or ambiguous commands remain warnings. The packaged gateway service
and persistent timer execute this probe every five minutes after an initial
three-minute delay. Alert transport, retention, escalation, and named response
ownership remain installation decisions.

## Migration, rollback, and assurance

Apply the gateway migration before starting VASI 0.34.0. The trigger supplies
new fields when a 0.33.0 INSERT omits them, so a short rollback can continue to
append structurally valid legacy `event` rows after migration `0007`; it does
not gain the 0.34.0 start/terminal command guarantees. Do not reverse the
migration or remove the immutability triggers during rollback.

Release assurance covers verifier tampering cases, metadata bounds, exact
migration checksums, internal scheduler packaging, and aggregate-output privacy.
The disposable PostgreSQL conformance proof must also cover legacy backfill,
concurrent append serialization, old insert compatibility, deleted-user history,
duplicate terminal rejection, context constraints, update/delete/truncate
denial, and chain-head substitution detection.

This design detects changes within the retained database but does not make a
database owner or host administrator untrusted: such an actor can replace code,
drop controls, or restore an older matched database. External transparency
anchoring, WORM custody, independent timestamping, and signed operational
attestations remain future/customer trust-profile choices.
