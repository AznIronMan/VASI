# Evidence reports, portable bundles, and verification

Status: implemented in VASI 0.9.0.

VASI 0.18.0 extends the sealed record to manifest version 6 with fixed,
privacy-bounded participant-context observations. Technical and structured
profiles retain those values; participant and plain-language profiles expose
only their presence, purposes, provenance class, and limitations.

VASI 0.22.0 extends the current sealed record to manifest version 7 with
privacy-bounded notification jobs and immutable adapter attempts available at
completion. Participant and plain-language reports omit internal job IDs and
failure codes. Every audience is told that provider acceptance does not prove
inbox delivery, receipt, reading, attention, or identity.

## Purpose and boundary

VASI turns a sealed transaction into deterministic evidence that a participant,
company representative, investigator, lawyer, or technical examiner can inspect
without requiring an LLM or a hosted VASI account. Reporting remains behind the
private engine. V·Sign authorizes the requester, asks the engine to open an
export, and streams verified chunks; browsers never receive an engine address,
service credential, database credential, or signing key.

The authoritative sealed event chain, manifests, report bytes, bundle bytes,
signing-key registry, and access ledger are stored in PostgreSQL. Uploaded
source documents included in a bundle are read from their authoritative
PostgreSQL chunks. VASI does not create an authoritative loose document or
report file on an application host.

## Deterministic reports

Every report traces to the source manifest fingerprint and lists every covered
event ID, sequence, event type, receive time, and event hash. The generator uses
only sealed record data and versioned templates; it does not use wall-clock time,
an LLM, or a nondeterministic external service. Reopening the same profile and
format for the same manifest reuses the same immutable PostgreSQL export.

The supported profiles are:

- `participant`: identity method, requester, outcomes, material times, event
  references, reduced notification state, latest browser-reported activity
  timing, and integrity
  information without forensic IP/user-agent or raw interaction-event detail;
- `nontechnical`: a plain-language chronology, requester and participant
  identity, outcomes, reduced notification state, latest activity timing,
  limitations, and integrity
  explanation;
- `technical`: the complete available sealed events, manifest, response and
  generalized activity/media detail, authentication/client context, seals, and
  verification data;
- `structured`: the sealed record without interpretive additions.

Reports are available as canonical JSON-derived JSON, UTF-8 text, and printable
self-contained HTML. Report wording states evidentiary limitations and does not
claim legal enforceability, attention, comprehension, or lack of coercion.

## Portable evidence bundle

The `vasi-evidence-bundle/v1` ZIP uses deterministic entry ordering, fixed ZIP
metadata, store-only entries, per-entry SHA-256 descriptors, and a canonical
bundle root hash. It includes:

- the complete sealed record, manifest, and JSON Lines event chain;
- all four report profiles in JSON, text, and HTML;
- exact authoritative PostgreSQL document-artifact revisions and an artifact
  index when the workflow bound documents;
- a bundle index and detached bundle seals; and
- offline-verification instructions.

The bundle is signed independently from the evidence manifest using the
`vasi-bundle-seal/v1` profile. A source-manifest fingerprint binds the bundle to
its sealed transaction. Export size and chunk size are bounded by engine
settings; the default complete bundle limit is 64 MiB.

## Offline and online verification

`npm run evidence:verify -- <bundle.zip>` verifies ZIP structure, CRC values,
every declared entry length and SHA-256 digest, absence of undeclared entries,
the bundle root, every bundle seal, the evidence event chain, manifest binding,
generalized activity batch hashes and latest summaries, strict notification
delivery fields/times/outcomes, every record seal, and regenerated report
bytes. It needs no private key, LLM,
network service, or database. `--json` produces a machine-readable result. A
sealed record JSON can be verified directly with the same command.

The public `/verify` page accepts only an exact 64-character manifest
fingerprint. The gateway applies same-origin enforcement and bounded per-client
rate limiting, creates a narrowly scoped short-lived verification assertion,
and returns no participant identity, responses, document content, tenant name,
or requester information. Known and unknown lookups are recorded in the
append-only access ledger.

## Signing keys and optional certificates

The required VASI seal provider uses a configured Ed25519 key and records each
public key in an immutable key registry. A new key ID registers a new active key
without invalidating historical records, whose public verification material is
embedded in their seals. Key status changes are modeled as append-only events.

An installation may additionally configure an X.509 private key and certificate
chain. VASI then adds a separate `vasi-certificate-seal/v1` signature to records
and bundles; it never represents that signature as the participant's signature.
Offline verification checks the leaf certificate, public/private key match,
payload digest, and signature. It intentionally does not claim chain trust,
revocation status, qualified-signature status, or trusted time. External KMS,
HSM, public trust-service, RFC 3161, revocation archival, and long-term
validation adapters remain replaceable higher-assurance profiles.

## Access evidence and controls

Owner record views, owner report/bundle exports, participant receipts,
participant report exports, and public fingerprint checks append access events.
Tenant `record.read` permission gates company exports. A participant may obtain
only the participant report for the completed assignment bound to the same
stable principal and verified email. Export chunk reads recheck authorization
and verify each stored chunk before returning it to V·Sign.

The participant report is not the broader participant-data-request workflow.
VASI 0.10.0 implements that separate workflow with organization-scoped review,
mandatory redaction policy, sealed bounded JSON delivery, audited access, and
automatic export-content expiry. Retention and legal holds remain independent
controls and can block destructive purge while a data request is active.
