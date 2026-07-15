# Pilot readiness dossier

VASI 0.45.0 provides a portable, administrator-only snapshot for accountable
pilot review. It converts the product's existing installation profile, tenant
profile, admission gates, integration bindings, capacity counters, and latest
production-stop record into two representations:

- machine-readable JSON for review tools and LLM-assisted analysis; and
- a printable, script-free HTML report for technical and non-technical people.

Both representations carry the SHA-256 of the same canonical dossier object.
The export is a handoff artifact, not a new approval system. It does not certify
VASI, provide legal advice, establish evidence sufficiency, or replace an
independent reviewer.

## Boundary and authorization

The browser calls `POST /api/admin/product/tenant-readiness-exports` only on the
internal administrator origin. The route uses the same authenticated
administrator, canonical-host, origin, and mutation controls as other internal
configuration changes. It sends a short-lived actor assertion across the mTLS
private-ingress boundary to the unexposed engine action
`POST /v1/admin/tenant-readiness-exports`. The command accepts only one tenant
UUID and the explicit format `json` or `html`.

The engine requires the installation `admin` role before opening a database
connection. Owners, participants, public callers, and service identities other
than the private ingress cannot invoke the action. The gateway marks both
formats `no-store`, `nosniff`, attachment-only, referrer-free, and sandboxed.
HTML also contains a restrictive CSP meta policy, escaped text, no executable
script, and an inert copy of the exact dossier JSON.

## Repeatable snapshot

The engine opens one PostgreSQL transaction at repeatable-read isolation. That
transaction observes a consistent set of:

1. the exact running engine release and active installation profile revision;
2. the selected tenant identity, status, profile revision, retention profile,
   quota limits, and current quota use;
3. the active admission revision and every gate's bounded reviewer reference,
   evidence reference, evidence digest, state, and decision time;
4. active integration capability, adapter identity and version, status,
   revision, creation time, and configuration hash; and
5. the latest production-stop reason, accountable gate, effects, result,
   timestamp, and immutable event hash, when one exists.

The dossier derives approved and pending gate lists and reports VASI's current
technical admission state. `externalReviewRequired` is always true and the
classification is always `recorded_evidence_not_certification`.

The engine hashes canonical VASI JSON for the dossier, then appends a
`tenant.readiness.exported` event to the tenant's immutable configuration chain.
The event binds the dossier hash, requested format, admission hash/revision,
and installation and tenant profile hashes/revisions. Its actor and event hash
make the disclosure attributable without putting the operator identifier in
the portable file. The export wrapper returns that audit-event hash alongside
the dossier hash and capture time.

The dossier hash does not cover the wrapper's capture time, requested format,
or audit-event hash. Consequently, JSON and HTML created from unchanged
readiness facts retain the same dossier hash while each disclosure still has a
new immutable audit event. The hash detects changes to exported facts; it is
not a digital signature, trusted timestamp, certificate seal, or proof that a
referenced review was correct.

## Deliberate privacy boundary

The export includes enough state to verify which technical configuration and
approvals were presented to reviewers. It deliberately excludes:

- integration credentials, encrypted envelopes, credential fingerprints, and
  raw configuration;
- SMTP hosts, webhook URLs, scanner hosts, Microsoft tenant/client identifiers,
  sender addresses, and all allowlist values;
- installation and tenant support addresses or other personal contact data;
- production-stop command IDs, incident references, and operator identifiers;
  and
- participant, request, workflow, document, response, authentication, browser,
  network, and evidence-record content.

Only allowlist entry counts and configuration hashes are exported. A dossier
should still be handled as internal company information because it names the
tenant, exposes usage and quota facts, identifies enabled adapter types, and
contains bounded reviewer/evidence references.

## Verification and use

The JSON format is the authoritative portable representation. The HTML report
embeds the same dossier object as inert `application/json` data and prints its
expected hash. A verifier can parse that object, apply canonical VASI JSON, and
recompute SHA-256. To prove that VASI itself recorded the disclosure, an
authorized investigator must additionally compare the returned audit-event
hash with the tenant configuration chain inside the installation.

Use the dossier as the cover sheet for the gate owners listed in
[Assurance and pilot readiness](../assurance-and-pilot-readiness.md). The
referenced assessment packages remain separately controlled; do not place
credentials, narrative case notes, URLs, or approval documents into admission
reference fields merely to make the dossier self-contained.
