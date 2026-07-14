# Requester provenance and participant disclosure

Status: implemented in VASI 0.23.0.

## Purpose

Every VASI request identifies the accountable company user who issued it. That
identity must remain historically stable if the user's membership, roles,
status, or email record later changes. A participant must also understand who
is asking, why, the material deadlines and access policy, and what submitting
will record before taking an action.

## Immutable issuance snapshot

Migration `0014_engine_requester_provenance` adds one
`vasi-requester-snapshot/v1` object to each request. New requests require the
authenticated issuance actor's normalized email and stable V·Sign principal.
The snapshot records:

- schema and requesting-organization relationship;
- stable principal ID and issuance-time email; and
- explicit capture provenance.

The principal must equal the request's creator. PostgreSQL validates the
bounded object and rejects changes to either the creator or snapshot after
insert. Existing requests are backfilled first from their immutable scheduled
or issued evidence event, then from a matching membership if necessary. A
legacy-unavailable marker is retained rather than inventing an email when no
authoritative value exists.

The snapshot is independent of the notification sender mailbox. The requesting
user is the accountable company actor; a Graph or SMTP mailbox is only the
configured delivery transport identity.

## Participant disclosure

Before an activity form, the authenticated participant sees:

- requesting company and available requester email;
- purpose and activity instructions;
- due and expiration times; and
- whether original content remains available after completion.

The page explains that submission creates a tamper-evident authenticated action
record, that the participant receipt and history retain material facts, and
that a reviewed data export can be requested from the participant workspace.
This disclosure does not claim that authentication proves attention,
comprehension, intent, authority, freedom from coercion, or legal
enforceability.

## Evidence and portability

Manifest `vasi-evidence-manifest/v8` binds the requester snapshot alongside the
request, workflow, participant, outcomes, event chain, context, interaction,
notification, and seal evidence. The offline verifier requires the snapshot to
match the first immutable `request.scheduled` or `request.issued` actor. Human
reports use the manifest value and retain event fallback only for older record
versions.

Participant receipts, history, and approved data exports use the immutable
snapshot instead of joining the request to current membership state. Disabling
or removing a company user therefore does not rewrite historical sender
provenance. Public fingerprint verification continues to reveal no requester,
company, participant, or content information.

## Limits

VASI preserves the identity asserted by the authenticated V·Sign session at
issuance. It does not independently establish the person's employment,
authority, legal capacity, or the legal sufficiency of a notice. Installations
remain responsible for identity, legal-notice, consent, retention, and
jurisdiction-specific review.
