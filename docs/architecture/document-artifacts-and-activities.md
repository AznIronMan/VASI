# PostgreSQL document artifacts and electronic activities

Status: implemented in VASI 0.7.0.

## Decision

Authoritative uploaded non-media documents are stored as immutable metadata and
bounded ordered `bytea` chunks in the engine-owned PostgreSQL database. VASI
does not use persistent loose files or PostgreSQL large-object OIDs as the
authoritative store. Images, audio, and video are outside this store and use the
separately documented external-media model.

The default upload limit is 25 MiB and the default chunk size is 256 KiB. The
gateway reads the browser request incrementally, forwards one authenticated
chunk at a time, and never constructs the whole document in application memory.
The engine finalizer reads one ordered chunk at a time while calculating the
complete SHA-256 digest and inspection result.

## Artifact lifecycle

1. An authorized company owner, manager, or author creates a quarantined
   artifact with the expected length, exact media type, filename, role,
   retention profile, and optional source/replacement references.
2. Each chunk is inserted once at the next sequence number with its own length
   and SHA-256 digest. Out-of-order, duplicate, oversized, or excess data fails.
3. Finalization rereads the database chunks in order, verifies every chunk,
   confirms total length, calculates the complete digest, and runs bounded
   content inspection.
4. A passing artifact is atomically published. A failing or aborted artifact is
   finalized as rejected with its inspection result. Neither state can be
   changed in place.
5. Replacement creates another immutable revision in the same artifact family.
   A derived preview identifies its immutable source artifact.

Published/rejected metadata, all chunk rows, workflow bindings, artifact-access
events, and activity-response revisions have database immutability triggers.
Workflow publication resolves each `document_review` reference to the exact
artifact family, revision, role, filename, media type, byte length, chunk count,
inspection profile, and SHA-256 digest. The resolved binding is part of the
immutable workflow snapshot and its hash.

## Supported document inputs

The initial allowlist includes PDF; UTF-8 plain text, Markdown, CSV, JSON, and
XML; macro-free Office Open XML document/spreadsheet/presentation containers;
and OpenDocument text/spreadsheet/presentation containers. Executable, HTML,
image, audio, and video media types are rejected by this document path.

The built-in bounded inspector validates expected PDF/ZIP signatures, UTF-8 and
basic structured-text shape where applicable, rejects NUL-bearing text, and
detects the EICAR antivirus test marker even across chunk boundaries. Every
artifact stores the adapter/profile, result, and limitation statement. This is
not represented as comprehensive malware-signature coverage. A future
replaceable malware-scanner adapter may strengthen the profile without changing
the artifact or workflow contracts.

VASI does not currently perform automatic Office-to-PDF conversion. A trusted
adapter can publish a separately hashed `derived_preview` tied to the original;
it must not replace or mutate the source revision.

## Built-in activity contracts

All activity definitions use contract version 1, reject unknown fields, and
execute only VASI-owned reducers:

- terms with acknowledgement or yes/no;
- approval, disapproval, or decline;
- single-choice and bounded multiple-choice questions;
- bounded free-form answers;
- typed-name or normalized vector-stroke electronic signatures with exact
  consent language;
- PostgreSQL document presentation/download followed by explicit review
  acknowledgement; and
- deterministic single/multiple-choice questionnaires and tests with an
  immutable answer key, points, threshold, and server-calculated result.

Questionnaire answer keys and per-question scoring metadata are not returned in
the participant projection. Branching may use only declared outcomes such as
`approved`, a single-choice ID, `passed`, or `failed`, and may move only forward
or terminate. Tenant JavaScript or arbitrary expressions are never evaluated.

A typed or drawn electronic signature is a participant-asserted electronic act
bound to the exact statement, consent text, authenticated session, response,
event chain, and VASI integrity seal. It is not described as a participant
certificate signature unless a future workflow actually uses a
participant-controlled signing key.

## Response revisions and evidence

Participants can save a valid response without completing an activity. Each
save and final submission creates an immutable response revision with the exact
value, presented label, normalized outcome, deterministic result, interaction,
client context, and server timestamp. The final response references its
submitted revision. The sealed version 3 evidence manifest includes every
activity's response-revision history, exact workflow snapshot, artifact
bindings, score/result, and evidence-chain hashes.

A document-review submission is rejected until the authenticated participant
has used the authorized presentation/download route for that exact assignment,
activity, and artifact. VASI records that route access and states its limitation:
access does not by itself prove every page was read.

Owner and participant delivery streams one authorized chunk at a time through
V·Sign. Each gateway chunk is checked against its engine-supplied length and
digest before release. Responses use `no-store`, `nosniff`, restrictive
content-disposition, referrer, and sandbox headers. Post-completion document
access follows the immutable workflow revision's access policy. Access after
the completion seal is recorded in the separate append-only access ledger so it
does not silently invalidate the completed manifest.

## Conformance evidence

The disposable private-engine harness verifies multi-chunk publication,
out-of-order rejection, EICAR rejection, replacement revisions, owner and
participant byte-for-byte streaming, tenant/participant denial, document-open
gating, all rich reducers, multiple saved revisions, server scoring, answer-key
redaction, version 3 sealing, and database tamper triggers. It also performs a
PostgreSQL dump/restore, compares a fingerprint over restored artifact metadata
and bytes, confirms response revisions, and runs vacuum/analyze on the restored
chunk table.

The 25 MiB default remains deliberately bounded. Higher limits require fresh
database growth, WAL/replication, concurrency, backup-duration, restore, and
vacuum evidence for the target deployment.
