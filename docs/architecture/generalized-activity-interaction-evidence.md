# Generalized activity interaction evidence

Status: implemented in VASI 0.17.0.

## Purpose and assurance boundary

Every VASI workflow activity can retain the same privacy-bounded browser
presence evidence, whether the participant is reviewing terms, a PostgreSQL
document, an approval, a questionnaire, an electronic signature, or
provider-hosted media. This closes the gap between the server's open-to-submit
duration and what the browser can support about presentation, foreground
visibility, focus, coarse interaction, idle time, missing intervals, and
departure.

This evidence is supporting context. It does not prove attention,
comprehension, physical identity, freedom from coercion, exclusive control of a
device, or legal enforceability. Server timestamps, authenticated state
transitions, exact responses, immutable content bindings, and integrity seals
remain separate first-party facts.

## Collection contract

The browser accepts and emits only these fixed event types:

- `presented`;
- `visible` and `hidden`;
- `focus` and `blur`;
- `heartbeat`;
- `interaction`; and
- `disconnect`.

Each event contains only a random event ID, increasing sequence, bounded
browser-monotonic milliseconds, canonical client timestamp, and fixed type.
Each batch additionally identifies the opaque activity, interaction, telemetry
session, request handle, and random idempotency key required for authorization
and replay defense.

The activity card records a coarse `interaction` occurrence at most once every
five seconds when pointer, keyboard, or form-change activity bubbles through
the card. VASI does not retain the key pressed, text entered, selected value,
pointer coordinates, pointer path, element selector, clipboard contents,
plugin inventory, installed fonts, canvas output, hardware identifiers, or an
invasive device fingerprint. The electronic-signature activity separately
records the participant's intentionally submitted signature response under its
published activity contract; that response is not copied into presence
telemetry.

The browser starts a new opaque telemetry session for each page lifetime or
recovery after a failed submission. It uses an intersection threshold,
document visibility, window focus, periodic heartbeat, and page-departure
signal. Synchronization is best effort and never prevents a participant from
submitting a response. Missing evidence stays missing and produces a limitation
instead of being inferred.

## Authorization, replay, and bounds

`POST /v1/participant/interaction-events` is available only through the
authenticated V·Sign gateway and private ingress. The engine binds all of the
following before accepting a batch:

- the opaque handle digest and intended verified email;
- the stable participant principal when already bound;
- the assignment, request, and currently available activity;
- the open engine interaction session and actor principal; and
- request schedule, expiration, revocation, and completion state.

An unknown participant receives the same not-found result as an unknown
record. Batches accept 1–100 events. The default activity ceiling is 20,000
events, with an installation maximum of 100,000. Event IDs and sequences are
unique within an activity telemetry session; sequence and monotonic time must
increase within and across batches.

The engine hashes the normalized batch without the opaque request handle. A
repeat of the same batch ID and exact hash is an idempotent success. Reusing
that ID with another participant, activity, interaction, session, or body is
denied. Accepted batch metadata is also appended to the assignment evidence
chain with the authenticated actor, payload hash, summary revision, and summary
hash.

## Deterministic duration model

`vasi-activity-interaction-policy/v1` defines three installation bounds:

- heartbeat interval: 10 seconds by default, accepted range 2–60;
- idle threshold: 60 seconds by default, from the heartbeat interval through
  900; and
- maximum credited gap: 20 seconds by default, from the heartbeat interval
  through 120.

`vasi-activity-interaction-summary/v1` groups events by telemetry session and
uses only browser-monotonic deltas. An interval receives open-time credit only
after `presented` and before `disconnect`. Foreground-visible credit additionally
requires both visible and focused state. Engaged credit additionally requires
a prior coarse interaction no older than the idle threshold. Foreground time
without recent interaction is reported as idle foreground time. Open time
without both visibility and focus is reported as background or hidden time.

An interval longer than the maximum credited gap receives no duration credit
and is reported in full as an uncredited gap. Sessions that lack `disconnect`
remain incomplete. Overlapping or resumed sessions remain separate; VASI does
not invent continuity between them.

Medium confidence requires presentation, heartbeat, visibility, focus, no
oversized gaps, and a recorded disconnect for every session. Every other result
is low confidence. Even medium confidence remains browser-reported supporting
evidence and retains the standard attention, identity, coercion, and telemetry
limitations.

## PostgreSQL evidence and manifest binding

Engine migration `0010_engine_activity_interaction` adds three authoritative
tables:

- immutable accepted batch envelopes;
- immutable normalized raw events; and
- immutable deterministic summary revisions.

Rows are tenant/request/assignment/activity/interaction bound and cascade only
through the existing authenticated retention-purge transaction. Ordinary
updates or deletes fail at PostgreSQL triggers. Runtime containers remain
read-only and create no authoritative telemetry files.

The version 5 evidence manifest includes every batch envelope, raw event, and
summary revision. The mandatory VASI integrity seal therefore covers the
complete generalized activity record along with the event chain, workflow,
content fingerprints, responses, identity provenance, and timestamps.

The offline verifier independently checks event shape and order, duplicate
identities, batch membership, event count, normalized batch hash, authenticated
chain receipt, every summary hash, summary-chain binding, and a fresh
calculation of each activity's latest summary. A changed raw monotonic value,
batch envelope, summary, chain event, manifest, or seal fails verification.

## Reports, transparency, and lifecycle

Participant and plain-language reports expose only the latest per-activity
open, foreground-visible, engaged, idle-foreground, background/gap, and
confidence result with an explicit browser-reported label. Technical and
structured reports retain the complete sealed batches, events, revisions, and
calculation policy. Report generation remains deterministic and offline.

An approved participant data export always includes summary revisions and,
when the reviewing organization approves technical telemetry, includes batch
envelopes and raw events. Controlled retention purge removes all generalized
interaction source rows together with the assignment while preserving the
existing privacy-minimized signed purge tombstone and lifecycle chain.

## Runtime settings and verification

- `ENGINE_ACTIVITY_HEARTBEAT_SECONDS` (default `10`);
- `ENGINE_ACTIVITY_IDLE_SECONDS` (default `60`);
- `ENGINE_ACTIVITY_MAX_CREDITED_GAP_SECONDS` (default `20`); and
- `ENGINE_ACTIVITY_MAX_EVENTS_PER_ACTIVITY` (default `20000`).

The dedicated interaction probe verifies participant isolation, strict field
privacy, deterministic duration, idempotent replay, changed replay denial,
out-of-order denial, resumed sessions, immutable summary revisions, manifest
version 5 binding, and offline tamper rejection. Lifecycle conformance also
proves reviewed technical export and controlled purge of these new rows.

Deployment-specific privacy/legal owners must still approve the notice,
purpose, lawful basis, retention schedule, subject-access treatment, and any
jurisdiction-specific use of browser evidence. Independent security and manual
accessibility review remain external assurance gates.

VASI 0.18.0 advances completed workflow records to manifest version 6 by adding
separately bounded participant browser/device context. The version 5 interaction
batch/event/summary structure and its verifier calculations remain unchanged
inside that newer manifest.
