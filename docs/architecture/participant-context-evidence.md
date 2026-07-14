# Privacy-bounded participant context evidence

Status: implemented in VASI 0.18.0.

## Purpose and assurance boundary

VASI records a small, fixed browser/device context snapshot when a participant
is presented an activity and immediately before a save or submission. The
snapshot supplements server-observed request headers and the generalized
activity-presence record. VASI does not compute or claim a persistent device
fingerprint from these values, and it never treats them as proof of identity,
attention, comprehension, physical location, or freedom from coercion.

Every value is labeled `browser_reported`. It can be absent, reduced,
randomized, automated, changed, or spoofed. Missing values remain absent; the
client and engine do not infer replacements.

## Fixed collection contract

`vasi-participant-context/v1` permits only these bounded groups:

| Group | Accepted values |
| --- | --- |
| Browser | preferred language, up to eight reported languages, IANA-style time-zone text, online state |
| Display | viewport, screen and available-screen dimensions; pixel ratio; color and pixel depth |
| Input | reported maximum touch points |
| Capabilities | cookie enablement, local/session storage availability, and the browser's PDF-viewer capability flag when exposed |
| Preferences | reduced motion, color scheme, contrast, and forced-colors media preferences |
| Connection | standardized effective type plus bounded downlink, round-trip-time, and data-saver values when the browser exposes them |

The engine rejects unknown keys, invalid enums, repeated or excessive arrays,
non-canonical timestamps, impossible numeric bounds, empty context groups, and
more than the installation-configured snapshot count. The collection policy,
allowed groups, exclusions, reliability class, and limitations are immutable
manifest data rather than client-authored claims.

VASI deliberately excludes:

- plugin or font enumeration;
- canvas, WebGL, audio, GPU, or other fingerprint hashes;
- precise geolocation;
- hardware, advertising, or persistent device identifiers;
- camera, microphone, biometric, or hidden media capture;
- keystrokes, input contents, pointer coordinates, or detailed interaction
  targets; and
- credentials, OAuth artifacts, tokens, or reusable session secrets.

User-Agent, low-entropy Client Hints, accepted language, and validated client IP
remain separately labeled server-observed gateway request context. The browser
snapshot does not duplicate or strengthen those values.

## Authorization, replay, and storage

The public browser sends a single snapshot at a time through the authenticated
V·Sign gateway. The private engine binds it to all of the following before
writing anything:

- opaque participant handle and intended email;
- participant principal and V·Sign gateway session;
- tenant, request, assignment, current activity instance, and interaction;
- a per-page context session, increasing sequence, monotonic time, purpose, and
  snapshot ID; and
- the exact canonical payload hash.

The first snapshot in a context session must be sequence 1 with purpose
`presentation`. Later `save` and `submission` snapshots must increase both
sequence and monotonic time. An exact ID/payload replay is idempotent; a changed
replay, duplicate sequence, wrong participant, stale activity, completed
interaction, expired/revoked assignment, or installation-limit overflow fails
closed.

Migration `0011_engine_participant_context` stores each normalized snapshot,
its server-observed request context, actor/session binding, payload hash, and
receipt time in `participant_context_snapshot`. Rows are immutable. They can be
deleted only by the existing tombstone-backed retention purge after legal-hold
and participant-data-request checks succeed.

## Sealing, verification, and portability

Every accepted snapshot appends `participant.context.recorded` to the
assignment evidence chain. Manifest `vasi-evidence-manifest/v6` contains the
complete policy and normalized snapshot rows. The offline verifier:

1. validates the fixed schema and policy;
2. rejects duplicate IDs and sequence identities;
3. verifies presentation-first and monotonic ordering per activity/context
   session;
4. recomputes every canonical payload hash;
5. checks the activity, interaction, actor, gateway session, request-context,
   purpose, sequence, and chain-event binding; and
6. rejects missing, orphaned, count-mismatched, over-limit, or altered rows.

Technical and structured reports retain the complete sealed context. Participant
and plain-language reports disclose the snapshot count, purposes, reliability,
and limits without placing the forensic values in an ordinary receipt. A
reviewed participant data request can include eligible complete context rows and
their provenance. Encrypted tenant archives now include participant-context and
all generalized activity-interaction tables, correcting the prior transfer
coverage gap while retaining cross-installation verification.

The browser recorder is best-effort. It retries queued observations when
possible, uses a bounded request timeout, and never prevents a save or response
when context collection or transport is unavailable.

## Runtime bound

- `ENGINE_PARTICIPANT_CONTEXT_MAX_SNAPSHOTS_PER_ACTIVITY` defaults to `16` and
  accepts `2` through `64`.

Changing the bound affects future collection capacity. Each sealed record keeps
the exact policy that governed its own snapshots.

## Assurance limits

The context can help an investigator understand the reported browser conditions
surrounding a recorded action. It cannot establish who physically controlled a
device, whether a VPN or automation was used, whether the content was read, or
whether a reported setting was truthful. Deployment privacy/legal owners must
approve the notice, purpose, lawful basis, retention, subject-access treatment,
and jurisdiction-specific use before a production pilot. Independent security
and manual accessibility review remain separate gates.
