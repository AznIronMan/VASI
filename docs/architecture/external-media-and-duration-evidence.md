# External Media And Duration Evidence

Status: implemented in VASI 0.8.0.

VASI keeps authoritative non-media uploads in PostgreSQL. Images, audio,
video, presentations, and other externally hosted material instead use an
immutable VASI descriptor and a provider-capability adapter. VASI does not
copy, proxy, or claim possession of the provider's media bytes.

## Capability model

| Capability | Initial providers | Evidence VASI can support | Evidence VASI does not claim |
| --- | --- | --- | --- |
| Instrumented player | YouTube, Vimeo | Player readiness, play/pause/buffer/rate/seek/position/end events; bounded visible unique-playback calculation | Attention, comprehension, exact provider bytes without a supplied version, or uninterrupted playback during telemetry gaps |
| Version-aware preview | SharePoint/OneDrive with a supplied version/eTag/change token | Immutable item/version reference plus authorized frame presentation and visibility | In-frame playback, every page viewed, future link availability, or independent verification of tenant-supplied metadata |
| Generic embed | Google Drive and installation-allowlisted HTTPS origins | Authorized frame presentation, load/error signal when available, visibility, focus, interaction, and bounded open time | Playback, in-frame actions, exact viewed bytes, or successful provider authorization merely because a frame loaded |
| External link | Dropbox media and explicit external links | Authorized source reference, departure, return, and optional acknowledgement | Activity, playback, or duration inside the external provider |

Dropbox media deliberately uses the external-link capability because Dropbox's
Embedder documentation excludes audio and video. Provider capability is part
of the published workflow revision and cannot be upgraded by a browser event.

## Immutable descriptor

Publishing normalizes and binds a descriptor containing:

- provider, item ID, canonical source, constructed or approved embed URL, and
  media kind;
- adapter ID/version and capability class;
- title, optional owner/description/dimensions/duration, and access expectation;
- available provider version, eTag, cTag, modification time, or checksum;
- exact allowed origins, metadata provenance, and capability limitations; and
- a SHA-256 canonical descriptor fingerprint.

Raw iframe markup is never accepted. Known providers are restricted to their
documented HTTPS hosts and VASI constructs their player/preview URL. A generic
source and embed must use the same credential-free HTTPS origin, and that
origin must appear in `ENGINE_MEDIA_GENERIC_ORIGINS`. Published descriptors,
metadata snapshots, event batches, raw events, and calculation revisions are
append-only database records protected by immutable-table triggers.

Provider metadata is currently tenant-supplied and labeled
`tenant_supplied_unverified`. A supplied version token improves identification
of the reference but does not mean VASI possesses or hashed the external bytes.
Future Microsoft Graph or Google Drive metadata adapters can add separately
provenanced provider snapshots without changing the domain contract.

## Participant authorization and embed isolation

V·Sign first authenticates and email-verifies the participant, then the private
engine binds the opaque request handle to that principal. Every media event and
frame authorization revalidates the handle, principal, intended email, request
state, current activity, and immutable descriptor.

Generic and version-aware previews load through an authenticated same-origin
wrapper. The wrapper obtains the descriptor from the private engine rather
than accepting a URL from the browser, applies an exact-origin Content Security
Policy, uses a restricted iframe sandbox and permissions policy, and reports a
small versioned same-origin message. The participant page validates message
origin, window source, schema, activity ID, and item ID. The main application
CSP permits only the VASI wrapper and the supported YouTube/Vimeo players.
Camera, microphone, geolocation, and browsing-topics access remain disabled.

YouTube uses the documented IFrame Player API with V·Sign's exact `origin` and
the privacy-enhanced player host. Vimeo uses the documented Player SDK. Player
scripts are display adapters only; the private engine still validates event
shape, capability, identity, ordering, limits, and completion.

References:

- <https://developers.google.com/youtube/iframe_api_reference>
- <https://developer.vimeo.com/player/sdk/reference>
- <https://learn.microsoft.com/en-us/graph/api/resources/driveitem?view=graph-rest-1.0>
- <https://learn.microsoft.com/en-us/graph/api/driveitem-preview?view=graph-rest-1.0>
- <https://developers.google.com/workspace/drive/api/reference/rest/v3/files>
- <https://www.dropbox.com/developers/embedder>
- <https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe>

## Telemetry and idempotency

The browser creates a new opaque telemetry-session ID on each page lifetime and
monotonically sequences events within it. It batches no more than 100 events
with a stable batch ID. The engine enforces:

- authenticated assignment, activity, and interaction ownership;
- capability-specific event allowlists and strict bounded fields;
- strictly increasing sequence and monotonic time within and across batches;
- stable batch payload hashes, so an ID replay with different content fails;
- a configurable total event limit per activity; and
- atomic raw-event, calculation-revision, metadata, and evidence-chain writes.

The browser retries a failed batch under the same ID. A byte-equivalent replay
is idempotent; a changed replay or sequence reuse is rejected. Navigation sends
a bounded keepalive disconnect batch when the browser permits it. Missing
disconnect or provider events are represented as gaps, never filled in.

Recorded event classes include presentation, frame state, visibility,
focus/blur, bounded interaction, heartbeat, player state, position, seek,
provider error, external-link departure/return, accessibility alternative, and
disconnect. Provider or browser telemetry is supporting evidence and is never
the sole assertion that a human paid attention or understood content.
Provider SDK seconds and rates are normalized to integer milliseconds and
milli-rate values before persistence and canonical hashing; completion
percentages use integer basis points. No floating-point number enters the
canonical signed evidence format.

## Duration calculation

Each accepted batch creates a deterministic immutable summary revision. VASI
keeps separate values for:

- page open time;
- visible and focused time;
- interaction-bounded engaged time; and
- unique plausible visible playback positions.

Playback intervals are credited only while the player was playing, not
buffering, and the presentation was visible. Position advance must be plausible
for elapsed monotonic time and playback rate. Explicit seeks clear the current
sample; large advances, backward movement, over-limit gaps, hidden playback,
and missing telemetry receive no duration credit. Overlapping intervals across
reloads or resumed authenticated sessions are unioned, so replaying the same
seconds cannot increase unique duration.

Completion uses the immutable workflow threshold and minimum unique seconds.
Duration comes from the workflow descriptor when supplied, otherwise only from
consistent player-reported samples. Generic frames and external links can use
an explicit acknowledgement or accessibility alternative but can never satisfy
a playback requirement. Every summary reports its policy version, duration
source, confidence, gaps, seeks, provider errors, and limitations.

## Evidence and privacy

The version 4 sealed evidence manifest includes the immutable descriptor,
publish/issue/start/completion metadata snapshots, every accepted raw media
event with server receipt time, all calculation revisions and hashes, and the
completion-time summary bound to the participant response. The per-assignment
evidence chain also covers each accepted batch's payload hash and summary hash.

VASI does not collect provider cookies, account tokens, page content, browsing
history, camera/microphone data, or activity in unrelated tabs. The participant
is told that provider-hosted content may receive normal network, browser,
cookie, or account context. Reports must describe browser/player events as
available technical evidence, not proof of attention, comprehension, identity
beyond the authenticated V·Sign session, or a legal conclusion.

## Installation settings

- `ENGINE_MEDIA_GENERIC_ORIGINS`: comma- or whitespace-separated exact HTTPS
  origins approved for the generic adapter. Empty by default.
- `ENGINE_MEDIA_MAX_EVENTS_PER_ACTIVITY`: accepted raw-event ceiling, default
  `20000`, bounded from `100` to `100000`.

These values use the normal encrypted PostgreSQL runtime-settings system. No
provider credential, access token, or secret is embedded in a workflow.

## Verification

The media conformance probe proves known-provider normalization, wrong-user
denial, media-open binding, insufficient-playback rejection, seek and gap
exclusion, cross-session interval union, stable batch idempotency, changed
replay and sequence denial, generic-player-event rejection, acknowledgement
fallback, metadata phases, raw-event and summary inclusion, integrity sealing,
database immutability, and PostgreSQL dump/restore fingerprints.
