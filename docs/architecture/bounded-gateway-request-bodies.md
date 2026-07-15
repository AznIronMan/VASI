# Bounded gateway request bodies

Status: implemented in VASI 0.36.0.

## Decision

VASI owns a byte limit before a gateway mutation route parses JSON or delegates
an authentication POST to Better Auth. The limit is 65,536 bytes for every
owned JSON API and the authentication catch-all. The private engine retains its
independent 65,536-byte JSON limit, so a proxy or gateway regression cannot
silently remove the final service boundary.

Document upload is intentionally separate. It streams directly into bounded
PostgreSQL chunks under the configured document maximum and never enters the
JSON parser.

## Enforcement

The gateway checks a syntactically valid `Content-Length` when present. A value
above the limit returns 413 before the body stream is inspected. Absence of the
header does not bypass the control: VASI reads the stream incrementally, counts
bytes rather than JavaScript characters, cancels it immediately after the
limit is crossed, and buffers no more than the accepted maximum.

When a declared length is present, the completed stream must have exactly that
length. A malformed, unsafe, truncated, extended, unreadable, or invalid-UTF-8
body receives the same generic 400 response. VASI-owned JSON routes additionally
require one JSON object; arrays, primitives, empty bodies, and malformed JSON
do not reach domain validation or the private engine. Overflow receives a
generic 413. Both responses are `no-store` and include `nosniff`; neither logs
or returns body data, parser detail, or transport detail.

Better Auth must also accept provider callbacks that use form-post rather than
JSON. VASI therefore applies the raw byte boundary first, rebuilds an accepted
request with the exact captured bytes and original non-length headers, removes
the caller-supplied `Content-Length`, and only then invokes the provider
handler. The authentication library remains responsible for endpoint-specific
content-type and schema validation.

## Authorization order

Internal administrator and participant mutation routes establish their normal
host, origin, session, and role boundary before reading an authorized body.
The public fingerprint verifier applies host, origin, and attempt controls
before parsing. The shared authentication catch-all applies its internal-admin
host restriction before reading a POST. These orderings avoid spending request
parsing capacity on a request already denied by a cheaper authorization check.

## Assurance and limits

Unit and route tests cover an exact-limit multi-chunk object, UTF-8 byte
expansion, declared oversize rejection before body access, streamed overflow,
length disagreement, malformed and non-object JSON, invalid UTF-8, transport
failure redaction, public-verifier pre-engine denial, and authentication
form-post preservation. Release assurance rejects direct `request.json()` use
in tracked gateway request-handling source.

This control bounds per-request application buffering; it is not complete
denial-of-service protection. A production reverse proxy must still enforce
approved connection, header, body, idle, and request timeouts and rate limits.
Customer-specific concurrency and sustained-load limits remain pilot admission
evidence.
