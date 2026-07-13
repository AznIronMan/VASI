# Edge Route And Exposure Policy

This document is the public-safe ingress contract for the pinned Documenso
`v2.14.0` baseline used by VASI. Examples use reserved names. Private host,
address, port, and certificate mappings remain outside git.

## Canonical Origin

The only canonical browser and email origin is the public VASI edge, represented
here as `https://sign.example.com`. `NEXT_PUBLIC_WEBAPP_URL`, WebAuthn origin and
relying-party values, redirects, email links, QR links, Open Graph metadata, and
cookie scope must all resolve to that origin.

The application origin, represented as
`https://origin.internal.example.test`, is not a browser destination. It is
reachable only from the edge and approved private management sources.
`NEXT_PRIVATE_INTERNAL_WEBAPP_URL` uses that private origin for server-to-server
jobs, PDF rendering, and font access.

The reserved fallback public hostname is maintenance-only. It must not proxy to
the VASI application, issue VASI application cookies, redirect to the private
origin, or become a second unrestricted entrance. Enabling it requires a new
reviewed route-policy change.

## Inventory Basis

This policy was checked against all 143 entries in the final React Router
server manifest produced from `apps/remix/app/routes/`. Pathless layouts and
index routes account for duplicate effective paths. Separate server mounts were
inventoried from `apps/remix/server/router.ts`, the auth route package, file and
download handlers, TRPC router, local/BullMQ job handlers, and the two
HTML-to-PDF routes. A future upstream merge must regenerate both inventories;
reviewing page filenames alone is insufficient.

## Policy Classes

| Class | Meaning |
| --- | --- |
| Public asset | Anonymous `GET`/`HEAD`; no application data mutation |
| Token public | Anonymous edge access; the application must validate the opaque recipient, direct-template, share, or recovery token |
| Public auth | Narrow authentication action needed by a token recipient; application CSRF, credential, and rate-limit checks still apply |
| Staff | CNB edge authentication **and** the normal VASI application session/authorization are required |
| Service | Non-browser access with an approved API token, signature, mTLS identity, or private source restriction |
| Internal | Private origin or management network only; never routed from the WAN |
| Blocked | Return a local edge `404` or `405`; do not forward |

An application `401` or `403` never changes the edge policy. In particular, a
valid VASI session does not replace CNB edge authentication for a staff route.

## Path Normalization

The edge must evaluate the URL-decoded path after rejecting invalid encoding,
NUL bytes, backslashes, dot segments, repeated slash ambiguity, and path
parameters. It must not use a client-controlled rewrite header as the policy
input.

React Router may append one terminal `.data` suffix for loader navigation. The
edge removes exactly one terminal `.data` for policy matching, applies the same
policy as the corresponding page route, and forwards the original valid path.
Query strings never select a less restrictive policy.

## Public Browser Assets

Allow anonymous `GET` and `HEAD` only for:

- `/assets/**` and `/__manifest*` for hashed React Router client bundles;
- `/fonts/**` and `/static/**`;
- `/site.webmanifest`, `/robots.txt`, `/opengraph-image.jpg`, and
  `/.well-known/security.txt`;
- `/favicon.ico`, `/favicon-*.png`, `/apple-touch-icon.png`, and
  `/android-chrome-*.png`.

Do not attach staff identity headers to cached assets. Hashed `/assets/**`
responses may use long immutable caching. Other public files must revalidate.

## Human Page Routes

### Token-public signing and verification

These exact page patterns bypass the staff portal and rely on the application
token and configured recipient authentication:

- `/sign/:token`
- `/sign/:token/complete`
- `/sign/:token/expired`
- `/sign/:token/rejected`
- `/sign/:token/waiting`
- `/d/:token`
- `/report/:token`
- `/share/:slug`
- `/share/:slug/opengraph`
- `/articles/signature-disclosure`

`:token` and `:slug` each represent one non-empty path segment. The edge must
not log their values, place them in metrics labels, or include them in error
pages. `/share/:slug` is required for the QR verification link printed in a
completed document.

`/p/:url` is a deliberately public profile feature, but it is disabled at the
edge for the initial VASI profile. It may move to token-public only after a
privacy review and an explicit product decision.

### Staff pages

Require CNB edge authentication for:

- `/`, `/dashboard`, and `/inbox`;
- `/admin` and `/admin/**`;
- `/settings` and `/settings/**`;
- `/t/:teamUrl` and `/t/:teamUrl/**`;
- `/o/:orgUrl` and `/o/:orgUrl/**`;
- `/signin`, `/forgot-password`, `/reset-password`,
  `/reset-password/:token`, `/check-email`, `/verify-email`,
  `/verify-email/:token`, `/team/verify/email/:token`, and
  `/unverified-account`;
- `/organisation/invite/:token` and `/organisation/decline/:token`.

The token in a staff onboarding or recovery URL does not replace the CNB edge
identity. The VASI application continues to validate its own token and session.

### Blocked pages

Block the following in the supported Community Edition production profile:

- `/signup`, because open signup is disabled;
- `/o/:orgUrl/signin` and `/organisation/sso/confirmation/:token`, because the
  upstream Organisation Authentication Portal is enterprise-gated and not the
  CNB edge portal;
- `/embed` and `/embed/**`, including the playground and authoring versions;
- `/p/:url`, pending the public-profile decision;
- `/ingest/**`, because production telemetry is disabled;
- any other page path not listed above.

## Browser And File APIs

### Token-public API routes

Allow `GET`/`HEAD` only for:

- `/api/avatar/:id`
- `/api/branding/logo/team/:teamId`
- `/api/branding/logo/organisation/:orgId`
- `/api/files/token/:token/envelopeItem/:envelopeItemId`
- `/api/files/token/:token/envelopeItem/:envelopeItemId/download`
- `/api/files/token/:token/envelopeItem/:envelopeItemId/download/:version`
- `/api/files/token/:token/envelope/:envelopeId/envelopeItem/:envelopeItemId/dataId/:documentDataId/:version/item.pdf`

The application validates the file token against the requested envelope and
item. The edge must not convert a `404` into an authentication redirect because
that would create a token oracle.

Allow same-origin `POST` only for `/api/theme` and `/api/locale`. These are
small cookie/preferences actions used on both staff and recipient pages.

### Staff file routes

Require CNB edge authentication for:

- `POST /api/files/upload-pdf`;
- `POST /api/files/presigned-post-url`;
- `GET /api/files/envelope/:envelopeId/envelopeItem/:envelopeItemId`;
- `GET /api/files/envelope/:envelopeId/envelopeItem/:envelopeItemId/download`;
- `GET /api/files/envelope/:envelopeId/envelopeItem/:envelopeItemId/download/:version`;
- `GET /api/files/envelope/:envelopeId/envelopeItem/:envelopeItemId/dataId/:documentDataId/:version/item.pdf`.
- `GET /api/limits`.

The application session or an application-issued embedding presign token still
performs the object authorization. The edge portal is an additional staff
boundary, not a substitute for object-level checks.

## Authentication API

Recipient account authentication can be required by a sender. The following
small subset is public-auth so a recipient can satisfy that requirement without
a CNB staff account:

- `GET /api/auth/csrf`
- `GET /api/auth/session`
- `GET /api/auth/session-json`
- `POST /api/auth/email-password/authorize`
- `POST /api/auth/passkey/authorize`

The password authorize request already carries optional TOTP or backup-code
proof. These routes retain the application's CSRF, allowed-origin, credential,
disabled-user, CAPTCHA (when configured), and database rate-limit checks.

All other `/api/auth/**` routes are staff routes for the initial profile,
including signup, password lifecycle, account linking, session revocation,
OAuth/OIDC authorization and callbacks, passkey management, two-factor setup,
and sign-out. Disabled providers remain disabled even behind the staff portal.

## TRPC Procedure Policy

TRPC uses `/api/trpc/:procedures` and may batch comma-separated procedure names
in the final path segment. The edge must URL-decode and split the procedure
segment, reject empty/duplicate/unknown names, and apply one policy to every
member. A mixed public/staff batch is blocked. The query-string `batch` flag is
not proof that a batch is safe.

The exact public recipient procedure allowlist is:

- `auth.passkey.createAuthenticationOptions`
- `auth.passkey.find`
- `document.accessAuth.request2FAEmail`
- `envelope.attachment.find`
- `envelope.field.sign`
- `envelope.recipient.report`
- `envelope.signingStatus`
- `field.removeSignedFieldWithToken`
- `field.signFieldWithToken`
- `recipient.completeDocumentWithToken`
- `recipient.rejectDocumentWithToken`
- `template.createDocumentFromDirectTemplate`

Every other TRPC procedure requires CNB edge authentication. The
`enterprise.csc.signEnvelope` procedure and all other enterprise procedures are
blocked in the supported production profile even if a client references them.

If the selected proxy cannot parse TRPC paths and enforce the whole-batch rule,
the deployment must add an origin middleware with a cryptographically protected
staff assertion or disable batching for the public recipient client. It is not
acceptable to expose all of `/api/trpc/**` merely because the application has
its own procedure authorization.

## REST, Integration, And Internal APIs

The initial profile has no public machine API. Block WAN access to:

- `/api/v1/**`, `/api/v2/**`, and `/api/v2-beta/**`, including OpenAPI files;
- `/api/ai/**`;
- `/api/csc/**`;
- `/api/stripe/webhook`;
- `/api/certificate-status`.

A later integration may expose an exact REST route through a service policy
using source restriction or mTLS plus the application API token. It must not
open an entire API version by default.

The following are internal or service-only and must never be routed from the
WAN:

- `/api/health`;
- `/api/jobs/**`, including the queue board;
- `/api/webhook/trigger`;
- `/__htmltopdf/audit-log` and `/__htmltopdf/certificate`.

Local jobs use the private application URL and signed job headers. HTML-to-PDF
routes use encrypted identifiers but remain internal. Health data belongs on a
private probe; the public edge may expose its own content-free `/healthz` that
does not proxy to the application.

## Method, Origin, And Content Rules

- Return `405` locally for a known path with an unlisted method.
- Require `Origin: https://sign.example.com` for public state-changing browser
  requests. Reject a different origin; do not rely on CORS as authorization.
- Reject request bodies on `GET` and `HEAD`.
- Default request-body limit: 2 MiB.
- PDF upload limit: the configured application limit plus at most 2 MiB of
  multipart overhead. With the default 50 MiB application limit, the edge limit
  is 52 MiB.
- Normal proxy connect timeout: 5 seconds. Normal response-header/read timeout:
  60 seconds. Upload and streamed download timeout: 300 seconds.
- Stream uploads and downloads where supported; do not buffer sensitive PDFs
  to an unprotected edge filesystem.
- Disable request and response body logging. Redact `Authorization`, `Cookie`,
  `Set-Cookie`, recipient/direct/share tokens, auth codes, and query strings.

The edge should add coarse abuse limits without replacing the application's
database-backed limits: public auth 20 requests per minute per verified client
IP, token pages/files 120 per minute, and public TRPC 120 per minute. Use a
small burst allowance and return `429` without reflecting token values.

## Forwarded Headers And Cookies

The outer TLS ingress and the CNB edge form a fixed trusted chain. Each hop
accepts forwarding metadata only from its known upstream source. Before sending
to the application origin, the edge must remove client-supplied forwarding and
vendor-IP headers, then set one canonical set:

- `Host: sign.example.com`
- `X-Forwarded-Host: sign.example.com`
- `X-Forwarded-Proto: https`
- `X-Forwarded-Port: 443`
- `X-Forwarded-For: <verified client address>`
- `X-Real-IP: <verified client address>`

Remove `Forwarded`, `X-Client-IP`, `CF-Connecting-IP`, and `True-Client-IP`
unless the outer ingress has explicitly verified and normalized them. This is
required because the pinned application's IP extractor prefers forwarding
headers and does not identify trusted proxies itself.

Application cookies remain host-only for the canonical edge host, `Secure`,
`HttpOnly` where applicable, and at least `SameSite=Lax`. Reject or alert on a
`Set-Cookie` domain naming an internal or fallback host. Rewrite an accidental
internal `Location` response to the canonical edge only as containment, log the
violation without its query string, and treat it as a deployment defect.

## Network And Failure Behavior

- The origin binds to a private interface and firewall rules accept application
  traffic only from the edge plus approved management probes.
- PostgreSQL, document storage, job handlers, signing material, and HTML-to-PDF
  routes have no WAN listener.
- The edge uses verified TLS or mTLS to the origin. Certificate-name and CA
  verification are mandatory.
- Unknown, malformed, blocked, or wrong-method requests terminate at the edge.
  Do not send them to the application and do not redirect them to staff login.
- Origin failure returns a generic edge `502`/`503` with no private hostname,
  upstream body, stack trace, or retrying non-idempotent request.
- WebSocket upgrade requests are blocked. The pinned supported flows require
  ordinary HTTP and streaming responses, not WebSockets.

## Change Control And Verification

Rebuild the route inventory after every upstream update. A new route is blocked
until classified. Before production cutover, test at least:

1. staff pages and non-public TRPC procedures fail without the CNB edge identity;
2. a synthetic external recipient can view, authenticate, sign, complete, and
   download through only the token-public paths;
3. mixed/unknown TRPC batches, blocked integrations, internal routes, wrong
   methods, malformed paths, and the fallback hostname fail at the edge;
4. generated mail, redirects, cookies, passkey origin, QR links, and metadata
   contain only the canonical public origin;
5. a spoofed forwarding header cannot alter the audit client address; and
6. the private origin is unreachable from an external network.
