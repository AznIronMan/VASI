# Public ingress boundary

Status: implemented in VASI 0.39.0, continuously assured since VASI 0.40.0,
and application-protocol hardened in VASI 0.43.0.

## Decision

The public reverse proxy is a security boundary, not an unreviewed transport
detail. V·Sign is the only public application origin. A retired or historical
engine hostname either has no DNS record or terminates in a content-free 404
server; it never has a `proxy_pass`, service credentials, application cookies,
or a route to private ingress.

VASI supplies a canonical Nginx reference renderer, an effective-configuration
auditor, and a black-box live probe. Nginx is the first supported edge profile,
not an application dependency: an installation can use another proxy only if
it implements and independently proves the same contract.

```mermaid
flowchart LR
  client["Untrusted public client"] --> edge["Bounded public edge"]
  edge -->|"replacement forwarding metadata"| gateway["V·Sign gateway"]
  gateway -->|"mTLS and signed actor assertion"| ingress["Private ingress"]
  retired["Retired engine hostname"] --> deny["Content-free 404"]
  deny -. "no proxy path" .-> ingress
```

## Required edge behavior

The canonical Nginx profile enforces:

- one exact HTTP redirect server that names the configured canonical V·Sign
  host rather than request-derived host state, plus one exact HTTPS application
  server for that hostname;
- a 65,536-byte request-body ceiling, bounded body/header read times, bounded
  header buffers, keepalive and downstream send limits;
- per-client general and authentication request zones plus a concurrent
  connection ceiling, with generic no-store 429 responses and `Retry-After`;
- five-second connect and 30-second upstream read/send timeouts, request and
  response buffering, socket keepalive, and no automatic upstream retry;
- direct proxy directives rather than an opaque shared include;
- exact `Host`, scheme, port, and forwarding metadata; `Forwarded`, Upgrade,
  Connection, and every client-supplied forwarding chain are removed or
  replaced; and
- server-version concealment, TLS 1.2/1.3, disabled session tickets, and a
  bounded dedicated TLS session cache.

Before rendering, the gateway separately allows only GET and HEAD for page,
download, and static-resource routes. POST, PUT, PATCH, DELETE, OPTIONS, and
other methods receive an empty no-store 405 with `Allow: GET, HEAD` and no
cookie or redirect. Explicit `/api` route handlers remain responsible for
their individually reviewed methods, body parsers, origin/session checks, and
authorization. This avoids method confusion without weakening or silently
intercepting state-changing API behavior.

The general rate is intentionally compatible with the release health/brand
load gate. Authentication receives its own lower per-client rate. These are
edge-abuse bounds, not tenant capacity promises or a substitute for upstream
volumetric denial-of-service protection. Installations must measure and approve
their own pilot thresholds.

## Canonical rendering

`scripts/public-ingress-config.mjs` renders only validated hostnames, a fixed
upstream identifier, a bounded host-and-port target, and safe absolute
certificate paths. It accepts no environment file and no certificate or
credential bytes. The sanitized example is
`deployment/nginx/vasi-public.conf.example`; source assurance requires it to be
byte-for-byte canonical and audit-clean.

For a fresh deployment, omit every retired-host argument and remove the former
DNS record. During controlled retirement, supply the hostname and its existing
public certificate paths so both HTTP and HTTPS terminate locally with 404.
Keeping the denial server is safer than allowing a shared default virtual host
to route the name elsewhere.

For a shared ingress, the tracked overlay Dockerfile requires an explicitly
approved local base image and replaces only `vasi.conf`. A VASI release must
not rebuild unrelated virtual hosts or certificate material from a mutable
upstream image tag. The candidate records the base and resulting image IDs,
passes `nginx -t` plus the effective audit, and retains the exact prior image
and launch contract for rollback.

## Effective configuration audit

The audit consumes `nginx -T`, not only a source template. Its bounded parser
accepts at most 4 MiB, 100,000 tokens, and 64 nesting levels. It finds the exact
host servers and rejects:

- a missing or additional host server/location;
- any proxy on the retired hostname;
- `$proxy_add_x_forwarded_for` or another non-replacement forwarding rule;
- a missing/duplicated rate or connection zone;
- body, header, connection, TLS, buffering, retry, or timeout drift;
- opaque proxy includes or extra proxy headers; and
- an unreviewed or variable upstream target.

Run `nginx -t` first so Nginx proves syntax and directive-context semantics,
then pipe the same `nginx -T` output into the VASI audit with the installation's
public host, optional retired host, and gateway upstream name.

## Live black-box proof

`scripts/probe-public-ingress.mjs` verifies TLS 1.2 and TLS 1.3 handshakes, the
exact canonical HTTP-to-HTTPS redirect, public version/identity, the complete
browser security-header policy, concealed server/application versions, hostile
cross-origin preflight denial, empty no-store page-method denials, the exact
65,536-byte body boundary, and optional retired-host denial. The deliberate
rate exercise sends only fixed Gmail recommendation requests, which require no
DNS and do not consume the application's custom-domain ledger. It requires
both accepted and generic 429 responses and verifies `Retry-After` plus
`no-store`.

The rate exercise can briefly throttle sign-in from the probe's source address.
Run it only in an approved release window. Ordinary recurring checks should
omit that flag.

VASI's [recurring public-edge assurance](recurring-public-edge-assurance.md)
adds independent daily exact-image vulnerability/SBOM evidence and a
15-minute runtime check of container, rollback, listeners, effective Nginx,
public/retired behavior, and fresh image-matched evidence.

## Residual responsibility

The application cannot prove that an upstream load balancer, firewall, DNS
provider, or host administrator has not bypassed the audited edge. The gateway
origin must remain private and accept traffic only from approved edge sources.
Volumetric protection, alert delivery, TLS private-key custody, certificate
renewal, and customer-specific connection/capacity policy remain installation
controls.
