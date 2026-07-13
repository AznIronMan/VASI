# Deployment Direction

This is public-safe deployment guidance. The intended production host and
operator access details are kept in ignored `.private/` notes.

## Current Status

VASI contains the pinned Documenso `v2.14.0` application source and a generic
[private-origin Compose template](../../ops/deploy/origin/README.md). The
upstream development/production examples are not the VASI deployment contract:
the upstream production example uses an embedded database, floating image tag,
and direct port exposure. The VASI template uses the verified
[production configuration contract](configuration.md), protected secret files,
an external PostgreSQL service, and a private-bind TLS listener. The separate
public edge is implemented as a pinned OAuth2 Proxy plus a deny-by-default
gateway, but it is not connected to production OIDC credentials or the live
listener yet.

Private production prerequisites have been reserved and verified: PostgreSQL,
administrator inheritance, encrypted internal service TLS, public and internal
DNS/TLS ingress, container ports, and backup coverage. The current endpoints are
maintenance placeholders, not a deployed signing application. Exact hostnames,
addresses, ports, credentials, certificate material, and replacement steps stay
in ignored `.private/` notes.

## Required Services

The current Documenso self-hosting requirements call for:

- PostgreSQL 14 or newer.
- SMTP or a supported email delivery provider.
- A reverse proxy for SSL termination and routing.
- An X.509 `.p12` signing certificate; without it, document signing fails.

Persistent document storage, protected application/encryption secrets, backups,
and monitoring are also required VASI production concerns. RFC 3161 timestamping
is optional and must be deliberately configured and tested if selected.

## Intended Container Shape

- Separate edge and origin Compose projects for each VASI environment.
- Public traffic reaches only the TLS edge/auth gateway.
- The VASI application origin binds only to a private interface or network and
  accepts ingress from the edge plus explicitly approved management sources.
- Application and worker/job processes use private networks for PostgreSQL and
  supporting services.
- PostgreSQL and document storage use host-managed or named persistent volumes.
- Secrets and signing material are mounted from protected host/container secret
  paths, never copied into an image.
- Runtime values use the tracked public-safe VASI environment example; supported
  credentials are loaded from one-value `_FILE` mounts before application code
  starts.
- Container images and upstream releases are pinned; `latest` is not a
  production version policy.

## Edge Access Policy

The central public ingress must proxy enough of the signing application for
external recipients to open and complete emailed invitations without exposing
the private origin itself. VASI reserves distinct public application and
recipient-signing hostnames; both terminate at the central TLS ingress, while
their upstream containers remain private.

Route policies must be explicit:

- Staff/admin application routes require the CNB portal authentication policy.
- Recipient signing routes preserve upstream invitation tokens and configured
  recipient authentication; they do not require a CNB staff portal account.
- APIs, webhooks, callbacks, health checks, static assets, uploads/downloads,
  and any long-lived connections receive narrowly defined policies based on the
  selected upstream release.
- Unknown or unreviewed routes fail closed.

The exact pinned-baseline classification, including React Router data requests,
recipient TRPC procedures, file routes, blocked integrations, forwarding
headers, limits, and failure behavior, is defined in the
[edge route and exposure policy](edge-route-policy.md).

The supported two-layer staff identity/session behavior and first-admin
bootstrap are defined in the [staff authentication guide](staff-authentication.md).
The matching generic Compose and gateway implementation is under
`ops/deploy/edge/`.

Configure the application canonical/base URL to the public edge URL. The edge
must normalize the public scheme/host, replace untrusted client-supplied
forwarding headers, and pass accurate client metadata to the origin. The origin
must trust those headers only from the edge.

Use an encrypted private edge-to-origin hop when practical. Firewall and bind
rules remain required even when that hop uses TLS.

## Production Gate

Before first production use:

1. Pin and document the exact upstream baseline and image/source revision.
2. Build and test the unbranded baseline locally.
3. Apply and visually verify VASI branding.
4. Validate database migrations and persistent storage.
5. Validate SMTP delivery and sender alignment.
6. Validate TLS, secure headers, public route exposure, and staff portal access.
7. Complete a synthetic external recipient
   send/view/authenticate/sign/complete flow through the edge.
8. Verify forwarding metadata, audit output, X.509 signature validation, and
   tamper detection.
9. Verify the application origin cannot be reached directly from the WAN.
10. Exercise backup and isolated restore.
11. Document and test upgrade and rollback procedures.

Use the [operations, monitoring, and upgrades](operations-and-upgrades.md)
runbook for the health, maintenance, migration, staging, and rollback sequence.

Do not claim the service is production ready until every applicable gate has
target-environment evidence.

## References

- [Self-hosting requirements](https://docs.documenso.com/docs/self-hosting/getting-started/requirements)
- [Self-hosting configuration](https://docs.documenso.com/docs/self-hosting/configuration)
- [Signing certificate configuration](https://docs.documenso.com/docs/self-hosting/configuration/signing-certificate)
