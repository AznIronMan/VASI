# Deployment Direction

This is public-safe deployment guidance. The intended production host and
operator access details are kept in ignored `.private/` notes.

## Current Status

VASI does not yet contain Documenso application source, a Dockerfile, or a
Compose stack. The commands and templates must be added only after an exact
upstream release is selected and reproduced locally.

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
- Container images and upstream releases are pinned; `latest` is not a
  production version policy.

## Edge Access Policy

The public edge must proxy enough of the signing application for external
recipients to open and complete emailed invitations without exposing the origin
itself. A separate public VASI origin hostname should not be necessary.

Route policies must be explicit:

- Staff/admin application routes require the CNB portal authentication policy.
- Recipient signing routes preserve upstream invitation tokens and configured
  recipient authentication; they do not require a CNB staff portal account.
- APIs, webhooks, callbacks, health checks, static assets, uploads/downloads,
  and any long-lived connections receive narrowly defined policies based on the
  selected upstream release.
- Unknown or unreviewed routes fail closed.

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

Do not claim the service is production ready until every applicable gate has
target-environment evidence.

## References

- [Self-hosting requirements](https://docs.documenso.com/docs/self-hosting/getting-started/requirements)
- [Self-hosting configuration](https://docs.documenso.com/docs/self-hosting/configuration)
- [Signing certificate configuration](https://docs.documenso.com/docs/self-hosting/configuration/signing-certificate)
