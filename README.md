# VASI

Version: `0.0.3`
Last updated: `2026-07-12`

VASI is **Verified Authorized Signing Infrastructure**: a planned CNB-branded,
self-hosted document-signing portal for Clark & Burke LLC.

The intended application foundation is
[Documenso Community Edition](https://github.com/documenso/documenso), an
AGPL-3.0 open-source signing platform that supports self-hosting. VASI will keep
the upstream signing workflow and auditability while applying CNB identity,
deployment policy, and operational standards.

## Current Status

`0.0.3` is the repository governance and architecture-planning skeleton. It
includes:

- Repository rules and semantic versioning policy.
- Ignored local `.tasks/` and `.private/` structures.
- Public project, architecture, security, standards, roadmap, and deployment
  direction.
- An intended Docker production model recorded without exposing private host
  details.
- A split public-edge/private-origin access model that avoids direct WAN
  exposure of the signing application.
- Provisioned private PostgreSQL, internal-CA TLS, public/internal DNS ingress,
  reserved container endpoints, and verified backup coverage for the future
  application build.

Documenso source has **not** been imported and VASI is not yet runnable. The
reserved infrastructure endpoints report that the application is not deployed;
they are not a production signing service.

## Intended Foundation

Documenso's current self-hosting documentation identifies PostgreSQL, outbound
email, a TLS/reverse-proxy path, and an X.509 signing certificate as core
production inputs. Completed documents can be cryptographically sealed, and an
RFC 3161 timestamp authority can be configured for trusted timestamps.

VASI's planned production shape uses a public CNB authentication/edge gateway
as the only WAN ingress. That edge proxies explicitly approved staff and
recipient-signing traffic to an internal-only VASI application origin. The
origin owns persistent database/document storage, protected application and
signing secrets, SMTP integration, backups, and operator-verified
upgrade/rollback procedures.

## Documentation

- [Project overview](docs/project-overview.md)
- [Architecture direction](docs/architecture.md)
- [Security and privacy](docs/security.md)
- [Roadmap](docs/roadmap.md)
- [Development standard](docs/standards/development.md)
- [Branding standard](docs/standards/branding.md)
- [Security standard](docs/standards/security-and-privacy.md)
- [Deployment direction](docs/operator/deployment.md)
- [Contributing](docs/contributing.md)

## License

This repository is distributed under the
[GNU Affero General Public License v3.0](LICENSE). When Documenso source is
imported, VASI will also preserve applicable upstream attribution, copyright,
license, and notice files. A tracked import task must establish the exact
upstream baseline before a runnable build is distributed.

## Changelog

### 0.0.3 - 2026-07-12

- Provisioned the private PostgreSQL and container-host prerequisites, public
  and internal DNS/TLS ingress, JAZMINE internal-CA identity, administrator
  access, and verified backup coverage for the future VASI application.
- Kept the live status explicit: the infrastructure placeholders are healthy,
  but Documenso/VASI application source and signing workflows are not deployed.

### 0.0.2 - 2026-07-12

- Defined the preferred public authentication edge and internal-only VASI
  origin architecture, including distinct staff and recipient route policies.

### 0.0.1 - 2026-07-12

- Established the VASI identity, repository governance, local task/private
  structures, public documentation, standards, and Docker production direction.
