# VASI

Version: `0.1.1`
Last updated: `2026-07-12`

VASI is **Verified Authorized Signing Infrastructure**: a planned CNB-branded,
self-hosted document-signing portal for Clark & Burke LLC.

The pinned application foundation is
[Documenso Community Edition](https://github.com/documenso/documenso), an
open-source signing platform that supports self-hosting. VASI currently tracks
Documenso `v2.14.0` at commit
`037170f6253d8b2bdeaf2eb0a08d04f152a41a58` and will keep the upstream signing
workflow and auditability while applying CNB identity, deployment policy, and
operational standards.

## Current Status

`0.1.1` is the locally reproduced upstream-source baseline. It includes:

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
- A dependency-ordered implementation roadmap covering upstream import, local
  verification, configuration, branding, access control, deployment, mail,
  PDF signing identity, data recovery, policy, security, operations,
  acceptance, and production cutover.
- The complete Documenso `v2.14.0` monorepo imported through a history-preserving
  merge with upstream licensing and attribution intact.
- A verified clean install, all 163 database migrations, synthetic seed,
  lint, Remix typecheck, 129 library tests, and production build.
- A completed synthetic recipient-signing flow with captured mail, expected
  audit events, a valid whole-document SHA-256 CAdES seal, and detected
  post-signing tampering.

The local proof uses an untrusted example certificate and synthetic data. It
also records inherited dependency advisories and known endpoint/proxy gaps for
hardening. The reserved infrastructure endpoints still serve maintenance
placeholders; they are not a production signing service.

## Pinned Foundation

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
- [Pinned upstream baseline](docs/upstream-baseline.md)
- [Architecture direction](docs/architecture.md)
- [Security and privacy](docs/security.md)
- [Roadmap](docs/roadmap.md)
- [Development standard](docs/standards/development.md)
- [Branding standard](docs/standards/branding.md)
- [Security standard](docs/standards/security-and-privacy.md)
- [Deployment direction](docs/operator/deployment.md)
- [Local development](docs/operator/local-development.md)
- [Contributing](docs/contributing.md)

## License

The Documenso Community Edition core and VASI's AGPL-covered modifications are
distributed under the [GNU Affero General Public License v3.0](LICENSE).
The exact upstream source also contains a separately licensed `packages/ee/`
subtree used by upstream build-time gating. VASI preserves its Commercial
License but does not enable or claim rights to enterprise features.

## Changelog

### 0.1.1 - 2026-07-12

- Reproduced the pinned baseline from a clean lockfile install and stabilized
  the upstream-generated lockfile and translation catalogs.
- Applied the upstream formatter's four mechanical source corrections so lint
  completes successfully.
- Verified all database migrations, synthetic seed, Remix typecheck, 129
  library tests, two clean production builds, health endpoints, and local mail.
- Completed and independently checked a synthetic signed PDF: the whole-file
  SHA-256 CAdES signature is valid and a one-byte mutation causes a digest
  mismatch.
- Documented inherited audit advisories, the missing signing-package tests, the
  unauthenticated limits-route error, local unknown audit IPs, and build
  warnings as explicit follow-up work.

### 0.1.0 - 2026-07-12

- Pinned Documenso `v2.14.0` at commit
  `037170f6253d8b2bdeaf2eb0a08d04f152a41a58`.
- Imported the upstream monorepo through a history-preserving merge and retained
  its licenses, attribution, lockfile, tooling, source structure, and code
  standards.
- Documented the Community/Enterprise license boundary and kept enterprise
  features disabled pending explicit licensing.

### 0.0.4 - 2026-07-12

- Expanded the project roadmap into implementation, product/access,
  production-service, hardening/operations, acceptance, and go-live gates.
- Established explicit separation between TLS and PDF signing certificates,
  staff and recipient authentication, and database versus full-system recovery.

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
