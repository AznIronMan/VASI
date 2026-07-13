# VASI

Version: `0.5.1`
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

`0.5.1` hardens the private-origin container contract added in `0.5.0`, alongside
the exact public-edge route policy, VASI/CNB identity, supported production
configuration, and locally reproduced upstream baseline. It includes:

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
  lint, Remix typecheck, 133 library tests, and production build.
- A completed synthetic recipient-signing flow with captured mail, expected
  audit events, a valid whole-document SHA-256 CAdES seal, and detected
  post-signing tampering.
- A deliberate Community Edition production profile with database document
  storage, local jobs, TLS SMTP, mounted PDF-signing material, closed signup,
  disabled billing/telemetry/optional integrations, and explicit feature
  boundaries.
- Startup validation that rejects unsafe production defaults, plus `_FILE`
  loading for application, database, SMTP, and signing secrets.
- VASI/CNB identity across staff, authentication, recipient signing, browser,
  PWA, support, email, and signed-PDF surfaces.
- A documented CNB palette with accessible action colors, repository-owned
  assets, and an upstream-update checklist.
- Signer disclosures that preserve clear intent without promising legal effect,
  plus visible Documenso Community Edition attribution and corresponding-source
  access in transactional email.
- Browser checks of light and dark application/signing states, a captured
  branded password-recovery email, and a freshly completed synthetic PDF whose
  whole-document SHA-256 CAdES signature validates.
- A route inventory covering all 143 React Router manifest entries and the
  separate auth, file, REST, TRPC, jobs, and HTML-to-PDF server mounts.
- A fail-closed edge policy that separates staff from token-bound recipient
  traffic, parses TRPC batches, blocks unsupported integrations, and keeps
  health/jobs/rendering paths private.
- Canonical-origin, fallback-host, forwarded-header, client-IP, cookie,
  request-size, timeout, rate-limit, logging, and unknown-route requirements.
- A generic private-origin Compose deployment with an immutable-image policy,
  migration-only service, external PostgreSQL, protected secret mounts,
  database document storage, an unexposed app network, and a private-bind
  internal TLS proxy.
- A hardened container entrypoint that reads migration credentials from secret
  files without retaining them in the long-running server environment, plus a
  target-architecture image build and rendered-Compose validation.

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
- [Brand implementation](docs/branding.md)
- [Branding standard](docs/standards/branding.md)
- [Security standard](docs/standards/security-and-privacy.md)
- [Deployment direction](docs/operator/deployment.md)
- [Edge route and exposure policy](docs/operator/edge-route-policy.md)
- [Production configuration](docs/operator/configuration.md)
- [Local development](docs/operator/local-development.md)
- [Contributing](docs/contributing.md)

## License

The Documenso Community Edition core and VASI's AGPL-covered modifications are
distributed under the [GNU Affero General Public License v3.0](LICENSE).
The exact upstream source also contains a separately licensed `packages/ee/`
subtree used by upstream build-time gating. VASI preserves its Commercial
License but does not enable or claim rights to enterprise features.

## Changelog

### 0.5.1 - 2026-07-12

- Assigned the non-root runtime identity its intended numeric UID and GID.
- Documented host ownership and permission requirements for Docker Compose
  file-backed secrets after validating the packaged migration process against
  the provisioned database.

### 0.5.0 - 2026-07-12

- Added the public-safe private-origin Compose contract, protected runtime
  secret mounts, an external database boundary, and a private internal-TLS
  listener with no published application port.
- Added an explicit migration-only container mode and secret-file database
  loading while keeping deploy credentials out of image build arguments and
  the long-running application environment.
- Documented configuration, migration, startup, persistence checks, upgrades,
  rollback, and maintenance-placeholder recovery.
- Validated the rendered Compose services and built/inspected the non-root VASI
  image on the target container architecture.
- Kept the live application listener on its maintenance placeholder because the
  public edge, mail, and signing-material gates are not complete.

### 0.4.0 - 2026-07-12

- Selected one canonical public VASI edge and kept the reserved fallback public
  hostname maintenance-only rather than creating a second application entrance.
- Classified every pinned React Router route and separate server mount as
  public asset, token-public, public-auth, staff, service, internal, or blocked.
- Defined the exact recipient TRPC procedure allowlist, including whole-batch
  enforcement so a public signing call cannot carry a staff procedure.
- Defined token file access, staff uploads/downloads, blocked Community profile
  features, private health/jobs/PDF rendering, and initial no-public-REST posture.
- Defined path normalization, origin/method checks, upload and body limits,
  timeouts, rate limits, forwarding-header replacement, cookie/redirect
  containment, sensitive-log redaction, and fail-closed behavior.

### 0.3.0 - 2026-07-12

- Applied VASI and Clark & Burke identity to staff, authentication, recipient,
  metadata, favicon/PWA, support, email, and signed-PDF surfaces.
- Added the documented CNB palette, accessible foreground pairings,
  repository-owned logo assets, surface inventory, and upstream-update
  checklist.
- Replaced unsafe legal-effect guarantees with clear signer-intent language
  while preserving role, requested action, document state, authentication,
  certificate identity, and audit facts.
- Added a Clark & Burke transactional footer with Documenso Community Edition
  attribution and a link to the corresponding VASI source.
- Verified type checking, 133 library tests, the production build, light/dark
  browser flows, captured branded email, a complete synthetic signing flow, and
  a valid whole-document SHA-256 CAdES signature.

### 0.2.0 - 2026-07-12

- Defined the supported VASI Community Edition feature, storage, mail, jobs,
  authentication, integration, telemetry, and secret profile.
- Added a public-safe production environment example whose tracked values are
  reserved examples or protected secret-file paths.
- Added runtime `_FILE` loading for session, encryption, database, SMTP, and
  signing-passphrase secrets; conflicting inline values fail startup.
- Added fail-closed production validation for required values, HTTPS origins,
  strong/non-placeholder secrets, private signing mounts, closed signup, and
  disabled unsupported integrations.
- Documented application-key recovery limits, coordinated credential and
  certificate rotation, database document persistence, and the full upstream
  option boundary.

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
