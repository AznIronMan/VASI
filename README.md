# VASI

Version: `0.10.0`
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

`0.10.0` adds mailbox-scoped Microsoft Graph app-only transactional mail to the
hardened signing-policy, PDF identity, application-owned recovery,
staff/recipient edge, and private-origin contracts.
It includes:

- Repository rules and semantic versioning policy.
- Ignored local `.tasks/` and `.private/` structures.
- Public project, architecture, security, standards, roadmap, and deployment
  direction.
- An intended Docker production model recorded without exposing private host
  details.
- A split public-edge/private-origin access model that avoids direct WAN
  exposure of the signing application.
- Provisioned private PostgreSQL, internal-CA TLS, public/internal DNS ingress,
  reserved container endpoints, verified backup coverage, and staged origin/
  edge images without activating public application traffic.
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
  storage, local jobs, Graph app-only mail, mounted PDF-signing material, closed signup,
  disabled billing/telemetry/optional integrations, and explicit feature
  boundaries.
- Startup validation that rejects unsafe production defaults, plus `_FILE`
  loading for application, database, Graph mail, and signing secrets.
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
- A pinned, provider-neutral OIDC staff portal that remains separate from
  native VASI login, roles, disabled-user checks, and object authorization.
- A deny-by-default streaming edge gateway with strict path/method/origin/body
  handling, trusted proxy enforcement, verified origin TLS, coarse abuse
  limits, generic errors, redacted logs, cookie/redirect containment, and no
  identity-token forwarding.
- A generated inventory of all 269 pinned TRPC procedures, exact 12-procedure
  recipient allowlist, whole-batch enforcement, and local rejection of unknown,
  duplicate, mixed, and enterprise calls.
- Host-only `SameSite=Lax` VASI cookies, combined portal/application logout,
  and a one-time first-administrator bootstrap that refuses existing admins,
  inline database credentials, and duplicate users.
- A Microsoft Graph app-only mail transport with Exchange Application RBAC
  mailbox scope, protected credential mounts, sender enforcement, MIME support,
  and a redacted token/delivery probe.
- Fail-closed PKCS#12 integrity, key-match, and minimum-validity checks plus a
  separate production trust and RFC 3161 decision gate.
- A complete data/recovery inventory, a safe aggregate restore verifier, and an
  application-role-owned isolated restore workflow for database-held documents.
- Fixed request-router, HTTP, SMTP, gRPC/protobuf, multipart, temporary-file,
  and WebSocket dependency lines with no high/critical npm audit finding.
- A default-deny signing-policy approval matrix covering document eligibility,
  recipient assurance, consent, evidence, retention, legal hold, and refusal.
- A system threat-model checklist and explicit reachability classification for
  the remaining low/moderate dependency findings.

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
signing secrets, Graph mail integration, backups, and operator-verified
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
- [Staff authentication](docs/operator/staff-authentication.md)
- [Production configuration](docs/operator/configuration.md)
- [Transactional email delivery](docs/operator/email-delivery.md)
- [PDF signing and timestamping](docs/operator/pdf-signing.md)
- [Data lifecycle and recovery](docs/operator/data-lifecycle-and-recovery.md)
- [Signing policy approval draft](docs/operator/signing-policy-draft.md)
- [Security audit baseline](docs/operator/security-audit.md)
- [Operations, monitoring, and upgrades](docs/operator/operations-and-upgrades.md)
- [Local development](docs/operator/local-development.md)
- [Contributing](docs/contributing.md)

## License

The Documenso Community Edition core and VASI's AGPL-covered modifications are
distributed under the [GNU Affero General Public License v3.0](LICENSE).
The exact upstream source also contains a separately licensed `packages/ee/`
subtree used by upstream build-time gating. VASI preserves its Commercial
License but does not enable or claim rights to enterprise features.

## Changelog

### 0.10.0 - 2026-07-12

- Added a Microsoft Graph Nodemailer transport using client-credentials OAuth,
  cached short-lived tokens, base64 MIME submission, fixed sender enforcement,
  bounded message size, and redacted failures.
- Added production validation, file-backed secret loading, Compose wiring, and
  synthetic token/delivery probes for the dedicated mail application.
- Replaced the planned ACS SMTP profile with Exchange Application RBAC scoped
  to one transactional mailbox, including explicit in-scope and denial tests.

### 0.9.0 - 2026-07-12

- Added a secret-safe health command that verifies canonical, fallback, and
  private-origin health states plus public/internal TLS expiry.
- Added operator and self-hosting runbooks for layered monitoring, maintenance,
  upgrade staging, migration, rollback, incident response, and maintenance
  cadence.
- Corrected deployment status to reflect the implemented, staged edge contract.

### 0.8.1 - 2026-07-12

- Upgraded Alpine packages during image assembly so fixed base-system security
  updates are present even while the pinned Node image digest is unchanged.
- Removed npm, Corepack, and unused package-manager shims from the runtime
  images; migrations now invoke the packaged Prisma CLI directly.
- Removed the unused runtime esbuild executable and its embedded Go toolchain
  after the production application and Prisma client are compiled.

### 0.8.0 - 2026-07-12

- Updated React Router, Hono, and Nodemailer past reviewed high-severity request,
  CORS, deserialization, file-access, and SSRF findings.
- Pinned fixed gRPC, protobuf, multipart, temporary-file, and both supported
  WebSocket major lines; repository and runtime npm scans now report no high or
  critical findings.
- Preserved the pinned Community Edition source and enterprise subtree while
  validating the router/mail/server dependency update through application tests
  and type checking.
- Added a default-deny production signing-policy draft with document-class,
  signer-assurance, consent, evidence, retention, legal-hold, and acceptance
  decisions that must be approved before real documents are sent.
- Added the security dependency baseline, reachability record, integrated
  threat-model checklist, and secret-safe evidence rules.

### 0.7.0 - 2026-07-12

- Selected Azure Communication Services Email SMTP, added Nodemailer mandatory
  STARTTLS support, and locked production to the verified port 587 endpoint
  without relying on retired Exchange Online basic SMTP submission.
- Added a secret-file-only SMTP auth/delivery probe and documented sender-domain
  alignment, delivery evidence, credential rotation, and redacted failures.
- Branded the PDF signature reason as VASI and made production startup validate
  PKCS#12 decryption, certificate/private-key matching, and at least 30 days of
  remaining certificate validity.
- Documented the PDF reader trust boundary, certificate custody and rotation,
  and deliberate RFC 3161 decision; staged a separate untrusted identity for
  isolated validation without installing it as a production secret.
- Inventoried database documents, identity/audit/job data, application/edge
  secrets, signing material, TLS, configuration, and logs as one recovery
  boundary with explicit retention and legal-hold gates.
- Added fixed-target application-owned restore tooling and safe schema/data
  verification; passed a fresh checksum-validated off-host backup, generic
  restore drill, 163-migration assertion, and VASI-role access check.

### 0.6.0 - 2026-07-12

- Added the pinned OAuth2 Proxy OIDC staff portal and provider-neutral protected
  configuration, session, MFA, deactivation, logout, and recovery contract.
- Added the non-root streaming edge gateway implementing the staff, recipient,
  file, authentication, TRPC, blocked, and internal route policies with verified
  origin TLS and normalized forwarding metadata.
- Generated and checked all 269 pinned TRPC procedure names directly from the
  TypeScript router graph; only the 12 reviewed recipient procedures may bypass
  staff OIDC, and mixed, duplicate, unknown, or enterprise batches fail locally.
- Enforced path normalization, canonical Host/Origin, request/body limits,
  token/public-auth rate limits with small bursts, WebSocket rejection, generic
  errors, path-free logs, internal-cookie rejection, and internal redirect
  containment.
- Made application authentication cookies host-only and `SameSite=Lax`, and
  expire the edge portal cookie after successful native VASI sign-out.
- Added a fail-closed one-time native administrator bootstrap using mounted
  database/password secrets with no public signup or sample data.
- Validated Compose and both images on the intended architectures, verified the
  OIDC configuration against real discovery, and passed isolated routing, rate,
  TLS, cookie, redirect, logout, and forwarding-header smoke matrices without
  replacing either maintenance placeholder.

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
