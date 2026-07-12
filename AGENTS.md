# AGENTS.md

This file defines repository rules for human operators and AI coding agents
working on VASI.

## Project Identity

- Project name: VASI
- Full name: Verified Authorized Signing Infrastructure
- Product direction: CNB-branded, self-hosted document signing based on
  Documenso Community Edition
- Maintainer: Street Kings Productions
- Company: Clark & Burke LLC
- Website: https://www.cnb.llc
- Developer email: streetkings@cnb.llc
- Current version: `0.0.3`

## Current State

- The repository contains governance, documentation, standards, and deployment
  direction only.
- Documenso source has not yet been imported.
- No runnable VASI application or production deployment exists yet.
- Keep public status statements honest as these conditions change.

## Required Workflow

- Every implementation request must be tracked with a `VASI-xxxx` item before
  code or documentation changes begin.
- This applies to requests from a developer, operator, Codex, Grok, or any other
  LLM or automation agent.
- Use `.tasks/active/`, `.tasks/pending/`, `.tasks/completed/`, and
  `.tasks/cancelled/` for local tracking.
- `.tasks/` is intentionally gitignored. Do not reference VASI task IDs in
  public docs, release notes, README content, commit messages, or pull requests.
- Increment the VASI version for every completed tracked change according to
  semantic versioning.
- Keep `VERSION`, the version in this file, and the root README aligned.
- Update `README.md` and relevant files in `docs/` when behavior, setup,
  architecture, configuration, deployment, security, or support policy changes.
- At the end of completed changes, commit the work and push `main` to the
  configured `origin` unless the operator explicitly says not to push.

## GitHub And Upstream Sync

- VASI origin: `https://github.com/AznIronMan/VASI.git`
- Intended Documenso upstream: `https://github.com/documenso/documenso.git`
- Work on `main` by default.
- Use `origin` for VASI and `upstream` for Documenso.
- Before importing or updating upstream code, record the exact Documenso tag or
  commit in the active task and in public release documentation.
- Never force-push shared branches unless the operator explicitly authorizes it.
- Review staged changes for secrets, signing material, private notes, customer
  data, and accidental production artifacts before every commit.

## Upstream And License Rules

- Documenso is currently distributed under AGPL-3.0. Treat imported or modified
  Documenso code as AGPL-covered and preserve upstream copyright, attribution,
  license, and notice files.
- Do not import upstream source until a tracked task defines the baseline,
  integration shape, VASI changes, upgrade strategy, and license verification.
- Prefer configuration, theme assets, and narrow documented overlays over broad
  rewrites so future upstream security updates remain practical.
- Do not copy Documenso enterprise-only code, assets, features, or license keys
  into VASI without explicit authorization and license review.
- Do not claim VASI is endorsed by Documenso.

## Versioning Rules

- Patch: documentation, branding adjustments, bug fixes, upstream patch updates,
  and compatible operational maintenance.
- Minor: new signing workflows, integrations, configuration options, or
  meaningful upstream feature baselines.
- Major: incompatible schema/configuration changes, major architecture changes,
  or broad divergence from the upstream application.
- Track VASI's version separately from the Documenso baseline version.
- `1.0.0` is reserved for the first production-ready release that passes the
  documented acceptance and recovery checks.

## Documentation Rules

- Public user-facing documentation belongs in `docs/`.
- The root README stays high level: identity, status, foundation, requirements,
  documentation links, license posture, and changelog.
- Engineering, branding, security, and release expectations belong in
  `docs/standards/`.
- Public-safe deployment and live operations guidance belongs in
  `docs/operator/`.
- Private hostnames, addresses, SSH commands, credentials, certificate details,
  production paths, and operator notes belong only in `.private/` or approved
  host/container secret stores.
- Public docs and examples must use reserved names such as `example.com`, fake
  addresses, and non-secret placeholder values.
- Do not present electronic-signature features as legal advice or claim that
  deploying VASI alone guarantees legal or regulatory compliance.

## Security And Privacy Rules

- Keep credentials, application secrets, encryption keys, signing-certificate
  private keys/passwords, TLS private keys, SMTP credentials, database URLs,
  OAuth secrets, API tokens, private deployment notes, dumps, backups, and live
  logs out of git.
- Use `.private/` only for ignored local operator context. Prefer host/container
  secrets for production material.
- Commit `.env.example` only when the application baseline exists; never commit
  real `.env` files.
- Never use real customer documents, signatures, signer identity data, audit
  trails, email addresses, or production exports as fixtures, screenshots, or
  examples.
- Treat uploaded documents, completed documents, audit data, email events,
  document hashes, recipient metadata, IP addresses, and backups as sensitive.
- Never log raw document content, signature images, access codes, session
  tokens, private keys, certificate passwords, or encryption secrets.
- Production signing must use a protected X.509 certificate. Certificate
  issuance, trust, rotation, revocation, expiry monitoring, backup, and restore
  must be deliberate operational decisions.
- Preserve Documenso's audit and cryptographic sealing behavior when applying
  VASI branding or workflow changes.

## Branding Rules

- VASI is a Clark & Burke/CNB product identity. Keep names, logos, colors, email
  sender identity, URLs, and document-facing text consistent with the approved
  brand standard.
- Branding must not obscure signer consent, recipient identity, document state,
  authentication requirements, audit information, or certificate trust status.
- Do not remove required open-source notices or imply that CNB authored
  unchanged upstream components.
- Keep brand assets in a clearly owned path once the upstream integration shape
  is selected. Do not overwrite upstream assets without documenting the delta.

## Repository Layout Direction

The current skeleton uses:

- `docs/` - public project and architecture documentation.
- `docs/standards/` - engineering, branding, and security standards.
- `docs/operator/` - public-safe deployment and operations guidance.
- `ops/deploy/` - future generic tracked Docker deployment templates.
- `.tasks/` - ignored local task ledger.
- `.private/` - ignored operator-only notes and private artifacts.

When Documenso is imported, preserve its upstream monorepo structure unless the
import task explicitly chooses and documents another strategy. Do not create a
second speculative application skeleton before that decision.

## Production Deployment Direction

- Production will use a split Docker deployment: a public edge/auth gateway on
  the privately designated edge host and an internal-only VASI application
  origin on the privately designated application host. Exact host and DNS
  details are documented in `.private/deployment-VASI.md`.
- The public edge is the only intended WAN ingress. Do not expose the VASI
  application origin, PostgreSQL, document storage, or supporting services
  directly to the WAN.
- Staff/admin routes may require the edge portal's CNB authentication policy.
  Recipient signing routes must use a separate policy that preserves
  Documenso's token-bound invite and configured recipient-authentication flow.
  Do not place a blanket staff login requirement in front of recipient links.
- Proxy edge-to-origin traffic over an approved private route, preferably with
  TLS or mTLS, and restrict origin ingress to the edge source and approved
  management paths.
- Configure the application's public/base URL for the edge hostname so emails,
  redirects, cookies, callbacks, and document links do not reveal or depend on
  the internal origin hostname.
- Preserve forwarding metadata required for security and audit events, but
  configure the origin to trust forwarded headers only from the known edge.
- A fallback public application hostname must remain inactive unless an
  explicit task documents why edge proxying is insufficient and approves the
  additional WAN exposure.
- Keep tracked Docker/Compose templates generic. They must not contain live
  hostnames, IP addresses, usernames, credentials, certificate contents,
  database URLs, or production documents.
- Use a TLS-terminating reverse proxy; do not expose PostgreSQL or internal
  service ports publicly.
- Persist PostgreSQL and document storage outside ephemeral container layers.
- Use protected host/container secret mounts for signing and application keys.
- Require backup, restore, upgrade, rollback, health-check, mail-delivery, and
  end-to-end signing verification before declaring production ready.
- A repository change is not authorization to deploy, migrate, restart, or
  mutate the live service unless the task explicitly includes that operation.

## Dependency And Change Rules

- Do not vendor unrelated third-party dependencies.
- Use the package manager and lockfile selected by the imported Documenso
  baseline.
- Keep upstream dependency and lockfile changes reviewable and intentional.
- Separate VASI-specific changes from mechanical upstream updates when
  practical.
- Never edit generated build output as source.

## Verification

- Documentation-only changes: check links, terminology, version alignment,
  secret hygiene, and Markdown formatting.
- Upstream imports/updates: run the upstream-required lint, typecheck, tests, and
  build checks; record the exact upstream baseline.
- Branding changes: visually verify desktop and mobile layouts plus every
  signer-facing email/document state touched.
- Signing changes: complete an end-to-end test covering send, view,
  authentication, sign, completion, audit trail, certificate validation, and
  tamper detection using synthetic data.
- Deployment changes: validate Compose configuration, container health,
  database persistence, SMTP delivery, TLS routing, signing certificate access,
  edge authentication, recipient-link routing, direct-origin isolation,
  forwarding-header trust, backup/restore, upgrade/rollback, and secret
  redaction.
- Never claim production readiness or a successful live deployment without
  direct verification from the intended environment.
