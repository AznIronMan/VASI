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
- Current version: `0.8.0`

## Current State

- Documenso `v2.14.0` at commit
  `037170f6253d8b2bdeaf2eb0a08d04f152a41a58` is the pinned source baseline.
- The complete upstream monorepo is imported with its history, license, notices,
  lockfile, and source structure intact.
- The local runtime baseline has passed clean install, migration, seed, lint,
  typecheck, library tests, production build, captured mail, synthetic browser
  signing, PDF signature validation, and tamper detection.
- The supported Community Edition production configuration, database-storage
  boundary, disabled-feature defaults, `_FILE` secret mounts, and fail-closed
  startup validation are implemented and documented.
- VASI/CNB branding is applied across application, authentication, signing,
  email, browser/PWA, support, and signed-PDF surfaces with upstream
  attribution and audit/certificate facts preserved.
- The canonical public edge, maintenance-only fallback, staff/recipient route
  split, exact public TRPC procedures, internal paths, proxy metadata, and
  exposure limits are documented for the pinned baseline.
- A generic private-origin Compose contract now provides migration-only mode,
  mounted runtime secrets, an external PostgreSQL boundary, an unexposed app
  network, and a private-bind internal TLS listener. Its target-architecture
  container build has been validated without replacing the maintenance origin.
- A generic edge Compose contract now pins OAuth2 Proxy, classifies the complete
  route/TRPC surface, requires OIDC plus native VASI authorization for staff,
  preserves recipient token flows, verifies origin TLS, normalizes proxy
  metadata, and fails unknown traffic closed. It has passed isolated
  target-host smoke tests but is not connected to production OIDC credentials
  or the live listener.
- Inherited audit advisories and recorded baseline exceptions remain open
  hardening work.
- No VASI application has been deployed to the reserved production endpoints;
  they still serve maintenance placeholders.
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
- Documenso upstream: `https://github.com/documenso/documenso.git`
- Current pinned baseline: `v2.14.0` / commit
  `037170f6253d8b2bdeaf2eb0a08d04f152a41a58`
- Work on `main` by default.
- Use `origin` for VASI and `upstream` for Documenso.
- Before importing or updating upstream code, record the exact Documenso tag or
  commit in the active task and in public release documentation.
- Never force-push shared branches unless the operator explicitly authorizes it.
- Review staged changes for secrets, signing material, private notes, customer
  data, and accidental production artifacts before every commit.

## Upstream And License Rules

- Treat the Documenso Community Edition core as AGPL-3.0 and preserve upstream
  copyright, attribution, license, and notice files.
- The exact upstream tree includes `packages/ee/` under Documenso's separate
  Commercial License because the upstream application compiles against gated
  helpers. Preserve that license and subtree unchanged, but do not configure a
  Documenso enterprise license key, enable enterprise-gated behavior, modify
  enterprise code, or claim enterprise rights without explicit authorization
  and license review.
- The upstream enterprise feature list currently includes Stripe billing,
  Organisation Authentication Portal, document-action reauthentication,
  21 CFR features, email domains, and embed authoring/white-label behavior.
- VASI staff authentication must remain an external edge control unless a later
  task verifies a Community-compatible application path or licenses the
  enterprise Organisation Authentication Portal.
- Before network use of modified AGPL-covered code, provide users a clear path
  to the corresponding VASI source, build/install scripts, license, notices, and
  a statement of modifications through the same network interface or another
  license-compliant mechanism approved for VASI.
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

The current downstream repository uses:

- `apps/`, `packages/`, `docker/`, `assets/`, `patches/`, and `scripts/` - the
  pinned Documenso monorepo source and tooling.
- `docs/` - public project and architecture documentation.
- `docs/standards/` - engineering, branding, and security standards.
- `docs/operator/` - public-safe deployment and operations guidance.
- `ops/config/` - generic tracked non-secret production configuration examples.
- `ops/deploy/` - future generic tracked Docker deployment templates.
- `.tasks/` - ignored local task ledger.
- `.private/` - ignored operator-only notes and private artifacts.

Preserve the imported upstream monorepo structure. Keep VASI-specific
configuration, branding, deployment, and source-availability changes narrow and
documented so later upstream security releases can be compared and merged.

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

## Upstream Documenso Code Guidelines

These rules come from the pinned Documenso baseline and apply inside the imported
application source unless a stricter VASI rule above overrides them.

### Build/Test/Lint Commands

- `npm run build` - Build all packages
- `npm run lint` - Lint all packages
- `npm run lint:fix` - Auto-fix linting issues
- `npm run test:e2e` - Run E2E tests with Playwright
- `npm run test:dev -w @documenso/app-tests` - Run single E2E test in dev mode
- `npm run test-ui:dev -w @documenso/app-tests` - Run E2E tests with UI
- `npm run format` - Format code with Biome
- `npm run dev` - Start development server for Remix app

**Important:** Do not run `npm run build` to verify changes unless explicitly asked. Builds take a long time (~2 minutes). Use `npx tsc --noEmit` for type checking specific packages if needed.

### Code Style Guidelines

- Use TypeScript for all code; prefer `type` over `interface`
- Use functional components with `const Component = () => {}`
- Never use classes; prefer functional/declarative patterns
- Use descriptive variable names with auxiliary verbs (isLoading, hasError)
- Directory names: lowercase with dashes (auth-wizard)
- Use named exports for components
- Never use 'use client' directive
- Never use 1-line if statements
- Structure files: exported component, subcomponents, helpers, static content, types

### Error Handling & Validation

- Use custom AppError class when throwing errors
- When catching errors on the frontend use `const error = AppError.parse(error)` to get the error code
- Use early returns and guard clauses
- Use Zod for form validation and react-hook-form for forms
- Use error boundaries for unexpected errors

### UI & Styling

- Use Shadcn UI, Radix, and Tailwind CSS with mobile-first approach
- Use `<Form>` `<FormItem>` elements with fieldset having `:disabled` attribute when loading
- Use Lucide icons with longhand names (HomeIcon vs Home)

### TRPC Routes

- Each route in own file: `routers/teams/create-team.ts`
- Associated types file: `routers/teams/create-team.types.ts`
- Request/response schemas: `Z[RouteName]RequestSchema`, `Z[RouteName]ResponseSchema`
- Only use GET and POST methods in OpenAPI meta
- Deconstruct input argument on its own line
- Prefer route names such as get/getMany/find/create/update/delete
- "create" routes request schema should have the ID and data in the top level
- "update" routes request schema should have the ID in the top level and the data in a nested "data" object

### Translations & Remix

- Use `<Trans>string</Trans>` for JSX translations from `@lingui/react/macro`
- Use `t\`string\`` macro for TypeScript translations
- Use `(params: Route.Params)` and `(loaderData: Route.LoaderData)` for routes
- Directly return data from loaders, don't use `json()`
- Use `superLoaderJson` when sending complex data through loaders such as dates or prisma decimals
