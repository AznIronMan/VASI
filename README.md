# VASI

Verified Authorized Signing Infrastructure

Version: `0.2.0`

A CNB project maintained by Street Kings Productions.

## Current milestone

The authentication portal is deployed and responding at
`https://vsign.cnb.llc`. Microsoft and username/password sign-in are enabled in
production. Transactional verification and password-recovery messages use a
mailbox-scoped Microsoft Graph application, with SMTP retained as a fallback.
Google, Apple, and Yahoo sign-in remain visible but disabled until their
credentials are configured.

The internal identity administration console is available at the configured
private origin under `/admin`. It lists connector health, manual-password
availability, and account state; supports invitations, password setup/reset,
account enable/disable, and forced connector disconnection; and records each
administrative change. Public account creation and invitation acceptance start
with an email-domain check that recommends Microsoft, Google, Apple, or Yahoo
before exposing the secondary manual-password path.

The production container workflow includes a one-shot database migrator,
restart policy, liveness monitoring, a read-only filesystem, and a configurable
loopback or private-network bind for trusted HTTPS gateways.

Administration has a narrow operator role, but document authorization is still
the next application milestone. CNB signer roles, document access policy, and
the signing workspace must be added on top of the verified user session.

## Included

- Next.js 16 App Router portal with accessible desktop and mobile layouts.
- Better Auth 1.6 with PostgreSQL-backed users, accounts, sessions, verification
  tokens, and rate limits.
- Built-in Microsoft, Google, and Apple OAuth/OIDC providers.
- Yahoo OpenID Connect through the generic OAuth authorization-code flow.
- Username or email sign-in, registration, required email verification,
  password recovery, and session revocation after password reset.
- SSO-first registration and invitation acceptance with common-domain mapping
  plus Microsoft 365 and Google Workspace MX discovery.
- Internal-host-only identity administration with operator allowlisting,
  account disablement, session revocation, connector status and disconnection,
  manual-password controls, invitations, and audit records.
- Microsoft Graph transactional delivery restricted to its configured sender
  mailbox, with SMTP available as an explicit fallback.
- Twelve-hour sessions, throttled authentication endpoints, secure cookie and
  origin defaults, encrypted provider tokens, security response headers, and
  generic account errors.
- Reviewed SQL migration, production build, health endpoint, and container image.

## Local setup

Requirements: Node.js 20.9 or newer and PostgreSQL 15 or newer. Docker is
optional and can provide PostgreSQL with the included Compose file.

```bash
cp .env.example .env.local
npm install
docker compose up -d postgres
npm run auth:migrate
npm run dev
```

Open `http://localhost:3000`. Without provider credentials, the four social
buttons remain visible and identify that configuration is required. In
development, verification and reset URLs are written to the server console when
transactional email is not configured. Production intentionally rejects email
delivery when the selected Graph or SMTP provider is incomplete.

For local administration, set `VASI_ADMIN_ORIGIN` to the local origin and add
your test account to `VASI_ADMIN_EMAILS`. The admin plugin promotes an
allowlisted account to the `admin` role when a new session is created.

Useful checks:

```bash
npm run check
npm run build
npm audit
```

## Production configuration

Copy the names from `.env.example` into the deployment secret store. At minimum,
configure:

- `BETTER_AUTH_URL=https://vsign.cnb.llc`
- `BETTER_AUTH_SECRET` with at least 32 random characters
- `VASI_ADMIN_ORIGIN` for the private HTTPS admin hostname
- `VASI_ADMIN_EMAILS` as a comma-separated operator allowlist
- `DATABASE_URL` for durable PostgreSQL
- A complete Microsoft Graph mailer configuration, or `AUTH_EMAIL_FROM`,
  `SMTP_HOST`, and any credentials required by an SMTP fallback
- One complete client ID/client secret set for each social provider to enable

Generate the auth secret with `openssl rand -base64 48`. Never store production
values in tracked files or build arguments.

Apply `npm run auth:migrate` as a release step before starting the new app. Build
with `npm run build`, start with `npm start`, and terminate TLS at a trusted proxy
that forwards the original HTTPS host. The liveness endpoint is `GET /api/health`.

See [Authentication setup](docs/authentication.md) for public and internal
provider callbacks, admin controls, onboarding behavior, Apple key handling,
email behavior, and the production checklist.

## Container image

```bash
export VASI_ENV_FILE=/absolute/path/to/vasi.env
docker compose -f compose.production.yaml run --rm migrate
docker compose -f compose.production.yaml up -d --build app
```

The app image runs as a non-root user and does not contain local environment
files, task records, or operator-private material. The production Compose file
binds to `127.0.0.1:3000` by default; set `VASI_BIND_ADDRESS` or `VASI_PORT` only
when the trusted ingress topology requires it. Database migration remains an
explicit, repeatable release step and never runs automatically on app startup.
