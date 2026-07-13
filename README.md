# VASI

Verified Authorized Signing Infrastructure

Version: `0.1.0`

A CNB project maintained by Street Kings Productions.

## Current milestone

VASI now contains the authentication foundation for `https://vsign.cnb.llc`.
It is ready for Microsoft, Google, Apple, Yahoo, and username/password sign-in.
Provider credentials, production infrastructure, DNS, and TLS must still be
configured before the portal is live.

Authentication is not yet authorization. The next application milestone should
add CNB roles, external signer invitations, access policy, and the signing
workspace on top of the verified user session.

## Included

- Next.js 16 App Router portal with accessible desktop and mobile layouts.
- Better Auth 1.6 with PostgreSQL-backed users, accounts, sessions, verification
  tokens, and rate limits.
- Built-in Microsoft, Google, and Apple OAuth/OIDC providers.
- Yahoo OpenID Connect through the generic OAuth authorization-code flow.
- Username or email sign-in, registration, required email verification,
  password recovery, and session revocation after password reset.
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
SMTP is not configured. Production intentionally rejects email delivery when
SMTP is missing.

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
- `DATABASE_URL` for durable PostgreSQL
- `AUTH_EMAIL_FROM`, `SMTP_HOST`, and any SMTP credentials required by the relay
- One complete client ID/client secret set for each social provider to enable

Generate the auth secret with `openssl rand -base64 48`. Never store production
values in tracked files or build arguments.

Apply `npm run auth:migrate` as a release step before starting the new app. Build
with `npm run build`, start with `npm start`, and terminate TLS at a trusted proxy
that forwards the original HTTPS host. The liveness endpoint is `GET /api/health`.

See [Authentication setup](docs/authentication.md) for provider callbacks,
Apple key handling, email behavior, and the production checklist.

## Container image

```bash
docker build -t vasi:0.1.0 .
docker run --rm -p 3000:3000 --env-file .env.production vasi:0.1.0
```

The image runs as a non-root user and does not contain local environment files,
task records, or operator-private material. Database migration is a separate
release step and is not run automatically when the container starts.
