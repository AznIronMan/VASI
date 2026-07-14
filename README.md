# VASI

Verified Authorized Signing Infrastructure

Version: `0.3.0`

A CNB project maintained by Street Kings Productions.

## Current milestone

VASI currently provides the V·Sign identity gateway: public authentication and
SSO-first onboarding, private identity administration, invitations, account
lifecycle controls, and transactional email. Microsoft, Google, Yahoo, and
username/password sign-in are available; Zoho is implemented and awaits a
production client; Apple is implemented but hidden until Apple Developer
approval is complete.

The product direction is a private, independently deployable interaction and
evidence engine behind this gateway. It will record the authenticated
participant, exact immutable content and questions presented, activity and
timing evidence, responses and outcomes, and a tamper-evident chronology. That
engine is not yet implemented in this release; `/workspace` remains the
verified-session handoff point.

## Included

- Next.js 16 and Better Auth with PostgreSQL-backed users, accounts, sessions,
  verification records, and rate limits.
- Microsoft, Google, Yahoo, Zoho, Apple-ready, and manual authentication with an
  SSO-first participant experience.
- Internal-host-only identity administration, operator allowlisting,
  invitations, connector health/disconnection, password controls, account
  disablement, session revocation, and audit records.
- Microsoft Graph transactional delivery restricted to its configured mailbox,
  with SMTP as an optional fallback.
- A local SQLite bootstrap at `data/VASI.settings` containing only the
  PostgreSQL connection, installation identity, pool/transport selection, and
  the key that decrypts runtime settings.
- AES-256-GCM encrypted runtime configuration in PostgreSQL, audited settings
  changes, forward-only migrations, and a value-redacting settings CLI.
- A non-root application image, loopback-only published port, health check,
  read-only application filesystem, and explicit release migration.

## Configuration model

VASI does not use environment files. A populated `data/VASI.settings` is local
installation state and must never be committed, copied into an image, or sent
with a support bundle. It contains the minimum information needed to reach
PostgreSQL and decrypt the remaining settings. Provider credentials, auth and
mailer secrets, origins, allowlists, and other runtime configuration are
encrypted in PostgreSQL and scoped to the installation ID.

The bootstrap database and PostgreSQL must be backed up together. Losing
`VASI.settings` loses the decryption key for the PostgreSQL settings; restoring
the file against the wrong database or installation will not decrypt them.
Keep the file at mode `0600` and its directory private.

Settings are loaded once per application process. Restart the app after a
settings change. The settings listing command reports names and versions but
never values.

## Local setup

Requirements: Node.js 24 or newer and PostgreSQL 15 or newer. Docker is
optional and can provide PostgreSQL with the development Compose file.

```bash
npm install
docker compose up -d postgres
npm run settings:init
npm run dev
```

The initializer prompts privately for the PostgreSQL credential, creates
`data/VASI.settings`, applies the database migrations, generates a strong auth
secret, and stores the required gateway settings in PostgreSQL. Open
`http://localhost:3000` after initialization.

Without provider credentials, provider actions identify that configuration is
required. Apple remains hidden until its login flag is enabled. Manual sign-in
is under `Other methods`. Development verification and reset URLs are written
to the server console when no mail transport is configured; production fails
closed when the selected transport is incomplete.

Useful commands:

```bash
npm run settings:list
npm run settings -- set GOOGLE_CLIENT_ID
npm run settings -- set GOOGLE_CLIENT_SECRET
npm run settings -- unset GOOGLE_CLIENT_ID
npm run db:migrate
npm run check
npm run build
```

Secret values are accepted only through hidden interactive input. Do not place
them in command arguments, shell history, source files, build arguments, or
logs.

## Production containers

Create the deployment directory and initialize it from an interactive terminal:

```bash
install -d -m 700 data
docker compose -f compose.production.yaml --profile tools run --rm settings init
docker compose -f compose.production.yaml --profile release run --rm migrate
docker compose -f compose.production.yaml up -d --build app
```

The settings tool performs the one-time ownership transition needed for the
non-root runtime container. Run later changes through the same tool service:

```bash
docker compose -f compose.production.yaml --profile tools run --rm settings list
docker compose -f compose.production.yaml --profile tools run --rm settings set YAHOO_CLIENT_SECRET
```

The app publishes only `127.0.0.1:3000` and expects a trusted HTTPS reverse
proxy. The liveness endpoint is `GET /api/health`. Database migrations are an
explicit, repeatable release step and never run automatically at app startup.

For a one-time migration from an older container, stream its configuration to
`settings import-env -`; no temporary environment file is required. A protected
legacy file can instead be mounted and imported by path, then securely retired
only after the new application passes its checks. This compatibility command is
not the continuing configuration mechanism.

See [Authentication setup](docs/authentication.md) for callbacks, provider and
mailer settings, administration behavior, and the release checklist.
