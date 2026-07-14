# VASI

Verified Authorized Signing Infrastructure

Version: `0.6.0`

A CNB project maintained by Street Kings Productions.

## Current milestone

VASI currently provides the V·Sign identity gateway: public authentication and
SSO-first onboarding, private identity administration, invitations, account
lifecycle controls, and transactional email. Microsoft, Google, Yahoo, and
username/password sign-in are available; Zoho is implemented and awaits a
production client; Apple is implemented but hidden until Apple Developer
approval is complete.

This release includes the independently deployed private engine boundary behind
that gateway: separate engine, private-ingress, and worker processes; an
engine-owned PostgreSQL database/schema and migration history; mutual TLS from
V·Sign; HMAC-authenticated ingress requests; and short-lived, replay-protected
EdDSA actor assertions. The engine and worker publish no host ports.

Version 0.5.0 adds the first deliberately narrow evidence transaction. An
authorized company owner can issue immutable text/terms with acknowledgement or
yes/no response and receive a one-time opaque participant link. V·Sign returns
an authenticated, email-verified participant to that request. The engine binds
the account, exact content, available authentication/browser/network context,
server timing, and response into an append-only per-assignment event chain,
then signs a deterministic manifest with the standard VASI integrity seal.
Participants receive a readable receipt; authorized owners can retrieve the
verified structured record.

Version 0.6.0 adds the VASI-owned workflow and company control plane. Company
roles are separate from identity administration; owners and managers can create
optimistically versioned drafts, publish immutable revisions, issue scheduled
multi-step requests, use restricted forward-only response branches, and manage
reminder, revocation, reissue, due, expiration, and post-completion access
policies. The worker advances lifecycle state and a retry-safe encrypted outbox
for generic SMTP or signed-webhook delivery. New V·Sign sessions also preserve
session-specific authentication provenance rather than guessing from linked
accounts.

The standard seal proves that the manifest and covered chain have not changed
and were signed by the configured VASI seal key. It is not yet an independent
CA identity, trusted timestamp, legal conclusion, or long-term validation
profile. Documents and richer electronic activities, media, reports/bundles,
retention, participant data requests, productized owner/integration gateways,
and optional CA/TSA adapters remain subsequent milestones.

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
  changes, explicit gateway/engine scopes, forward-only migrations, and a
  value-redacting settings CLI.
- A non-root application image, loopback-only published port, health check,
  read-only application filesystem, and explicit release migration.
- Framework-independent engine contracts, service authorization, request
  signing, actor-assertion validation, and gateway-client packages.
- Private engine and worker containers with no published ports, plus an mTLS
  facade, PostgreSQL outbox baseline, and persistent assertion replay defense.
- An admin-host-only engine identity diagnostic at `/api/admin/engine`; it
  translates the authenticated V·Sign administrator session into a one-minute
  internal actor assertion without forwarding provider tokens or cookies.
- An internal first-slice issuance console at `/admin/evidence`, public opaque
  request paths under `/r/`, authenticated participant response/receipt pages,
  tenant membership enforcement, immutable workflow snapshots, append-only
  evidence chains, deterministic manifests, and Ed25519 VASI integrity seals.
- A private-origin company console at `/owner` with engine-owned roles,
  structured workflow drafts, immutable publication, ordered/conditional
  activity execution, request lifecycle controls, and revision-bound access and
  notification policies.
- AES-256-GCM encrypted outbox envelopes, immutable delivery-attempt records,
  bounded retry and stale-lock recovery, generic SMTP and HMAC-signed HTTPS
  webhook adapters, and session-level authentication provenance.

## Configuration model

VASI does not use environment files. A populated `data/VASI.settings` is local
installation state and must never be committed, copied into an image, or sent
with a support bundle. It contains the minimum information needed to reach
PostgreSQL and decrypt the remaining settings. Provider credentials, auth and
mailer secrets, origins, allowlists, and other runtime configuration are
encrypted in PostgreSQL and scoped to the installation ID and process family.

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
docker compose -f compose.production.yaml --profile tools run --rm --build settings init
docker compose -f compose.production.yaml --profile release run --rm --build migrate
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

## Private engine

The sanitized private-engine Compose contract is separate from the public
gateway contract:

```bash
install -d -m 700 data
docker compose -f compose.engine.yaml --profile tools run --rm --build settings init
docker compose -f compose.engine.yaml --profile release run --rm --build migrate
docker compose -f compose.engine.yaml up -d --build engine worker private-ingress
```

`engine` and `worker` have no `ports` mappings. `private-ingress` is the narrow
service facade and binds only `127.0.0.1:11121` in the sanitized template. A
deployment-specific, untracked Compose override may replace that with an
approved private address. Never bind it to a public interface or configure a
public reverse proxy to supply the V·Sign client certificate.

The engine uses its own PostgreSQL database or role/schema boundary and its own
`data/VASI.settings`; do not reuse the gateway bootstrap. Service TLS keys,
client trust, internal HMAC material, assertion keys, and evidence-seal keys are
encrypted in the appropriate PostgreSQL settings scope. Run
`npm run engine:probe` from the gateway deployment to verify mTLS, actor
identity, and replay rejection. The disposable conformance environment also
runs `npm run engine:probe:evidence` for issuance, isolation, response, receipt,
seal, replay, and tamper checks, plus `npm run engine:probe:workflow` for roles,
drafts, immutable revisions, branching, lifecycle, encrypted outbox, and
multi-step sealing.

See [Authentication setup](docs/authentication.md) for callbacks, provider and
mailer settings, administration behavior, and the release checklist. See
[Private engine deployment](docs/engine-deployment.md) and the
[engine boundary decision](docs/architecture/private-engine-boundary.md) for
the service trust and deployment contract. The
[sealed evidence slice](docs/architecture/sealed-evidence-slice.md) defines the
first transaction, record, and assurance limits. The
[workflow control plane](docs/architecture/workflow-control-plane.md) defines
the company roles, state machine, publication, lifecycle, and outbox contracts.
