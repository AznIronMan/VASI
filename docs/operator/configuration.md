# Production Configuration Contract

VASI uses a deliberately narrow production profile on top of the pinned
Documenso Community Edition baseline. The tracked example is
[`ops/config/vasi-production.env.example`](../../ops/config/vasi-production.env.example).
It contains public settings and secret-file paths only.

The application validates this profile at production startup. Missing values,
unsafe defaults, unsupported integrations, inline signing material, or a
non-HTTPS origin stop the process before it begins serving requests.

## Supported Profile

| Area                                 | VASI production decision                                              |
| ------------------------------------ | --------------------------------------------------------------------- |
| Public URL                           | HTTPS edge gateway; all generated links use this origin               |
| Internal URL                         | Separate HTTPS private origin used for self-calls                     |
| Staff authentication                 | External CNB edge policy; application signup disabled                 |
| Recipient authentication             | Upstream token-bound invitations and configured document policy       |
| Database                             | PostgreSQL with separate pooled/runtime and direct/migration URLs     |
| Document storage                     | PostgreSQL `database` transport                                       |
| Jobs                                 | Upstream `local` provider backed by PostgreSQL                        |
| Mail                                 | Microsoft Graph with app-only OAuth and Exchange mailbox-scoped RBAC  |
| PDF signing                          | File-mounted local PKCS#12 certificate and separate passphrase secret |
| Timestamping                         | Optional until the signing-identity gate selects and tests a TSA      |
| Uploads                              | PDF only, 10 MB application display limit; edge limit must agree      |
| Billing and enterprise               | Disabled; no Documenso enterprise license key                         |
| Analytics and telemetry              | PostHog unset and Documenso telemetry disabled                        |
| Signup and application SSO           | All application signup methods disabled; OAuth/OIDC unset             |
| AI, DOCX conversion, Browserless     | Disabled for the initial profile                                      |
| Webhook private-network bypass       | Disabled; no private target allowlist                                 |
| Rate-limit bypass and debug switches | Disabled                                                              |

Database storage keeps source PDFs, completed PDFs, and application records in
one PostgreSQL recovery boundary. Capacity planning, backups, restores, and
retention must therefore include large binary data; a database-only backup is
not merely metadata. Switching to object storage is an architecture migration,
not a one-line production toggle.

## Non-Secret Settings

These are the supported operator-set values. The example names use reserved
domains and must be replaced in the protected deployment configuration.

| Variable                                    | Required value or rule                                        |
| ------------------------------------------- | ------------------------------------------------------------- |
| `NODE_ENV`                                  | `production`                                                  |
| `VASI_CONFIG_PROFILE`                       | `production`                                                  |
| `PORT`                                      | Container listener, normally `3000`                           |
| `NEXT_PUBLIC_WEBAPP_URL`                    | Public HTTPS edge origin, with no path                        |
| `NEXT_PRIVATE_INTERNAL_WEBAPP_URL`          | Different private HTTPS origin, with no path                  |
| `NEXT_PUBLIC_SUPPORT_EMAIL`                 | Approved public support mailbox                               |
| `NEXT_PUBLIC_SIGNING_CONTACT_INFO`          | Approved contact text or URL embedded in signatures           |
| `NEXT_PUBLIC_UPLOAD_TRANSPORT`              | `database`                                                    |
| `NEXT_PUBLIC_DOCUMENT_SIZE_UPLOAD_LIMIT`    | Integer from 1 through 25; VASI default `10`                  |
| `NEXT_PRIVATE_JOBS_PROVIDER`                | `local`                                                       |
| `NEXT_PRIVATE_SMTP_TRANSPORT`               | `microsoft-graph`                                             |
| `NEXT_PRIVATE_MICROSOFT_GRAPH_TENANT_ID`    | Microsoft Entra tenant UUID                                   |
| `NEXT_PRIVATE_MICROSOFT_GRAPH_CLIENT_ID`    | Dedicated VASI mail application UUID                          |
| `NEXT_PRIVATE_SMTP_FROM_NAME`               | Approved VASI/CNB sender name                                 |
| `NEXT_PRIVATE_SMTP_FROM_ADDRESS`            | Exchange RBAC-scoped sender mailbox                           |
| `NEXT_PRIVATE_SIGNING_TRANSPORT`            | `local`                                                       |
| `NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH`      | Absolute `/run/secrets/` PKCS#12 path                         |
| `NEXT_PRIVATE_SIGNING_TIMESTAMP_AUTHORITY`  | Empty until a tested TSA is approved; otherwise approved URLs |
| `NEXT_PRIVATE_USE_LEGACY_SIGNING_SUBFILTER` | `false` or unset                                              |
| `NEXT_PUBLIC_DISABLE_SIGNUP`                | `true`                                                        |
| `NEXT_PUBLIC_DISABLE_EMAIL_PASSWORD_SIGNUP` | `true`                                                        |
| `NEXT_PUBLIC_DISABLE_GOOGLE_SIGNUP`         | `true`                                                        |
| `NEXT_PUBLIC_DISABLE_MICROSOFT_SIGNUP`      | `true`                                                        |
| `NEXT_PUBLIC_DISABLE_OIDC_SIGNUP`           | `true`                                                        |
| `NEXT_PUBLIC_FEATURE_BILLING_ENABLED`       | `false` or unset                                              |
| `DOCUMENSO_DISABLE_TELEMETRY`               | `true`                                                        |
| `DANGEROUS_BYPASS_RATE_LIMITS`              | `false` or unset                                              |

The following variables are deliberately empty in the supported profile:

- `NEXT_PRIVATE_DOCUMENSO_LICENSE_KEY`
- `NEXT_PUBLIC_POSTHOG_KEY`
- `NEXT_PRIVATE_GOOGLE_CLIENT_ID` and `NEXT_PRIVATE_GOOGLE_CLIENT_SECRET`
- `NEXT_PRIVATE_MICROSOFT_CLIENT_ID` and `NEXT_PRIVATE_MICROSOFT_CLIENT_SECRET`
- `NEXT_PRIVATE_OIDC_WELL_KNOWN`, `NEXT_PRIVATE_OIDC_CLIENT_ID`, and
  `NEXT_PRIVATE_OIDC_CLIENT_SECRET`
- `NEXT_PRIVATE_STRIPE_API_KEY` and `NEXT_PRIVATE_STRIPE_WEBHOOK_SECRET`
- `NEXT_PRIVATE_RESEND_API_KEY` and all `NEXT_PRIVATE_MAILCHANNELS_*` values
- `NEXT_PUBLIC_TURNSTILE_SITE_KEY` and `NEXT_PRIVATE_TURNSTILE_SECRET_KEY`
- `GOOGLE_VERTEX_PROJECT_ID` and `GOOGLE_VERTEX_API_KEY`
- `NEXT_PRIVATE_PLAIN_API_KEY`
- `NEXT_PRIVATE_BROWSERLESS_URL`
- `NEXT_PRIVATE_DOCUMENT_CONVERSION_URL`
- `NEXT_PRIVATE_WEBHOOK_SSRF_BYPASS_HOSTS`

Enabling one of these values requires a tracked configuration, security, route,
backup, and acceptance review. It must not be added directly on a live host.

## Secret Files

The VASI server supports a `_FILE` convention before it imports application
code. Each file contains exactly one UTF-8 value with an optional final newline.
Setting both the inline variable and its `_FILE` counterpart is an error.

| File-path variable                                | Populates                                    | Classification                       |
| ------------------------------------------------- | -------------------------------------------- | ------------------------------------ |
| `NEXTAUTH_SECRET_FILE`                            | `NEXTAUTH_SECRET`                            | Session signing/encryption secret    |
| `NEXT_PRIVATE_ENCRYPTION_KEY_FILE`                | `NEXT_PRIVATE_ENCRYPTION_KEY`                | Primary application encryption key   |
| `NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY_FILE`      | `NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY`      | Secondary application encryption key |
| `NEXT_PRIVATE_DATABASE_URL_FILE`                  | `NEXT_PRIVATE_DATABASE_URL`                  | Runtime database credential/URL      |
| `NEXT_PRIVATE_DIRECT_DATABASE_URL_FILE`           | `NEXT_PRIVATE_DIRECT_DATABASE_URL`           | Migration database credential/URL    |
| `NEXT_PRIVATE_MICROSOFT_GRAPH_CLIENT_SECRET_FILE` | `NEXT_PRIVATE_MICROSOFT_GRAPH_CLIENT_SECRET` | Entra application credential         |
| `NEXT_PRIVATE_SIGNING_PASSPHRASE_FILE`            | `NEXT_PRIVATE_SIGNING_PASSPHRASE`            | PKCS#12 passphrase                   |

The certificate itself is mounted at
`NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH`. Do not use
`NEXT_PRIVATE_SIGNING_LOCAL_FILE_CONTENTS` in production because it turns the
private key bundle into an environment value.

The selected mail provider and its authorization boundary are documented in
[Transactional Email Delivery](email-delivery.md). The signing trust and
timestamp decision gate is documented in [PDF Signing Identity And
Timestamping](pdf-signing.md).

Secret files must be supplied by the protected host/container secret store,
readable only by the container identity and authorized operators, excluded
from images and backups unless the backup is explicitly a protected secret
backup, and never printed during validation. File paths are configuration;
their contents are secrets.

## Generation, Recovery, And Rotation

Generate the session and two application encryption keys independently:

```sh
openssl rand -base64 48
```

Use a password manager or secret store to create the database, Graph mail, and
PKCS#12 credentials. Do not pipe production values through shared shell history
or write them to the repository checkout.

Key behavior is not interchangeable:

- Rotating `NEXTAUTH_SECRET` invalidates existing application sessions. Stage
  the new file, restart during a change window, and verify staff must sign in
  again through the edge.
- The primary encryption key protects security-sensitive application data such
  as 2FA material. The secondary key protects other encrypted records,
  including configured email transport data. The pinned baseline does not
  provide a general online re-encryption command. Never replace either key in
  place without an inventory, an offline tested re-encryption migration, a
  backup, and a rollback copy of the old key.
- Database and Graph application credential rotation must overlap provider-side validity
  where possible: create the new credential, stage the new secret, restart and
  verify, then revoke the old credential.
- Rotate the PKCS#12 bundle and passphrase as one change. Validate a synthetic
  signature, timestamp behavior, certificate chain, expiry, and tamper
  detection before revoking or archiving the old key. Preserve the public
  certificate chain needed to validate historical PDFs.

Disaster recovery requires the exact database/document backup plus the exact
encryption keys that protected its records. Keep a separately encrypted,
access-controlled, tested recovery copy of the session/encryption/signing
materials according to the future retention policy. A database restore without
the matching encryption keys is not a complete restore.

## Baseline Inventory And Unsupported Options

The pinned source inventory was compared across `.env.example`, the upstream
environment reference, process-environment types, and direct source reads.
Upstream supports alternatives that VASI does not currently support:

- S3, CloudFront, and Azure Blob variables under `NEXT_PRIVATE_UPLOAD_*`.
- BullMQ/Redis and Inngest variables under `NEXT_PRIVATE_REDIS_*`,
  `NEXT_PRIVATE_BULLMQ_*`, `NEXT_PRIVATE_INNGEST_*`, `INNGEST_*`.
- Resend, MailChannels, SMTP API, SES, Stripe, OAuth, OIDC, Turnstile, PostHog,
  Vertex AI, and Plain integration credentials.
- Google HSM and enterprise CSC signing variables under
  `NEXT_PRIVATE_SIGNING_GCLOUD_*` and `NEXT_PRIVATE_SIGNING_CSC_*`.
- Browserless, Playwright PDF generation, DOCX conversion credentials, database
  replicas, CloudFront signing, and private webhook bypasses.
- Hosting-provider database aliases such as `DATABASE_URL`, `POSTGRES_URL`,
  `POSTGRES_PRISMA_URL`, and their unpooled variants.
- Test, CI, migration compatibility, internal telemetry/license override,
  service-account migration, debug, and logger-internal variables.

Two `NEXT_PUBLIC_*` values are derived by the server and must never be set by
operators: `NEXT_PUBLIC_DOCUMENT_CONVERSION_ENABLED` and
`NEXT_PUBLIC_SIGNING_TRANSPORT_IS_CSC`.

The canonical upstream details remain in
`apps/docs/content/docs/self-hosting/configuration/environment.mdx`. That file
describes what the baseline can consume; this VASI contract decides what the
production service is authorized to consume.

## Startup Failure Contract

Production startup fails before listening when any of these conditions is
detected:

- the VASI profile marker, required values, or secret files are missing;
- secrets are short, obvious placeholders, or the two encryption keys match;
- public/internal URLs are invalid, non-HTTPS, loopback, credential-bearing, or
  use the same origin;
- database URLs are not complete PostgreSQL URLs or point at loopback;
- storage, jobs, mail, or signing transports differ from the supported profile;
- Graph app-only configuration is missing, legacy SMTP values are set, the
  upstream sender identity remains, or signup is on;
- the signing bundle is inline instead of mounted under `/run/secrets/`;
- telemetry, billing, enterprise licensing, analytics, AI, SSO, conversion,
  private webhook bypass, or a dangerous rate-limit/debug switch is enabled.

Validation errors name variables and rules but never include their values.
