# Local Development

This guide reproduces the pinned Documenso `v2.14.0` baseline with synthetic
data only. It is for development and verification; none of the example
credentials, certificates, documents, or mail settings are suitable for
production.

## Prerequisites

- Node.js 22 or newer
- npm 11.11 or newer
- Docker with Compose support
- OpenSSL for generating local secrets
- Optional: Poppler's `pdfsig` for independent PDF signature checks

The baseline was verified with Node.js 24.15.0 and npm 11.12.1.

## Bootstrap

1. Create an ignored local configuration:

   ```sh
   cp .env.example .env
   ```

2. Generate three independent development-only secrets:

   ```sh
   openssl rand -hex 32
   openssl rand -hex 32
   openssl rand -hex 32
   ```

   Put the results in `NEXTAUTH_SECRET`, `NEXT_PRIVATE_ENCRYPTION_KEY`, and
   `NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY`. Never reuse these values outside
   the local checkout.

3. For local signing tests only, configure:

   ```dotenv
   NEXT_PRIVATE_SIGNING_TRANSPORT="local"
   NEXT_PRIVATE_SIGNING_LOCAL_FILE_PATH="apps/remix/example/cert.p12"
   NEXT_PRIVATE_SIGNING_PASSPHRASE=
   NEXT_PUBLIC_UPLOAD_TRANSPORT="database"
   NEXT_PRIVATE_JOBS_PROVIDER="local"
   DOCUMENSO_DISABLE_TELEMETRY="true"
   ```

   The repository's example certificate is self-signed and untrusted. It
   exists only to prove the signing code path. Production requires a separately
   managed signing identity and must never use this file.

4. Install dependencies, start the development services, migrate, and seed:

   ```sh
   npm ci
   npm run dx:up
   npm run prisma:migrate-deploy
   npm run prisma:seed
   ```

   The development Compose file provides PostgreSQL, local mail capture,
   Redis, S3-compatible object storage, and document conversion. The default
   database and mail ports match `.env.example`. The verified baseline uses
   database document storage and local jobs, so Redis and object storage are
   available but are not required for the basic PDF signing flow.

5. Start the application:

   ```sh
   npm run dev
   ```

   Open `http://localhost:3000`. Captured development mail is available at
   `http://localhost:9000`.

Stop supporting services with:

```sh
npm run dx:down
```

## Verification

Run the verified baseline checks from the repository root:

```sh
npm run lint
npm run typecheck -w @documenso/remix
npm test -w @documenso/lib
npm run build
```

The signing package currently declares a test command but contains no test
files, so `npm test -w @documenso/signing -- --run` exits nonzero with a
no-tests-found result. Signing behavior must therefore also be exercised
through the synthetic browser flow below until a dedicated test is added.

## Synthetic Signing Check

Use only seeded or newly created fictitious documents and recipients:

1. Sign in with a synthetic seeded account.
2. Create or select a pending synthetic document.
3. Add a fictitious recipient and signature field, then send it.
4. Open the captured recipient message from the local mail UI.
5. Complete the signature and confirm the waiting or completed screen.
6. Confirm that completion mail was captured and that the envelope audit trail
   contains view, recipient-completion, document-completion, and email events.
7. Download the completed PDF and inspect it independently when `pdfsig` is
   available:

   ```sh
   pdfsig completed-synthetic-document.pdf
   ```

The expected local result is a valid SHA-256 `ETSI.CAdES.detached` signature
covering the complete document, accompanied by an unknown-issuer warning for
the self-signed example certificate. Changing a signed byte must produce a
digest mismatch.

## Verified Baseline Exceptions

- A clean npm audit currently reports 65 inherited advisories: 8 low, 47
  moderate, 9 high, and 1 critical. Do not run a forced automatic upgrade;
  remediation must be reviewed against the pinned upstream release.
- The unauthenticated `/api/limits` route returns an internal-server-error
  response instead of a clean authorization response.
- A direct local signing request records the audit IP as unknown. The
  production edge must forward client metadata, and the origin must trust it
  only from the approved proxy.
- The documentation build emits inherited invalid-height and stale browser-data
  warnings but completes successfully.

These exceptions are tracked as security, proxy, and upstream-maintenance work
and prevent the local proof from being interpreted as production readiness.
