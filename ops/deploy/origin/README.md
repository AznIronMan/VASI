# Private Origin Deployment

This template runs the VASI application behind an internal-CA Nginx listener.
It does not include PostgreSQL, public TLS, or the staff/recipient edge. Exact
host values and secret preparation stay in the ignored private operator notes.

## Inputs

Copy `deployment.env.example` to a protected path outside the repository. Use
an immutable image digest or a unique VASI commit tag. The image runs as numeric
UID/GID `1001:1001`. Docker Compose file-backed secrets retain host ownership,
so make every runtime secret owned by `1001:1001` with mode `0400` inside a
root-only parent directory. The signing PKCS#12 file is binary; every other
secret is one UTF-8 value with an optional final newline. If the deployment
uses a secret backend that remaps ownership, verify the mounted result is
readable by `1001:1001` and not by other container users.

The database URL must use the provisioned non-superuser application role and
require the intended TLS mode. Source/completed PDFs are stored in PostgreSQL
for this profile, so database backup and capacity are also document-storage
concerns.

The supported mail endpoint is Azure Communication Services SMTP on port 587
with mandatory STARTTLS. Its SMTP username and Entra client secret use the two
SMTP secret files. The signing bundle and passphrase remain separate from those
credentials and from both TLS identities.

## Validate And Migrate

From this directory, supply the protected environment file to every command:

```sh
docker compose --env-file /protected/vasi-origin.env config --quiet
docker compose --env-file /protected/vasi-origin.env --profile tools run --rm migrate
docker compose --env-file /protected/vasi-origin.env --profile tools run --rm signing-check
docker compose --env-file /protected/vasi-origin.env --profile tools run --rm smtp-probe
```

`signing-check` validates PKCS#12 integrity, key matching, and a minimum 30-day
validity window. `smtp-probe` verifies provider authentication and mandatory
STARTTLS without sending a message. Set `VASI_SMTP_PROBE_TO` only for an
approved synthetic delivery test. Neither probe prints secret values.

Migration-only mode reads the database `_FILE` secret in a subprocess. It does
not copy the value into Compose output or the long-running application
environment. Back up the database before migration and review upstream schema
compatibility before rollback.

## Bootstrap The First Administrator

Only when the database contains no administrator, create a random 16-or-more
character bootstrap password in `bootstrap-admin-password` using the same
`1001:1001` ownership and `0400` mode as the other application secrets. Set the
administrator email and display name in the protected environment file, then
run:

```sh
docker compose --env-file /protected/vasi-origin.env --profile tools run --rm bootstrap-admin
```

The command applies pending migrations, refuses to run if any administrator or
the requested email already exists, hashes the password with the application's
bcrypt cost, and creates one verified native VASI administrator without a
personal organisation. Sign in through the staff edge, change the bootstrap
password immediately, enable native VASI 2FA, create the real organisation, and
remove the bootstrap password file and values. Do not use the seed command or
temporarily enable public signup in production.

## Start And Verify

```sh
docker compose --env-file /protected/vasi-origin.env up -d app origin
docker compose --env-file /protected/vasi-origin.env ps
```

Verify internal TLS with the approved CA, then check `/healthz` and a synthetic
staff/recipient flow through the edge. Recreate the `app` container and confirm
the database-backed documents and audit state remain. The application container
has no published port; only the TLS origin listener binds the private host.

## Upgrade And Rollback

Record the current image reference and database backup, pull/build the new
immutable image, run migration-only mode, update the protected environment
file, and recreate `app` before `origin`. Rollback uses the recorded prior image
only when its code supports the migrated schema. Otherwise restore the database
backup in isolation first.

The reserved placeholder Compose project is the emergency maintenance rollback:
stop this stack, start the placeholder, and verify its content-free health and
maintenance response. Never run both projects on the same bind address/port.
