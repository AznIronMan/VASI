# Private engine deployment

The VASI engine is deployed separately from V·Sign. Use a dedicated PostgreSQL
database and login role, a dedicated deployment directory, and a unique
`data/VASI.settings`. Do not copy the gateway bootstrap.

## Network contract

- `engine` exposes port 8080 only to its internal Docker network and has no host
  port mapping.
- `worker` has no listener or host port.
- `private-ingress` exposes the two approved routes and is the only host
  listener.
- The tracked Compose binds the facade to loopback. Put a private address in an
  ignored override only after confirming the address and port are reserved.
- Public reverse proxies must not receive the client certificate or key. A
  public route that happens to reach the listener must fail the TLS handshake.

Approved routes are:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Authenticated service health proof |
| `POST` | `/v1/whoami` | Validate and return bounded actor context |

Everything else returns 404 after service authentication.

## Initialize

Requirements are Docker Engine with Compose, PostgreSQL 15 or newer, an HTTPS
server identity for the private engine hostname, a dedicated V·Sign client
certificate, and an Ed25519 assertion key pair.

```bash
install -d -m 700 data
docker compose -f compose.engine.yaml --profile tools run --rm --build settings init
```

The engine initializer prompts for the dedicated PostgreSQL connection, creates
the bootstrap, applies the engine settings/boundary migrations, generates the
internal HMAC secret, and stores portable defaults. Complete these `engine`
scope settings before startup:

- `ENGINE_ASSERTION_PUBLIC_JWK`
- `ENGINE_ASSERTION_ISSUER`
- `ENGINE_ASSERTION_AUDIENCE`
- `ENGINE_INGRESS_TLS_CERT`
- `ENGINE_INGRESS_TLS_KEY`
- `ENGINE_AUTHORIZED_CLIENT_CA_CERT`
- `ENGINE_AUTHORIZED_CLIENT_FINGERPRINT_SHA256`

The gateway scope needs the corresponding `ENGINE_ORIGIN`, server CA, client
certificate/key, assertion private JWK/key ID, issuer, and audience. PEM values
may be entered on one line with newlines encoded as `\n`. For automated
provisioning, stream one JSON object directly to `settings import-json -`; never
write the object to disk or put values in command arguments.

Use separate signing and certificate material for development and production.
The service client certificate is not a participant signature and must never be
described as one.

## Release

```bash
docker compose -f compose.engine.yaml --profile release run --rm --build migrate
docker compose -f compose.engine.yaml up -d --build engine worker private-ingress
docker compose -f compose.engine.yaml ps
```

Run the gateway proof after every trust, key, network, or engine release:

```bash
npm run engine:probe
```

The proof verifies server trust, the V·Sign client certificate, engine health,
a signed actor identity, and rejection of a replayed assertion. Also verify:

1. unauthenticated TLS fails;
2. the public route remains unavailable;
3. `docker port` is empty for engine and worker;
4. the running containers contain no application secrets in their environment;
5. the admin engine diagnostic is 404 on the public gateway host and requires
   an allowlisted administrator on the private host; and
6. the bootstrap and PostgreSQL database are covered by matched backup/restore
   tests.

Changing service trust or runtime settings requires restarting the affected
processes. Migration remains an explicit, repeatable release step.
