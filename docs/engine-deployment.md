# Private engine deployment

The VASI engine is deployed separately from V·Sign. Use a dedicated PostgreSQL
database and login role, a dedicated deployment directory, and a unique
`data/VASI.settings`. Do not copy the gateway bootstrap.

## Network contract

- `engine` exposes port 8080 only to its internal Docker network and has no host
  port mapping.
- `worker` has no listener or host port.
- `integration-gateway` has no host port and is the only application process
  that decrypts delivery credentials or contacts external SMTP/webhook hosts.
- `private-ingress` exposes only the approved route table and is the only host
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
| `GET/POST` | `/v1/owner/tenants` | List or create an authorized company space |
| `POST` | `/v1/owner/tenant-profile-read` | Read the active immutable company profile |
| `POST` | `/v1/owner/tenant-profiles` | Append/activate a branding or policy revision |
| `POST` | `/v1/owner/tenant-usage` | Read transactionally calculated quota use |
| `POST` | `/v1/owner/integration-list` | List redacted tenant integration bindings |
| `POST` | `/v1/owner/integrations` | Append/activate an allowlisted binding revision |
| `GET/POST` | `/v1/admin/installation-profile` | Read or revision the operator-controlled installation profile |
| `POST` | `/v1/owner/member-list` | List engine-authorized company members and grants |
| `POST` | `/v1/owner/members` | Grant or change company roles by verified email |
| `POST` | `/v1/owner/retention-policy-list` | List system and tenant retention-policy revisions |
| `POST` | `/v1/owner/retention-policies` | Append and activate a policy revision optimistically |
| `POST` | `/v1/owner/lifecycle-record-list` | List authorized record lifecycle, deadlines, and holds |
| `POST` | `/v1/owner/legal-holds` | Place or release an append-only legal hold |
| `POST` | `/v1/owner/data-request-review-list` | List participant data scopes for tenant review |
| `POST` | `/v1/owner/data-request-reviews` | Approve/redact or deny one tenant scope |
| `POST` | `/v1/owner/artifact-list` | List tenant-authorized artifact metadata and state |
| `POST` | `/v1/owner/artifacts` | Create a quarantined artifact revision |
| `POST` | `/v1/owner/artifact-chunks` | Append one bounded ordered artifact chunk |
| `POST` | `/v1/owner/artifact-finalizations` | Verify, inspect, hash, and publish/reject an artifact |
| `POST` | `/v1/owner/artifact-aborts` | Finalize an interrupted quarantine as rejected |
| `POST` | `/v1/owner/artifact-open` | Authorize and audit owner document streaming |
| `POST` | `/v1/owner/artifact-read` | Return one authorized owner artifact chunk |
| `POST` | `/v1/owner/workflow-list` | List authorized workflow drafts and publications |
| `POST` | `/v1/owner/workflows` | Create a validated workflow draft |
| `POST` | `/v1/owner/workflow-drafts` | Update a draft with optimistic version control |
| `POST` | `/v1/owner/workflow-publications` | Publish an immutable workflow revision |
| `POST` | `/v1/owner/requests` | Issue an immutable revision now or on a schedule |
| `POST` | `/v1/owner/request-list` | List tenant-authorized request lifecycle state |
| `POST` | `/v1/owner/request-actions` | Remind, revoke, or reissue idempotently |
| `POST` | `/v1/owner/records` | Verify and return an owner-authorized structured record |
| `POST` | `/v1/participant/open` | Bind/open an opaque participant assignment |
| `GET` | `/v1/participant/history` | List participant-bound records with lifecycle state |
| `GET/POST` | `/v1/participant/data-requests` | List or create a participant data request |
| `POST` | `/v1/participant/data-exports` | Open an approved sealed participant data export |
| `POST` | `/v1/participant/data-export-chunks` | Return one authorized verified export chunk |
| `POST` | `/v1/participant/respond` | Record one authoritative response and seal its manifest |
| `POST` | `/v1/participant/receipt` | Return a participant-safe verified receipt |
| `POST` | `/v1/participant/artifact-open` | Authorize/audit exact participant document access |
| `POST` | `/v1/participant/artifact-read` | Return one assignment-authorized artifact chunk |

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
internal HMAC secret and evidence-seal key pair, and stores portable defaults.
Complete these `engine` scope settings before startup:

- `ENGINE_ASSERTION_PUBLIC_JWK`
- `ENGINE_ASSERTION_ISSUER`
- `ENGINE_ASSERTION_AUDIENCE`
- `ENGINE_INGRESS_TLS_CERT`
- `ENGINE_INGRESS_TLS_KEY`
- `ENGINE_AUTHORIZED_CLIENT_CA_CERT`
- `ENGINE_AUTHORIZED_CLIENT_FINGERPRINT_SHA256`
- `ENGINE_OUTBOX_ENCRYPTION_SECRET`
- `ENGINE_INTEGRATION_CONFIG_ENCRYPTION_SECRET`
- `ENGINE_INTEGRATION_GATEWAY_HMAC_SECRET`
- `EVIDENCE_SEAL_PRIVATE_JWK`
- `EVIDENCE_SEAL_PUBLIC_JWK`
- `EVIDENCE_SEAL_KEY_ID`

Evidence reporting accepts optional bounds `ENGINE_EXPORT_MAX_BYTES` (default
64 MiB) and `ENGINE_EXPORT_CHUNK_BYTES` (default 256 KiB). A second
certificate-backed seal is enabled only when all three optional settings are
present:

- `EVIDENCE_CERTIFICATE_KEY_ID`
- `EVIDENCE_CERTIFICATE_PRIVATE_KEY_PEM`
- `EVIDENCE_CERTIFICATE_CHAIN_PEM`

Participant data access accepts `ENGINE_PARTICIPANT_DATA_EXPORT_MAX_BYTES`
(default 64 MiB), `ENGINE_DATA_REQUEST_REVIEW_DAYS` (default 30), and
`ENGINE_DATA_EXPORT_DELIVERY_DAYS` (default 7). Review and delivery bounds are
enforced by the engine and worker; export bytes remain in bounded PostgreSQL
chunks until controlled expiry.

The certificate private key is secret. Its chain is public verification
material. Use signing material distinct from the service TLS identity. Local
certificate verification proves the leaf signature and key match, not public
chain trust, revocation status, qualified-signature status, or trusted time.

Notification delivery starts with a disabled per-tenant binding. An operator
must first allow the exact SMTP or webhook host in the installation profile;
an owner can then configure the binding in the company console. Credentials
are encrypted in PostgreSQL and decrypted only by `integration-gateway`. Set
`ENGINE_PARTICIPANT_ORIGIN` when SMTP issue/reminder messages should contain the
VASI request link. Pre-0.11 global `ENGINE_NOTIFICATION_*` values are consumed
only for one-time compatibility conversion and should be unset after the new
binding is verified.

Document storage defaults to `ENGINE_DOCUMENT_MAX_BYTES=26214400` (25 MiB) and
`ENGINE_DOCUMENT_CHUNK_BYTES=262144` (256 KiB). The engine accepts only the
document media allowlist, and the authenticated chunk action alone receives a
512 KiB JSON envelope allowance; every other private action retains the 64 KiB
body limit. Increasing either setting requires target-deployment database/WAL,
replication, concurrency, backup/restore, and vacuum evidence. See the
[document artifact decision](architecture/document-artifacts-and-activities.md)
for inspection limitations and supported formats.

The gateway scope needs the corresponding `ENGINE_ORIGIN`, server CA, client
certificate/key, assertion private JWK/key ID, issuer, and audience. PEM values
may be entered on one line with newlines encoded as `\n`. For automated
provisioning, stream one JSON object directly to `settings import-json -`; never
write the object to disk or put values in command arguments.

Use separate signing and certificate material for development and production.
The service client certificate is not a participant signature and must never be
described as one.

The evidence-seal key is a separate Ed25519 identity. Keep an offline recovery
copy or use a higher-assurance external signing-key adapter; do not reuse the
gateway assertion key or TLS key. The private JWK is encrypted in the engine
settings scope, while public material is embedded in each seal and registered
with an immutable key/status history. Rotation uses a new key ID and retains
historical verification material.

## Release

```bash
docker compose -f compose.engine.yaml --profile release run --rm --build migrate
docker compose -f compose.engine.yaml up -d --build engine integration-gateway worker private-ingress
docker compose -f compose.engine.yaml ps
```

Run the gateway proof after every trust, key, network, or engine release:

```bash
npm run engine:probe
npm run engine:probe:evidence # disposable conformance database only
npm run engine:probe:workflow # disposable conformance database only
npm run engine:probe:documents # disposable conformance database only
npm run engine:probe:media # disposable conformance database only
npm run engine:probe:reports # disposable conformance database only
npm run engine:probe:lifecycle # disposable conformance database only
npm run engine:probe:productization # disposable conformance database only
```

The proof verifies server trust, the V·Sign client certificate, engine health,
a signed actor identity, and rejection of a replayed assertion. Also verify:

1. unauthenticated TLS fails;
2. the public route remains unavailable;
3. `docker port` is empty for engine, integration gateway, and worker;
4. the running containers contain no application secrets in their environment;
5. the admin engine diagnostic is 404 on the public gateway host and requires
   an allowlisted administrator on the private host; and
6. the bootstrap and PostgreSQL database are covered by matched backup/restore
   tests.

For a containerized matched backup, prepare a protected destination writable
by UID `1000`, then mount it only for that invocation:

```bash
docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /secure/vasi-backups:/backup maintenance \
  scripts/backup.mjs create /backup/vasi-YYYYMMDD
```

Changing service trust or runtime settings requires restarting the affected
processes. Migration remains an explicit, repeatable release step.
