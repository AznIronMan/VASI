# Recipient-encrypted backup custody

Status: implemented in VASI 0.35.0.

## Decision and trust boundary

VASI owns a portable, provider-neutral encrypted custody envelope for a
verified matched PostgreSQL and `VASI.settings` backup. The application host
stores only one or more X25519 recipient public keys in the existing encrypted
PostgreSQL runtime-settings boundary. It does not need, read, or retain a
custodian private key when creating a package.

The installation still chooses the off-host destination, transfer mechanism,
geographic and organizational separation, retention law, key custodians,
alerting, RPO, RTO, and recovery approvers. VASI deliberately does not embed a
cloud-backup SDK, vendor account, customer path, private key, or external
credential. A package left on the application host is encrypted, but it is not
an off-host backup.

Gateway and private-engine installations remain separate. Each needs its own
matched backup, recipient configuration, custody schedule, off-host copy, and
recovery drill.

## Recipient provisioning and rotation

Create a recipient on a protected offline or custody host. The parent directory
must already be a real mode-`0700` directory; the new private JWK is created
exclusively at mode `0600` and is never printed:

```bash
npm run backup:custody -- recipient backup-2026-q3 \
  /secure/vasi-custody-keys/backup-2026-q3.private.jwk
```

The command prints only a public record shaped as
`{"keyId":"…","publicJwk":{"crv":"X25519","kty":"OKP","x":"…"}}`.
Use an opaque key ID that does not contain a customer, host, person, or location
name. Configure a JSON array containing between one and eight public records in
`BACKUP_CUSTODY_RECIPIENTS` for the applicable gateway or engine scope:

```bash
npm run settings -- --scope gateway set BACKUP_CUSTODY_RECIPIENTS
npm run settings -- --scope engine set BACKUP_CUSTODY_RECIPIENTS
```

Although recipient public keys are not secret, the setting follows the same
AES-256-GCM PostgreSQL storage, installation binding, revision, and audit
contract as other runtime settings. Never place a private JWK in VASI settings,
`VASI.settings`, source, an environment file, an image, a backup root, or an
application-host scheduler.

Rotate with overlap: add the new public recipient, create and externally copy a
new package, prove both old and new custodians can recover the packages they are
expected to retain, then remove the old public recipient. Removing a public
recipient does not re-encrypt old packages. Losing every applicable private key
makes those packages unrecoverable. Two separately controlled recipients are
recommended when the approved custody policy requires break-glass recovery.

## Envelope and streaming guarantees

`scripts/backup-custody.mjs create` first requires the existing matched-backup
verifier to recompute the two member hashes and accept the PostgreSQL custom
archive. It then writes a random mode-`0600` partial file in the protected
custody root and streams this fixed inventory in order:

1. `manifest.json`;
2. `VASI.settings`; and
3. `postgresql.dump`.

No plaintext aggregate archive or temporary loose copy is created. A random
256-bit content key encrypts the stream as fixed 8 MiB AES-256-GCM chunks; each
chunk has a unique nonce derived from a random per-package prefix and its
bounded index, authenticates its index and plaintext length, and is verified
before recovery writes its plaintext. This keeps each GCM invocation within a
safe bounded size while supporting large PostgreSQL backups. A new ephemeral
X25519 key agreement plus HKDF-SHA-256 derives a distinct AES-256-GCM wrapping
key for every configured recipient. The authenticated canonical header binds
the suite, content length, creation/source timestamps, ephemeral public key,
and every opaque recipient key ID and wrapped key. Successful creation fsyncs
the file, atomically renames it, fsyncs the directory, and re-inspects the
result before retention can run. Temporary content and wrapping key buffers are
zeroed on completion paths where the runtime permits it.

The single `.vbc` filename includes the source timestamp and SHA-256 of every
package byte. `inspect` and `check` recompute that digest, validate the exact
versioned structure and length, and reject unsafe permissions, malformed
headers, truncation, or renamed content. This is independent copy-integrity
evidence, not proof of authenticity: anyone able to replace a package can also
compute a new filename. Only successful recipient-key extraction proves the
wrapped-key and per-chunk AES-GCM authentication tags.

The cleartext header intentionally contains only format metadata, timestamps,
opaque key IDs, public key material, and wrapped keys. The encrypted package
length reveals an approximate matched-backup size. It contains no installation
fingerprint, database endpoint, credential, tenant, participant, request, or
content label. The current format does not pad size or hide creation cadence.

## Creation, checking, and retention

Use distinct existing mode-`0700` matched and custody roots. The custody root
must be a mounted transfer location or staging area approved by the
installation; no destination is attached by the Compose contract.

```bash
docker compose -f compose.production.yaml --profile tools run --rm -T \
  -v /secure/vasi-gateway-backups:/matched:ro \
  -v /approved/off-host-mount/vasi-gateway:/custody maintenance \
  scripts/backup-custody.mjs create /matched /custody --scope gateway

docker compose -f compose.production.yaml --profile tools run --rm -T \
  -v /approved/off-host-mount/vasi-gateway:/custody:ro maintenance \
  scripts/backup-custody.mjs check /custody
```

Use `compose.engine.yaml` and `--scope engine` for the private engine. Creation
selects the newest recognized matched backup, takes a separate exclusive
mode-`0600` custody lock, creates and structurally verifies a package, and only
then applies retention. The maintenance process decrypts only the selected
public-recipient setting, not the scope's unrelated runtime secrets. The
default retains 30 packages, with a supported range
of 2 through 365. Deletion candidates must have an exact managed filename and
pass the complete copy-digest and structural inspection; unknown, symlinked,
or corrupt entries stop pruning and are never deleted automatically.

`check` is read-only and applies a default 26-hour threshold to the
header-declared source-backup timestamp in the newest recognized package; that
header is cryptographically authenticated only during recipient-key recovery.
Missing, malformed, corrupt, future-dated, or stale state exits nonzero with a
bounded reason. Output contains only schemas, timestamps, age/threshold,
recipient and managed-package counts, copy/structure status, and reason codes.
It never prints paths, public keys, key IDs, fingerprints, endpoints,
credentials, or customer data.

`authenticate PACKAGE.vbc --key-id … --private-key-file …` is the
custodian-side stronger check. It authenticates the selected content-key wrap,
canonical header, and every encrypted chunk without writing any recovered
plaintext. Run it on a protected custody/recovery host; do not move the private
key to the application host merely to strengthen the application-side check.
The structural `check` result explicitly reports
`recipientAuthentication: "not_performed"`, while `authenticate` reports only
the authenticated chunk count, source timestamp, schema, and successful
recipient authentication.

VASI does not ship an active custody timer because no sanitized default can
truthfully identify an off-host destination or prove that its mount is remote.
Use an installation-reviewed root-owned service/drop-in or external backup
orchestrator. Run it after matched-backup creation, monitor creation and
`check` independently, verify the destination is genuinely off-host before
enabling it, and do not express credentials in an environment file or unit.

## Offline authenticated recovery

Copy the `.vbc` package and one applicable private JWK to an isolated recovery
host through separately approved channels. Make the package and key mode `0600`
or stricter and prepare an empty real mode-`0700` destination parent. The
maintenance image can extract without a network or production settings mount:

```bash
npm run backup:custody -- authenticate /recovery/custody/PACKAGE.vbc \
  --key-id backup-2026-q3 \
  --private-key-file /recovery/keys/backup-2026-q3.private.jwk
```

Authentication does not create plaintext. A full recovery drill then uses the
maintenance image to extract without a network or production settings mount:

```bash
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user 1000:1000 \
  --tmpfs /tmp:size=16m,mode=1777 \
  -v /recovery/custody:/custody:ro \
  -v /recovery/keys:/keys:ro \
  -v /recovery/output:/recovery \
  vasi-engine-maintenance:0.35.0 \
  scripts/backup-custody.mjs extract \
  /custody/PACKAGE.vbc /recovery/matched \
  --key-id backup-2026-q3 --private-key-file /keys/backup-2026-q3.private.jwk
```

Extraction opens real non-symlink files without following a final symlink,
recomputes the package digest and structure from the same file handle,
authenticates the wrapped content key, and decrypts directly into a random
mode-`0700` partial directory. It never creates a plaintext aggregate archive.
It authenticates the complete ciphertext before reporting an inner-format
failure, then requires the recovered manifest hashes and `pg_restore --list`
to pass and binds the recovered manifest timestamp to the authenticated header.
Only then is the directory atomically promoted. Wrong recipient, wrong key,
tampering, truncation, inventory/size mismatch, unsafe permissions, or failed
PostgreSQL verification removes the partial output and exits nonzero.

After extraction, follow the matched-backup restore and confirmed database
rebind procedure. A production restore still requires an approved outage,
rollback window, named operator, independent row/fingerprint comparison, and
recorded RPO/RTO result.

## Assurance limits

Recipient encryption protects confidentiality and package integrity outside a
compromised application host only when private keys remain separately
controlled and an authentic package was created before compromise. It cannot
detect a malicious authorized application host that creates a false backup,
guarantee an off-host copy completed, establish immutability/WORM retention,
replace an HSM or organizational key ceremony, recover a lost private key,
prove media/legal retention compliance, or guarantee a recovery time. Those
claims require installation evidence and periodic independent restore drills.
