# Fail-closed production release activation

Status: implemented in VASI 0.41.0; corrected in VASI 0.41.1 and 0.46.2;
protected archive staging implemented in VASI 0.49.0.

VASI source archives are deliberately sanitized: they contain no installation
address, credential, bootstrap database, or live Compose override. Production
still needs a small installation-owned listener decision. A release must never
be selected merely because an archive extracted successfully; omitting that
protected decision could expose the wrong listener or leave recurring controls
pointing at an incomplete release.

The `release:activate` command makes that boundary explicit for the gateway and
private engine. It validates the complete candidate and merged runtime before
atomically changing `current`, reconciles the complete role without building or
pulling, and restores the prior selector and runtime when reconciliation fails.

## Protected inputs

Each host keeps two files outside the source release tree and shared data root:

- a mode-`0600` JSON activation configuration based on
  `deployment/activation/gateway.example.json` or
  `deployment/activation/engine.example.json`; and
- a mode-`0600` Compose listener overlay based on the corresponding
  `*.live.example.yaml` file.

Both files must be canonical regular files owned by root or the invoking
deployment account. Each containing directory must be canonical, owned by the
same trusted boundary, and mode `0700`. The configuration accepts exactly
these fields:

| Field | Meaning |
| --- | --- |
| `schema` | Exact `vasi-production-release-activation/v1` contract |
| `role` | `gateway` or `engine` |
| `releaseRoot` | Directory containing exact extracted releases |
| `currentLink` | Stable selector outside `releaseRoot` and `dataRoot` |
| `dataRoot` | Private mode-`0700` shared bootstrap-data directory |
| `overlayFile` | Stable protected listener overlay outside release and data roots |
| `releaseOwnerUid` | One explicitly trusted numeric owner for staged release files/directories |

Paths must be absolute, normalized, canonical, non-overlapping, and free of
group/world-writable parent boundaries used by activation. The protected
release-owner UID permits a root-only Docker deployment to verify a release
tree owned by its unprivileged deployment account; it grants no Docker or file
permission and must match the reviewed installation owner. The protected
overlay has one accepted four-line shape: it replaces only `app.ports` for the
gateway or `private-ingress.ports` for the engine with one TCP binding. The
address must be exactly `127.0.0.1` or RFC1918 IPv4; the target is fixed to
gateway port `3000` or engine port `8443`. An extra key, service, listener,
environment value, mount, network, command, or YAML feature is rejected.

The examples contain documentation addresses, not deployment values. Copy and
protect them outside the repository, then substitute only reviewed local paths
and the reserved listener. Never put the resulting files in source control, a
source archive, an environment file, a support bundle, or command output.

## Protected archive staging

VASI 0.49.0 makes the source-archive boundary a first-party fail-closed step.
Create a deterministic Git archive from the approved commit, with the release
identifier as its one top-level directory, and retain its independently
approved SHA-256 digest. The archive must be a canonical physical regular file
owned by root, the invoking deployment account, or the configured release
owner; it must not be group/world writable and cannot exceed 64 MiB.

From an already selected trusted release, inspect without writing first:

```bash
npm run release:stage -- CONFIG_FILE ARCHIVE_FILE RELEASE_ID EXPECTED_SHA256 --dry-run
```

Require the bounded JSON result with `status: "ready"`, then omit `--dry-run`
to stage the candidate. The command uses the same protected activation JSON
and listener overlay. It does not build images, run migrations, change Docker,
or change the `current` selector. Staging is safe to complete before the
separately approved cutover window.

The stager hashes one size-bounded read of the physical archive and parses
those same immutable bytes without invoking a host archive utility. It accepts
only gzip-compressed USTAR with one leading Git global-PAX commit identifier,
one exact release root, and ordered regular files/directories. It rejects
additional extensions, links, devices, duplicate or parentless entries,
traversal, noncanonical names, ambiguous executable bits, private/runtime
paths, unexpected trailers, and archives exceeding entry, file, expanded, or
decompressed limits. `package.json` must identify private package `vasi` at the
release version, and the role's sanitized Compose file must exist.

Extraction occurs in a private random directory under the configured release
root. The stager creates files without following links, verifies every digest,
normalizes the candidate root to `0750`, directories and executable files to
`0755`, other files to `0644`, and every entry to the configured release owner.
It then creates and verifies exact absolute `data` and `compose.live.yaml`
links to protected installation state. A private staging lock serializes the
operation. Linux publication uses a same-filesystem, no-replace rename and
verifies the published inode; an existing candidate is never replaced. A
failed attempt removes only its private temporary directory and lock. A stale
lock after abrupt host/process loss requires operator inspection before manual
removal.

## Candidate proof

Before any mutation, activation proves all of the following:

1. The candidate is a canonical direct child of the configured release root,
   with an exact semantic version in `package.json` and the role's sanitized
   Compose source.
2. Candidate source and boundary directories are not group/world writable;
   the candidate `data` entry is an exact symbolic link to the configured
   private shared data root.
3. Compose source contains no interpolation, environment file, environment
   block, include, or extend mechanism.
4. Candidate `compose.live.yaml` is absent or is an exact symbolic link to the
   stable protected overlay. Activation creates that link only after every
   preflight succeeds.
5. Docker renders both the sanitized and merged models. Project identity,
   service inventory,
   images, networks, mounts, commands, settings, and hardening must be byte-for-
   byte equivalent after normalizing the one approved listener replacement.
6. Every role image exists with the candidate version. Every runtime service
   remains read-only, unprivileged, capability-dropped, no-new-privileges, free
   of Docker-socket mounts, and bound to its exact image.
7. When `current` already selects a different release, that rollback release
   independently passes the same shared-data, Compose, listener, exact-image,
   directory, and hardening proof. Its live overlay must be the stable link or
   a protected byte-identical legacy copy.

The command inherits only the minimum Docker client selectors and emits a
fixed aggregate result containing schema, role, version, service count, image
count, and status. It does not emit a path, listener, image ID, credential,
setting, customer value, or captured subprocess output.

## Selected-path execution identity

VASI 0.46.2 resolves the invoked CLI path and the imported module URL to their
physical regular-file identities before entering `main`. This preserves the
import-safe module boundary while making both an exact release path and a
trusted `current` directory symlink execute the command exactly once. A
missing, unrelated, malformed, looping, NUL-containing, or oversized path
fails the identity check without executing the operational body or throwing an
unbounded error.

The same helper protects the complete reviewed set of importable operational
CLIs, not only activation. Release assurance owns that exact inventory, rejects
the former literal URL comparison, rejects missing or duplicate guards, and
requires the database-gateway runtime image to carry the helper. Spawned tests
prove physical invocation, a release-selector directory symlink, and import-
only behavior. A zero exit with no activation result is never evidence of a
dry-run; operators must require and retain the bounded JSON result.

## Activation sequence

Stage the exact source release with `release:stage`, then prepare all exact
images, settings, and compatible migrations. Take and verify the required
matched backup.
From the selected trusted release, preflight the candidate:

```bash
cd /opt/vasi/current
npm run release:activate -- /var/lib/vasi-release/gateway.json RELEASE_ID --dry-run
```

The first upgrade from a release that predates this command may run the exact
candidate copy instead:

```bash
cd /opt/vasi/releases/RELEASE_ID
npm run release:activate -- /var/lib/vasi-release/gateway.json RELEASE_ID --dry-run
```

After dry-run passes, pause installation-owned recurring work for the bounded
cutover window and omit `--dry-run` to activate. For a version-aligned stack,
activate and prove the private engine before the gateway. The command obtains a
private activation lock, creates the candidate's stable overlay link, updates
`current` by atomic rename, and runs the complete role with `--no-build` and
Compose health waiting. It never removes orphans. An exact `compose ps` proof
then requires only the declared services, exact images, running state, and any
declared health to be healthy.

If selection, reconciliation, or readiness fails, the command removes any
candidate overlay link it created. After a selector change it restores the
prior `current` target and reconciles the prior complete project. A failure of
the first activation, where no prior target exists, stops every candidate
runtime service instead. A failure of either recovery is reported separately and requires the installation's
break-glass procedure. The lock is removed on every exit.

The stable `compose.live.yaml` link is intentional: packaged systemd controls
run from `current` and therefore use the same installation-owned overlay after
cutover and rollback. A retained release created by this activator is directly
eligible for rollback. A pre-0.41 retained release containing a copied regular
live overlay must be reviewed and normalized to the stable protected link
before it can be selected as a future activator target.

## Limits and required surrounding gates

Activation does not build or pull images, initialize settings, run migrations,
take backups, apply the private-engine host firewall, install systemd units,
alter the public edge, or decide schema rollback compatibility. Those remain
explicit staged release steps. After activation, run the role's exact-image,
listener, health, mTLS/replay, outbound, backup, operations, capacity,
deployment, timer, accessibility, load, and public-edge proofs before resuming
normal operation.

The host and Docker administrator remains trusted. Source archive digests,
image SBOM/vulnerability evidence, database migration policy, protected-file
custody, alert delivery, and independent assessment remain separate release or
pilot gates.
