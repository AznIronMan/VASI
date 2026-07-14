# Recurring matched-backup continuity

## Decision

VASI supplies a scheduler-neutral, product-owned continuity command for the
matched PostgreSQL and `VASI.settings` backup pair. The command does not choose
a proprietary backup service, host path, timer, encryption provider, remote
destination, or alert transport. Those are installation controls, while safe
creation, verification, freshness assessment, and local retention semantics are
part of the VASI product.

The gateway and private engine remain separate installations and require
separate matched backup roots. A backup from one boundary never substitutes for
the other.

## Create, verify, then retain

`scripts/backup-continuity.mjs create PROTECTED_ROOT` performs this sequence:

1. Require an existing real directory with no group or other permission bits.
2. Acquire an exclusive mode-`0600` `.vasi-backup.lock`; concurrent cycles fail
   rather than race.
3. Use the existing matched-backup implementation to write a custom-format
   PostgreSQL dump and exact bootstrap through a random partial directory, then
   atomically rename it to `vasi-YYYYMMDDTHHMMSSZ`.
4. Recompute both file hashes and require `pg_restore --list` to accept the
   archive. A failed new verification removes only the directory created by
   that failed cycle.
5. Apply the versioned retention count only after the new backup verifies.
   Pruning recognizes exact timestamp directory names, requires each deletion
   candidate to have a supported manifest, and verifies its hashes and archive
   before removal. Unknown, symlinked, or corrupt entries are never pruned.
6. Remove the lock in a `finally` path and emit bounded readiness JSON.

The default policy retains 14 managed backups. Retention accepts only bounded
values from 2 through 365, so automation cannot silently reduce recovery to a
single copy. A stale lock is not removed automatically because VASI cannot
prove that a long-running dump is dead; an operator must confirm the process
state before removing only the lock.

## Independent freshness check

`scripts/backup-continuity.mjs check PROTECTED_ROOT` is read-only. It locates
the newest recognized timestamp directory, verifies its manifest hashes and
PostgreSQL archive, confirms that the directory timestamp agrees with the
manifest, and compares its age to the versioned threshold. The default maximum
age is 26 hours so a daily job has a bounded scheduling margin.

Missing, malformed, corrupt, future-dated, or stale state exits nonzero with a
bounded reason code. The JSON reports only schema, ready/critical status,
creation time, age, threshold, managed-copy count, and reason codes. It excludes
paths, installation fingerprints, database endpoints, credentials, users,
tenants, participants, evidence, and document data.

## Deployment handoff

The production Compose contracts expose a tools-profile `maintenance` service
that runs as UID/GID `1000`, mounts application data read-only, has a read-only
root filesystem, drops all capabilities, prohibits privilege escalation, and
publishes no port. No backup destination is attached by default.

An installation scheduler should run `create` daily and monitor its exit code,
then run `check` independently. Mount the destination read/write only for
creation and read-only for checking. The protected directory and scheduler
configuration are deployment state, not source or environment files. Alert
labels may include service, operation, status, age, and reason code, but never a
backup path or customer field.

Gateway example:

```bash
docker compose -f compose.production.yaml --profile tools run --rm \
  -v /secure/vasi-gateway-backups:/backup maintenance \
  scripts/backup-continuity.mjs create /backup
docker compose -f compose.production.yaml --profile tools run --rm \
  -v /secure/vasi-gateway-backups:/backup:ro maintenance \
  scripts/backup-continuity.mjs check /backup
```

Private-engine example:

```bash
docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /secure/vasi-engine-backups:/backup maintenance \
  scripts/backup-continuity.mjs create /backup
docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /secure/vasi-engine-backups:/backup:ro maintenance \
  scripts/backup-continuity.mjs check /backup
```

## Limits and recovery ownership

A same-host recurring copy improves operator recovery options but does not
survive total host loss. The installation must copy the matched directory into
an approved encrypted off-host system and periodically restore it in a
disposable environment. Backup retention, geographic custody, deletion,
encryption keys, legal holds, PostgreSQL point-in-time recovery, replication,
RPO, RTO, and incident escalation require named customer or operator owners.
VASI does not infer those promises from the 14-copy or 26-hour software
defaults.
