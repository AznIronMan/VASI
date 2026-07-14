# Host and PostgreSQL capacity readiness

## Decision

VASI provides a vendor-neutral, privacy-safe capacity probe for Linux hosts and
the PostgreSQL database identified by the protected `VASI.settings` bootstrap.
It emits bounded JSON plus a deterministic exit status for an
installation-selected scheduler and alert transport. It adds no public route,
monitoring vendor, environment file, process enumeration, or host topology to
PostgreSQL.

The hardened maintenance container receives only four aggregate Linux proc
inputs: `stat`, `loadavg`, `meminfo`, and the `pressure` directory. The Compose
profile does not mount the host proc tree, process directories, command lines,
environments, network tables, or devices. Filesystem capacity comes from one
through four explicitly mounted, empty sentinel directories using fixed codes:
`system`, `docker`, `database`, and `backup`.

## Contract and thresholds

`vasi-capacity-readiness/v1` samples and validates:

- logical CPU count, one-second CPU utilization, one-minute load per CPU, and
  ten-second CPU `some` pressure-stall average;
- available/total memory, memory utilization, swap utilization when swap is
  configured, and memory `full` pressure-stall average;
- I/O `full` pressure-stall average;
- available/total filesystem bytes and inodes for every named sentinel mount;
  and
- PostgreSQL query latency, database size, active/total/maximum connections,
  oldest transaction age, primary/standby mode, and primary replica count.

Defaults live in `config/assurance-policy.json`. The gate fails above 90 percent
CPU or memory use, 1.5 one-minute load per logical CPU, 80 percent swap use,
80 percent CPU `some` pressure, or 10 percent memory/I/O `full` pressure. Every
filesystem requires 5 GiB and 100,000 inodes free and stays at or below 85
percent byte/inode use. PostgreSQL requires a query below 2,000 ms, no more than
80 percent of server connections, no transaction older than 300 seconds, and a
database no larger than 500 GiB under the portable default.

Replica enforcement is deliberately disabled in the sanitized single-node
profile. A production installation that promises a primary replica sets
`--require-primary-replica true`; a primary with no visible streaming replica
then fails closed. This flag is an operational threshold, not a replication
configuration mechanism.

## Privacy and failure contract

Success returns `ready`. A missing/malformed input or threshold failure returns
the same bounded `critical` document, a fixed reason code, and a nonzero exit.
Examples include `host_metrics_unavailable`, `memory_pressure`,
`storage_system_inode_pressure`, `database_connection_pressure`, and
`database_replica_missing`. Raw filesystem, proc parser, PostgreSQL, network,
and settings errors are discarded.

The document excludes proc and filesystem paths, mount/device names, database
name or endpoint, SQL text, process identifiers/state/command lines,
installation/tenant/user identity, evidence content, credentials, and keys.
Storage codes are a fixed vocabulary rather than operator-controlled alert
labels. Metric values are finite, nonnegative, and bounded before emission.

## Operation

Create an empty search-only sentinel on each filesystem to measure. Do not bind
the filesystem root or a directory containing data merely to call `statfs`:

```bash
sudo install -d -o root -g root -m 0111 /var/lib/vasi-capacity
```

The capacity service already mounts only the required aggregate proc inputs.
Mount the sentinel read-only and pass its fixed code:

```bash
docker compose -f compose.production.yaml --profile tools run --rm \
  -v /var/lib/vasi-capacity:/host/storage/system:ro \
  capacity --scope gateway --storage system=/host/storage/system

docker compose -f compose.engine.yaml --profile tools run --rm \
  -v /var/lib/vasi-capacity:/host/storage/system:ro \
  capacity --scope engine --storage system=/host/storage/system
```

Repeat `--storage CODE=/container/path` and a read-only sentinel mount for a
separate Docker, database, or backup filesystem. Duplicate, unknown, relative,
or missing targets fail before any measurement. Numeric thresholds have
strictly bounded command-line overrides; installations should keep their
approved values in the scheduler unit rather than an environment file.

The tracked systemd suite schedules gateway and engine scopes independently
every hour. Alert on every nonzero exit and retain only the bounded result under
the approved monitoring policy. Keep this gate independent from
deployment-perimeter, engine-operational, backup-continuity, and external
availability checks so one failed scheduler cannot conceal another boundary.
See the [recurring scheduler contract](recurring-operational-schedulers.md).

## Limits

A point-in-time sample detects current pressure; it does not establish a
customer capacity promise, forecast growth, configure PostgreSQL replication,
prove off-host backup custody, test denial-of-service protection, or deliver an
alert. Network saturation and PostgreSQL replica lag require deployment-specific
instrumentation. Pilot owners must still approve measured concurrency/volume,
growth targets, alert destinations, incident contacts, RPO/RTO, and stop or
rollback criteria.
