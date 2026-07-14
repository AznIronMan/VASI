# Private-engine outbound isolation

Status: accepted and implemented in VASI 0.21.0.

## Decision

Private VASI processes are deny-by-default for outbound network access. The
engine, worker, and private ingress join only Docker networks marked internal.
The integration gateway alone joins a dedicated provider-egress network. A
minimal PostgreSQL transport gateway is the only persistent process on a
separate database-egress network.

```mermaid
flowchart LR
  ingress["Private ingress"] --> engine["Evidence engine"]
  worker["Worker"] --> integration["Integration gateway"]
  ingress --> transport["Raw PostgreSQL gateway"]
  engine --> transport
  worker --> transport
  integration --> transport
  transport -->|"exact IPv4 + TCP port host policy"| database["Approved PostgreSQL"]
  integration -->|"application allowlists and validated adapters"| providers["Graph / SMTP / webhook / scanner"]
```

`engine-data`, `engine-private`, and `engine-integrations` are internal. Only
`database-gateway` joins `database-egress`; one-shot initialization,
migration, backup, capacity, and policy tools may join it while they run. Only
`integration-gateway` joins `integration-egress`. No service receives host
networking, the Docker socket, `NET_ADMIN`, or a firewall capability.

## PostgreSQL identity and transport

The persistent clients retain the original PostgreSQL URL and TLS settings.
A fixed, tracked, non-secret marker tells the Node PostgreSQL client to open
its raw socket to `database-gateway:5432`; TLS still starts end-to-end in the
client and validates the original database hostname. The transport gateway
does not terminate TLS, parse PostgreSQL, know credentials, or select an
arbitrary destination. It reads only the protected bootstrap destination and
pool bound, resolves at most 16 safe IPv4 answers, relays bytes to the fixed
port, and limits concurrent and incomplete connections.

The current host adapter uses Linux `iptables` through Docker's documented
`DOCKER-USER` forwarding boundary. Its policy semantics are independent of the
adapter: allow established return traffic, traffic within the dedicated
bridge, and TCP from that bridge to the resolved PostgreSQL IPv4 address set
and configured port; reject every other forwarded packet from the bridge. The
renderer never includes the hostname, URL, database name, or credentials.
With `--format portable-json`, it returns the same bounded source subnet,
destination IPv4/port set, protocol, established/intra-bridge allowances, and
default-deny decision as `vasi-database-egress-policy/v1`. That root-only
output is the adapter boundary for nftables, a cloud firewall, or another
approved host control; the packaged applicator consumes the default `iptables`
form.

The database-egress network uses the stable reviewed
`172.29.254.0/28` sanitized default and has IPv6 disabled. An installation with
an overlapping allocation must select a non-overlapping private IPv4 subnet in
its ignored Compose override and preserve the same single-subnet and
IPv6-disabled invariants. IPv6-only PostgreSQL is deliberately unsupported by
this adapter and fails closed.

## Persistence and ordering

The packaged policy service runs after Docker and network availability. Its
timer reapplies the policy after boot and every two minutes, covering Docker
network recreation and bounded DNS changes. The transport gateway refreshes
its IPv4 set every minute and becomes unhealthy after five minutes without a
successful resolution. If DNS changes between refreshes, a new address can be
denied until the host policy catches up; availability may pause, but the
policy does not broaden.

The policy must be applied before persistent services start. A deployment
manager should order the VASI engine stack after
`vasi-engine-database-egress-policy.service`. The one-shot bootstrap
initializer is the only fresh-install exception because the protected
database destination does not exist until initialization completes; apply the
policy immediately afterward and before migration or service startup.

The shipped systemd units assume `/opt/vasi-engine/current`. Change only
`WorkingDirectory` and the matching documentation path when an installation
uses a different release symlink. Unit configuration contains no secret or
environment file. The root host service has only the network capabilities
needed for the firewall adapter and Docker control; those privileges are not
passed to any container.

The default Docker project and firewall chain are `vasi-engine` and
`VASI_DATABASE_EGRESS`. A dedicated host running more than one isolated VASI
instance must give each applicator and verifier the same validated
`--project-name` and unique uppercase `--chain` (maximum 28 characters), then
record those arguments in the corresponding systemd `ExecStart` overrides.
This also permits disposable assurance beside a stopped or running production
project without sharing containers, networks, or firewall chains.

## Bounded verification

`scripts/probe-engine-egress-boundary.mjs` verifies:

- the installed database chain exactly matches a freshly rendered policy and
  has exactly one `DOCKER-USER` jump;
- the database gateway, engine, integration gateway, worker, and private
  ingress are running, with declared health checks healthy;
- a fixed public HTTPS canary is unreachable from the database gateway,
  engine, worker, and private ingress;
- the same canary is reachable from the integration gateway; and
- an engine query crosses the raw transport and completes through PostgreSQL.

Its successful JSON contains only schema, release version, fixed check names,
status, and a private-service count. Failure output is one fixed sentence. It
does not emit container IDs, network names, subnet, destination addresses,
hostnames, routes, response bodies, credentials, or customer information.

## Failure and rollback

Policy generation, validation, or application failure stops nonzero and leaves
the previous installed policy in place whenever one exists. An unresolved or
unsafe database destination fails generation. A missing rule, unexpected
destination, extra chain rule, public private-service path, failed integration
canary, unhealthy runtime, or broken database transport fails verification.

Never remove the host policy while `database-gateway` or a one-shot database
tool is running. For an authorized rollback, stop the private engine stack,
remove the policy with `apply-database-egress-policy.sh remove`, restore the
previous complete release and its network contract, then rerun that release's
assurance. Removing the policy is not a troubleshooting shortcut.

## Assurance limits

Internal Docker networks and host forwarding policy reduce reachable paths;
they do not make a compromised host administrator, Docker daemon, kernel,
database endpoint, DNS resolver, or integration gateway trustworthy. Provider
destinations remain enforced by the integration gateway's installation and
tenant allowlists, strict URL parsers, TLS validation, and adapter contracts.
Installations still require independent boundary testing, monitored policy
and probe failures, host patching, protected administrative access, and
approved incident response.
