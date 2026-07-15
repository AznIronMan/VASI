# Durable operational-alert handoff

Status: implemented in VASI 0.42.0 and corrected in VASI 0.42.1.

## Decision

Every packaged assurance control except the alert-spool readiness check itself
has a role-specific systemd `OnFailure` dependency. A hardened,
network-incapable recorder writes one atomic,
privacy-bounded record to a root-owned local pending spool. A separate
persistent readiness timer checks that spool every minute and returns nonzero
while any record or overflow notice remains pending. A transient probe failure
therefore cannot disappear merely because the probe passes on its next run or
an external monitor missed the original unit transition.

The handoff is deliberately transport-neutral. It does not contain an SMTP,
Graph, webhook, pager, or monitoring SDK; it holds no destination or
credential. An installation-selected dispatcher can read the next record,
deliver or register it using its own independently held configuration, and
acknowledge the exact record only after that handoff succeeds.

## Record contract and privacy boundary

`vasi-operational-alert/v1` contains only:

- an opaque random record ID and UTC occurrence time;
- the fixed public role and allowlisted packaged source-unit name;
- bounded systemd service result, exit-code class, and exit status; and
- the opaque systemd invocation ID when a valid one is available.

Missing or unsupported systemd metadata becomes `unknown`. When systemd
supplies `MONITOR_UNIT`, the recorder requires it to equal the allowlisted unit
instance. Every other metadata value is reduced to a 64-character syntax that
cannot encode JSON delimiters. Records never include hostnames, addresses,
paths, endpoints, tenant or company identifiers, users, participants, email
addresses, requests, content, payloads, provider responses, logs, settings,
credentials, keys, or arbitrary labels.

The stable status contract, `vasi-operational-alert-spool/v1`, reports only the
role, pending and invalid record counts, overflow count, oldest pending age,
and `ready`, `pending`, or `invalid`. It exits zero only for an empty,
structurally valid spool.

## Filesystem and bounds

The fixed roots are:

- gateway: `/var/lib/vasi/operations-alerts`;
- engine: `/var/lib/vasi-engine/operations-alerts`; and
- edge: `/var/lib/vasi-edge/operations-alerts`.

The root, `pending`, and `acknowledged` directories must be physical,
non-symbolic-link directories owned by root at mode `0700`. Every state file
must be a physical root-owned regular file at mode `0600` and within its fixed
size bound. The recorder takes an exclusive lock, writes within the destination
filesystem, synchronizes, and atomically renames the completed file. Unsafe
ownership, mode, path resolution, file type, content, time, or name fails
closed.

VASI retains up to 256 full pending records and never prunes an
unacknowledged full record. Further failures increment a bounded durable
overflow record with the last allowlisted source and time, so capacity loss is
visible rather than silent. An operator must acknowledge the overflow notice
separately. Up to 1,024 acknowledged records are retained; only the oldest
acknowledged history is pruned after a later successful acknowledgement.

## Dispatcher contract

Installations use four commands against the protected stable script:

```bash
sudo /usr/local/libexec/vasi/operational-alert-spool.sh status gateway
sudo /usr/local/libexec/vasi/operational-alert-spool.sh next gateway
sudo /usr/local/libexec/vasi/operational-alert-spool.sh \
  acknowledge gateway RECORD_ID OPAQUE_REFERENCE
```

Use `engine` or `edge` on the corresponding role. `next` returns the overflow
notice first, otherwise the oldest full pending record, or JSON `null`. The
record ID is the dispatcher's idempotency key. Do not acknowledge on a timeout,
ambiguous provider response, local queueing alone, or delivery failure. The
acknowledgement reference is a lowercase, syntax-bounded opaque incident or
provider-acceptance token; it must not contain customer or recipient data.

The local move and bounded acknowledgement output prove only that a privileged
caller acknowledged the handoff. They do not prove inbox delivery, paging,
human response, remediation, or external evidence retention. The dispatcher or
incident system owns those claims.

## systemd boundary

Gateway, engine, and edge each have one recorder template, one stable spool
readiness service, and one persistent readiness timer. The recorder and
readiness units have no network transport or application/database dependency,
run from the stable root-owned script outside `current`, have an empty
capability bounding set, use a private network namespace, deny the complete
network-I/O syscall group, and can write only their fixed state root. This
avoids relying on a distribution-sensitive broad runtime-filesystem mask while
also preventing access to Internet or local Unix-socket transports. Alert
units have no `OnFailure` dependency, preventing recursion. The readiness
timer repeats independently of each source control and leaves a stable failed
unit for an external host monitor to detect while pending state exists.

Install the stable script before the units:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec/vasi
sudo install -o root -g root -m 0555 scripts/operational-alert-spool.sh \
  /usr/local/libexec/vasi/operational-alert-spool.sh
sudo install -o root -g root -m 0644 deployment/systemd/vasi-ROLE-* \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/vasi-ROLE-*.service \
  /etc/systemd/system/vasi-ROLE-*.timer
sudo systemctl start vasi-ROLE-alert-readiness.service
sudo systemctl enable --now vasi-ROLE-alert-readiness.timer
```

Replace `ROLE` with exactly one host role. Run every normal one-shot manually
before enabling its timer, then prove record, `pending` status, `next`,
acknowledgement, and restored `ready` status using a deliberately created test
record. Do not acknowledge a real record merely to make the readiness service
green; first register it with the named incident owner.

## Limits

Same-host durable state cannot report total host loss, storage loss, root
compromise, systemd failure, network isolation, or destruction of the spool.
An independent monitor, approved external transport and recipient, escalation
policy, response owner, retention policy, and delivery test remain deployment
and pilot gates. The durable handoff makes those integrations reliable and
portable; it does not replace or falsely claim them.
