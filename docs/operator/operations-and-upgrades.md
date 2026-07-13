# Operations, Monitoring, And Upgrades

This runbook covers the supported VASI edge/private-origin deployment. Keep
hostnames, addresses, credentials, provider identifiers, alert destinations,
and protected file paths in the ignored operator notes rather than this file.

## Health Contract

Monitor independent layers so a public liveness response cannot hide an origin
or database failure.

| Signal | Source | Expected production result | Suggested interval |
| --- | --- | --- | --- |
| Public edge liveness | Canonical `/healthz` | HTTP 200, generic `ok` | 1 minute |
| Edge readiness | Loopback `/readyz` | HTTP 200 after OIDC and origin probes | 1 minute on the edge host |
| Private application health | Origin `/healthz` with CA/name verification | Database and certificate checks are `ok` | 1 minute |
| Maintenance fallback | Fallback `/healthz` | `application_deployed:false` | 5 minutes |
| Container state | Both Compose projects | Required services healthy, no restart loop | 1 minute |
| SMTP authentication/delivery | Protected probe and synthetic mailbox | STARTTLS, provider acceptance, aligned delivery | Auth daily; delivery after change and periodically |
| PDF signing identity | `signing-check` and synthetic PDF | Key match, validity window, valid CAdES seal | Daily and after rotation |
| Public/internal TLS | Certificate chain and expiry | Verified name/chain, more than 30 days remaining | Daily |
| PostgreSQL backup | Backup automation | Recent checksum/catalog success and non-empty VASI dump | After every scheduled run |
| Full recovery | Isolated application-owned restore | Migration/table/data checks and exact-image health pass | Monthly and before risky upgrades |
| Capacity | Database, backup store, and container hosts | Below approved warning/critical thresholds | 5 minutes |

The public-safe `ops/monitor/check-vasi-health.sh` checks canonical, fallback,
and private health plus TLS expiry. Run it from an approved management source
that can reach the private origin:

```sh
VASI_PUBLIC_ORIGIN=https://sign.example.test \
VASI_FALLBACK_ORIGIN=https://fallback.example.test \
VASI_INTERNAL_ORIGIN=https://origin.internal.example.test:443 \
VASI_INTERNAL_CA_FILE=/protected/origin-ca.pem \
VASI_EXPECT_APPLICATION_DEPLOYED=true \
VASI_MINIMUM_TLS_DAYS=30 \
ops/monitor/check-vasi-health.sh
```

The check prints status and public certificate expiry only. It does not print
response bodies, tokens, cookies, identities, database URLs, or secret values.
Use `VASI_EXPECT_APPLICATION_DEPLOYED=false` while the maintenance placeholders
are intentionally active.

## Alert Policy

Page immediately for an unavailable canonical edge, failed private database or
signing-certificate health, failed backup/checksum/restore, repeated signing
failure, or evidence that the fallback is serving the application. Create
warning alerts at 90, 60, and 30 days for public/internal TLS and the PDF-signing
certificate; escalate at 14 and 7 days. Alert before disk or backup capacity can
consume the approved RPO window.

Keep logs path/query-free at the edge and redact authorization, cookies,
recipient tokens, email addresses, database URLs, and provider diagnostics.
Correlate allowed requests with generated request IDs. Preserve only the
minimum redacted incident evidence under the approved retention policy.

## Start, Stop, And Maintenance

Use the protected environment file with every Compose command. Render the
configuration before a state change:

```sh
docker compose --env-file /protected/vasi.env config --quiet
docker compose --env-file /protected/vasi.env ps
```

For planned maintenance, activate the content-free placeholder first and verify
its explicit maintenance response. Stop the edge before the origin when taking
the signing service offline. Start the origin and wait for private health before
starting the edge. Never run a placeholder and application project on the same
listener.

## Upgrade Gate

1. Record the current Git revision, image ID, upstream baseline, Compose files,
   migration count, and last successful backup/restore evidence.
2. Review upstream releases and security advisories. Preserve VASI overlays,
   the Community Edition boundary, AGPL source availability, and attribution.
3. Build from a clean Git archive using a unique commit tag. Scan the exact
   origin and edge images; unresolved high or critical findings block release.
4. Validate Compose, route inventory, policy tests, mail probe, signing check,
   and configuration rejection cases without production credentials in logs.
5. Restore the latest checksum-verified dump with the fixed isolated restore
   helper. Run the restore SQL and the new image's migration-only mode there.
6. Start the exact origin image without a published port against the isolated
   database. Verify database/certificate health, signing, tamper detection, and
   no outbound side effects.
7. Start both projects on unused private staging listeners with production-like
   OIDC, SMTP, signing, CA, and proxy-source controls. Run the staff and external
   recipient acceptance matrix.
8. Take a fresh production backup, enter maintenance, run migration-only mode,
   deploy origin then edge, and verify every health and synthetic signal before
   leaving maintenance.

## Rollback

Record the prior immutable images and configuration before migration. If the
new schema is backward compatible, restore the prior images and verify health.
If it is not, keep maintenance active and restore the pre-upgrade database into
isolation first; never point old code at an incompatible migrated database.
Escalate before replacing production data or signing keys.

The content-free placeholders are the last-resort application rollback. They
preserve health visibility without accepting documents or issuing VASI cookies.

## Incident And Recovery

For suspected credential, signing-key, or session compromise, enter maintenance,
preserve redacted timestamps/request IDs/image IDs, revoke the affected provider
credential, rotate VASI sessions and the edge cookie secret as applicable, and
follow the certificate compromise procedure before resuming signing. Do not
delete audit or document evidence that may be subject to legal hold.

Use the isolated recovery procedure in
[data lifecycle and recovery](data-lifecycle-and-recovery.md). Business approval
is required before recovered data replaces production or external mail/signing
effects resume.

## Maintenance Cadence

Assign named primary and backup operators before go-live. Review upstream and
dependency advisories weekly, apply critical fixes under the incident SLA,
review routine releases monthly, test restore/application recovery monthly,
review capacity quarterly, and rehearse upgrade/rollback at least quarterly.
Record the owner, evidence location, and next due date outside Git.
