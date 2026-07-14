# Deployment-perimeter readiness

## Decision

VASI provides a vendor-neutral, privacy-safe probe for deployment state that
cannot be derived inside the private evidence engine. The same packaged command
runs in the hardened gateway or engine maintenance image and emits bounded JSON
plus a deterministic exit status for an installation-selected scheduler and
alert transport.

The probe does not introduce a public monitoring endpoint, contact an alerting
vendor, or add host topology and credentials to PostgreSQL. The operator passes
one credential-free HTTPS origin, a `gateway` or `engine` settings scope, and an
absolute filesystem path that is already visible to the maintenance container.

## Checks and thresholds

`vasi-deployment-readiness/v1` checks four independent boundaries concurrently:

- `GET /api/health` succeeds over HTTPS and reports the exact packaged VASI
  version;
- the public TLS peer is trusted by the runtime and remains valid for the
  required window;
- the selected filesystem has enough available bytes and remains below the
  maximum-use percentage; and
- the configured gateway or engine service-certificate set parses and remains
  valid for the required window.

Gateway scope inspects the V·Sign service-client certificate and engine trust
CA. Engine scope inspects the private-ingress server certificate and authorized
client CA. When an optional evidence certificate seal is configured, engine
scope also inspects its complete public certificate chain. Private keys are
never loaded by this probe.

Defaults live in `config/assurance-policy.json`: certificates require 30 days
remaining, the selected filesystem requires 5 GiB available and no more than
85 percent use, and network operations time out after 10 seconds. Each numeric
value accepts a strictly bounded command-line override for an approved
installation policy.

## Privacy and failure contract

Success returns `ready`; any failed component or threshold throws a
`DeploymentReadinessError`, prints the same bounded `critical` result, and exits
nonzero. Reasons are fixed codes such as `public_health_unavailable`,
`public_version_mismatch`, `public_tls_expiring`,
`service_certificate_missing`, and `storage_pressure`. Raw network,
filesystem, certificate-parser, database, or settings errors are not emitted.

Output contains only the expected and observed release version, check time,
public health duration, certificate expiry windows, aggregate certificate
counts, aggregate filesystem bytes/use, configured thresholds, scope, and
bounded reason codes. It excludes the HTTPS origin, filesystem path,
certificate subject/issuer/serial/fingerprint/PEM, setting names and values,
database endpoint, installation/tenant/user identity, evidence content,
credentials, and private keys.

## Operation

Run from the appropriate deployment directory and mount the operator-selected
filesystem read-only when it is outside the application tree:

```bash
docker compose -f compose.production.yaml --profile tools run --rm \
  -v /secure/vasi-storage:/monitored:ro maintenance \
  scripts/probe-deployment-readiness.mjs https://vasi.example \
  --scope gateway --storage /monitored

sudo node scripts/probe-deployment-readiness.mjs https://vasi.example \
  --scope engine --storage /secure/vasi-engine-storage
```

The engine form runs on the trusted host because its maintenance container is
restricted to exact PostgreSQL egress and the perimeter probe must also reach
the public health and TLS origin. Do not broaden a private engine container for
this operational check. The host process reads the same protected bootstrap,
emits the same bounded schema, and receives no credential in its arguments.

Schedule each deployment scope independently and alert on every nonzero exit.
Retain only the bounded result under the installation's monitoring policy. A
failure should identify the deployment scope and reason code; operators should
inspect protected host/service logs separately rather than adding paths,
certificate identities, or customer fields to alert labels.

## Limits

This contract verifies the selected filesystem's byte capacity, not every host
filesystem or database tablespace. The separate capacity-readiness contract
measures aggregate CPU, memory, pressure stalls, filesystem inodes, and
PostgreSQL saturation/replication posture. Neither contract measures network
saturation, backup custody, sustained application capacity, DNS expiry,
certificate revocation, HSM/KMS/TSA state, or external alert delivery. The
operational-readiness and backup-continuity probes remain independent.
Customer-specific thresholds, alert destinations, escalation, RPO/RTO, and
incident ownership remain pilot-admission decisions.
