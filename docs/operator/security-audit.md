# Security Audit And Dependency Baseline

This is the living VASI security record. It distinguishes repository-wide npm
findings from code that is present and reachable in the supported origin image.
It is not a production approval while provider, policy, integrated audit, and
acceptance tasks remain open.

## Dependency Hardening Baseline

The July 2026 audit identified direct or transitive high-severity findings in
the request framework, router, mailer, gRPC/protobuf, multipart, temporary-file,
and WebSocket stacks. The supported lockfile now uses:

| Package | Pinned fixed version | VASI relevance |
| --- | --- | --- |
| React Router framework packages | `7.15.1` | Origin request rendering and actions |
| Hono | `4.12.27` | Origin HTTP server and auth mounts |
| Nodemailer | `9.0.3` | Production MIME generation for Microsoft Graph delivery |
| `@grpc/grpc-js` | `1.14.4` | Transitive cloud client code |
| `protobufjs` | `7.6.5` | Transitive cloud message processing |
| `form-data` | `4.0.6` | Transitive outbound HTTP clients |
| `tmp` | `0.2.7` | Packaging/tool dependency present in install graph |
| `ws` | `7.5.11` and `8.21.0` | Transitive WebSocket clients/servers |

This removes every npm-audit high and critical finding from both the full
repository installation and `--omit=dev` scan. In particular, the fixed router
line is beyond the framework-mode deserialization/RCE patch, Hono is beyond the
credentialed wildcard-CORS patch, and Nodemailer is beyond the raw-message
file/URL access patch.

Primary advisory records:

- [React Router framework deserialization/RCE](https://github.com/advisories/GHSA-49rj-9fvp-4h2h)
- [Hono credentialed wildcard CORS](https://github.com/advisories/GHSA-88fw-hqm2-52qc)
- [Nodemailer raw-message file/URL access](https://github.com/advisories/GHSA-p6gq-j5cr-w38f)
- [gRPC malformed-request crash](https://github.com/advisories/GHSA-5375-pq7m-f5r2)
- [protobuf JSON expansion denial of service](https://github.com/advisories/GHSA-wcpc-wj8m-hjx6)
- [`ws` memory-exhaustion denial of service](https://github.com/advisories/GHSA-96hv-2xvq-fx4p)

## Remaining Low/Moderate Findings

The repository-wide scan currently reports no high/critical findings and a
small set of low/moderate findings. They remain tracked rather than described
as universally harmless:

- AI SDK/provider and `gaxios`/`uuid` findings are in the disabled Vertex/AI
  path. The VASI production validator rejects those credentials and the edge
  blocks unsupported integration routes. Enabling AI requires a new audit.
- `@ts-rest/open-api`/`@anatine/zod-openapi`/`ts-deepmerge` findings are in the
  API schema/OpenAPI generation graph. VASI exposes no public REST API in its
  initial route policy; a future API enablement requires upgrade and review.
- Next/PostCSS findings belong to the separate docs/OpenPage workspaces, not the
  pruned VASI origin runtime image. They still matter to anyone deploying those
  workspaces separately.
- Esbuild and Turbo findings affect development/build tooling, not the running
  origin. Builders must remain non-public and process only trusted repository
  input.
- The remaining old `brace-expansion` path is under disabled AWS CRT storage
  support. VASI uses PostgreSQL document storage and rejects AWS upload
  configuration.

For each release, rerun the repository scan and scan the exact pruned runtime
image. A newly reachable or high/critical finding blocks release unless an
authorized owner records a concrete, time-bounded risk acceptance.

## Runtime Image Hardening

Runtime images apply available Alpine security upgrades during assembly. The
edge needs only the Node executable, and the origin invokes its packaged Prisma
CLI directly, so neither image retains npm, Corepack, or package-manager shims.
The origin also removes esbuild after the application and Prisma client have
been compiled. This prevents unused npm dependencies and esbuild's embedded Go
toolchain from expanding the production attack surface.

Scan each exact immutable image with a checksum-verified current scanner and
fresh vulnerability database. Record scanner/database time, image ID, finding
counts, and any remediation or explicit risk acceptance without committing the
full report when it contains private layer or host information.

## System Threat Model Checklist

The integrated audit must still verify:

- Entra tenant/client assignment, MFA/Conditional Access, callback exactness,
  cookie lifetime, deactivation, recovery, and emergency revocation;
- native VASI role/object authorization after the staff edge and first-admin
  bootstrap removal;
- recipient token entropy, expiry, replay, optional authentication, cross-
  envelope isolation, reminder/rejection/voiding, and final-download rules;
- edge path normalization, whole-batch TRPC decisions, Host/Origin/method/body
  limits, proxy-source enforcement, client-IP normalization, and generic logs;
- upload PDF validation, encoded document/attachment limits, malicious parser
  inputs, signature images, and document download authorization;
- Graph mailbox scope, sender alignment, template/link safety, header injection, retries, and
  redacted provider failures;
- PostgreSQL TLS/role boundaries, application encryption, jobs, backup/restore,
  secret recovery, deletion, retention, and legal hold;
- PDF signing key custody, certificate trust/expiry/rotation/compromise,
  timestamp behavior, whole-document coverage, and tamper detection;
- disabled webhooks, REST, jobs, HTML-to-PDF, enterprise, billing, telemetry,
  AI, cloud storage, and conversion paths remaining unreachable; and
- AGPL source availability, upstream attribution, privacy disclosure, and
  evidence exports containing no credentials or private key material.

## Evidence Rules

Security evidence may contain release IDs, route names, status codes, aggregate
counts, public certificate fingerprints, and redacted findings. It must not
contain customer documents, recipient addresses, invitation/access tokens,
cookies, authorization headers, passwords, database URLs, OIDC/Graph secrets,
private keys, or raw production dumps. Any exception requires an incident owner
and protected evidence store outside Git.
