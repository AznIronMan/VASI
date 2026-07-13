# VASI Roadmap

## Current Position

Repository governance, the pinned/verified application, VASI identity,
production configuration, private PostgreSQL, internal TLS, DNS/TLS ingress,
origin Compose, staff OIDC, deny-by-default recipient gateway, mandatory
STARTTLS mail, PDF identity validation, and application-owned restore contracts
are established. The endpoints still serve maintenance placeholders: no
Documenso/VASI application or production signing workflow is live. Provider
credentials, production signing trust/timestamp approval, policy, integrated
acceptance, and cutover gates remain.

## Phase 1 - Upstream Baseline

1. Select and pin an exact Documenso Community Edition tag and commit.
2. Verify AGPL, attribution, Community/Enterprise boundaries, and runtime
   requirements.
3. Import the upstream monorepo with its license, notices, lockfiles, and
   structure intact.
4. Reproduce a clean local install, migration, test, build, and synthetic signing
   flow before customization.
5. Define the supported feature, configuration, storage, and secret contract.

## Phase 2 - VASI Product And Access

1. Apply approved VASI/CNB identity to application, email, and signer-facing
   surfaces through maintainable configuration or narrow overlays.
2. Inventory every staff, recipient, API, webhook, callback, asset, upload,
   download, health, and internal route in the pinned release.
3. Finalize the canonical edge URL and keep the fallback hostname
   maintenance-only, restricted, or removed unless explicitly approved.
4. Implement CNB staff authentication without requiring staff accounts for
   external recipients.
5. Implement the recipient signing proxy with explicit route policy, trusted
   forwarding metadata, limits, rate controls, and private-origin isolation.

## Phase 3 - Production Services

1. Replace the private-origin placeholder with a version-pinned Compose
   deployment using protected secrets, persistent storage, migrations, internal
   TLS, and a tested rollback.
2. Configure and verify CNB-branded transactional email delivery.
3. Provision a protected PDF-signing X.509 identity separate from TLS, and make
   a deliberate RFC 3161 timestamping decision.
4. Protect the complete data set with retention, encrypted backups, off-host
   copies, capacity monitoring, and isolated restore drills.
5. Define approved document types, recipient assurance, consent, retention,
   evidence, legal hold, and prohibited-use policy.

## Phase 4 - Hardening And Operations

1. Threat-model and harden authentication, authorization, recipient tokens,
   routes, uploads/downloads, APIs, webhooks, storage, SMTP, proxy headers,
   signing keys, dependencies, logs, and admin operations.
2. Verify audit accuracy and privacy/retention behavior through the edge.
3. Add health visibility and alerts for edge, origin, mail, jobs, database,
   storage, backups, TLS, signing certificates, and timestamping.
4. Write and rehearse maintenance, restore, incident, certificate/key rotation,
   upstream upgrade, migration, and rollback procedures.

## Phase 5 - Acceptance And Go Live

1. Run a synthetic end-to-end production acceptance gate across staff and
   recipient workflows, branding, email, audit, certificates, tamper detection,
   route policy, origin isolation, persistence, restore, alerts, and rollback.
2. Resolve every blocking security, legal/policy, reliability, and recovery
   finding.
3. Cut over the approved release through the canonical public edge.
4. Apply the final fallback-host posture and confirm there is no accidental
   second public application entrance.
5. Monitor the initial operating window with immediate rollback available.

## Execution Order And Parallel Work

- Upstream selection, import, and local reproduction are sequential and block
  application work.
- After the configuration contract, branding and public-route design can proceed
  in parallel.
- After the private-origin contract is staged, SMTP, PDF signing identity,
  staff auth, recipient edge, and complete backup/restore work can proceed in
  parallel without activating public application traffic.
- Recipient-edge implementation follows the route contract, private origin, and
  staff-auth boundary.
- Security hardening and operations follow the integrated system.
- Acceptance and production cutover are final gates and cannot be parallelized
  around unresolved blockers.
