# VASI Roadmap

## Phase 1 - Foundation

1. Establish governance, private/task structures, documentation, and standards.
2. Select and record an exact Documenso Community Edition baseline.
3. Import upstream source with license and attribution intact.
4. Reproduce the upstream development and test workflow locally.

## Phase 2 - VASI Product Layer

1. Inventory supported branding/configuration surfaces.
2. Add approved CNB name, logos, colors, URLs, and email identity.
3. Review every signer-facing page and email for clear consent and status.
4. Add only the CNB-specific integrations required for internal use.

## Phase 3 - Deployment Engineering

1. Create generic Docker Compose templates for the public edge/auth gateway and
   internal-only VASI origin.
2. Inventory public staff, recipient, API, webhook, callback, static, and health
   routes; assign an explicit edge policy to each.
3. Restrict private-origin ingress to the edge and approved management paths.
4. Configure persistent PostgreSQL and document storage.
5. Configure SMTP, protected application secrets, and an X.509 certificate.
6. Decide whether to enable an RFC 3161 timestamp authority.
7. Implement health checks, monitoring, backup/restore, upgrade, and rollback.

## Phase 4 - Acceptance And Production

1. Complete synthetic end-to-end signing and audit tests.
2. Verify certificate validation and post-signing tamper detection.
3. Verify email delivery, TLS, authorization, retention, and secret hygiene.
4. Verify staff portal login, external recipient invitation access, forwarded
   client metadata, and failed direct-origin WAN access.
5. Restore a backup into an isolated environment.
6. Deploy to the privately designated production Docker hosts only after the
   acceptance checklist passes.
