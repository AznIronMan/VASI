# Security And Privacy

VASI will process confidential documents, personal information, signatures,
audit events, and cryptographic key material. Security and privacy are release
requirements, not optional production cleanup.

## Required Posture

- Serve all public traffic through HTTPS.
- Expose only the edge/auth gateway to the WAN; keep the VASI application
  origin private and firewall it to approved edge/management sources.
- Keep PostgreSQL and supporting services on private Docker/internal networks.
- Separate staff portal authentication from recipient signing-link policy.
  Recipient links must retain upstream token and configured recipient
  authentication without requiring a CNB staff account.
- Trust `Forwarded`/`X-Forwarded-*` metadata only from the known edge and use it
  consistently for secure redirects, cookies, rate limits, and audit events.
- Mount secrets at runtime; never bake them into images or commit them.
- Use the supported `_FILE` mounts and fail-closed production configuration
  validation; do not duplicate mounted values as inline environment variables.
- Encrypt and access-control backups, then test restoration on a schedule.
- Restrict administrative access and use least-privilege database/service
  accounts.
- Keep logs free of document bodies, signature images, credentials, access
  codes, tokens, and cryptographic secrets.
- Define retention and deletion policy for documents, audit records, mail data,
  logs, and backups before production use.
- Apply supported upstream security updates promptly after testing.

The [production configuration contract](operator/configuration.md) defines the
current secret boundary, disabled integrations, encryption-key recovery limits,
and rotation requirements. The [staff authentication guide](operator/staff-authentication.md)
defines the independent OIDC and native VASI session/authorization layers.

## Signing Certificate

Documenso uses an X.509 certificate to seal completed PDFs. A self-signed
certificate can provide tamper evidence, but PDF readers will not automatically
trust its issuer. Production certificate choice must account for relying-party
trust expectations, issuance cost, expiry, rotation, revocation, password/key
protection, backup, and disaster recovery.

Trusted timestamping is a separate decision. If RFC 3161 timestamping is
enabled, validate the timestamp authority, authentication material, failure
behavior, renewal policy, and long-term verification expectations.

## Safe Development Data

Use generated PDFs and fictitious people at reserved domains such as
`example.com`. Never copy production agreements, signatures, audit trails,
recipient emails, IP addresses, access codes, database rows, or backups into
source, issue text, task files, screenshots, or test fixtures.

## Compliance Language

Technical controls can support enforceability and compliance, but legal effect
depends on jurisdiction, workflow, identity assurance, consent, retention, and
the documents involved. Public material must not state that VASI deployment
alone guarantees compliance. Obtain qualified legal advice for production use.
