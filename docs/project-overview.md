# VASI Project Overview

## Purpose

VASI stands for **Verified Authorized Signing Infrastructure**. It is intended
to provide Clark & Burke LLC with a CNB-branded signing portal that can be
operated on company-managed infrastructure without per-document platform fees.

## Product Direction

VASI is planned as a maintained downstream deployment of Documenso Community
Edition, not a from-scratch signing engine. The project should preserve
upstream cryptographic signing and audit behavior while adding only the CNB
branding, configuration, integrations, and operational controls that are
actually required.

Planned capabilities include:

- Prepare and send documents for recipient action.
- Support signer, approver, viewer, and copy-recipient workflows available in
  the selected upstream baseline.
- Retain an audit trail for document and recipient activity.
- Seal completed PDFs with an X.509 signing certificate.
- Optionally attach trusted RFC 3161 timestamps.
- Operate through CNB-controlled Docker infrastructure, storage, SMTP, TLS,
  backup, and recovery procedures.
- Keep the signing application on an internal-only origin while a dedicated
  public CNB edge authenticates staff and proxies approved recipient traffic.

## Boundaries

- VASI is not legal advice and does not itself guarantee ESIGN, UETA, eIDAS, or
  industry-specific compliance.
- CNB branding must not weaken consent, identity, authentication, audit,
  certificate, or tamper-evidence behavior.
- Upstream enterprise-only features are out of scope unless separately licensed
  and explicitly approved.
- External recipients must be able to follow signing invitations without CNB
  staff accounts. Edge authentication policy must distinguish staff/admin
  access from token-bound recipient signing access.
- Real signing documents, recipient data, credentials, and private host details
  are never repository fixtures or public documentation examples.

## Current Milestone

The current milestone establishes only the repository skeleton. The next
milestone must select an exact Documenso release, verify its license and runtime
requirements, import it in an upgrade-friendly way, and prove an unbranded local
development run before VASI branding begins.

## Primary References

- [Documenso repository](https://github.com/documenso/documenso)
- [Documenso self-hosting requirements](https://docs.documenso.com/docs/self-hosting/getting-started/requirements)
- [Documenso signing certificates](https://docs.documenso.com/docs/concepts/signing-certificates)
- [Documenso signing workflow and audit trail](https://docs.documenso.com/docs/concepts/signing-workflow)
