# Data Lifecycle And Recovery

VASI's initial production profile stores source PDFs, completed PDFs, and
envelope attachments inside PostgreSQL. A database backup is therefore also the
document-storage backup, but it is not a complete VASI recovery by itself.

## Recovery Inventory

| Class | Primary location | Recovery requirement |
| --- | --- | --- |
| Users, roles, organisations, teams, and settings | PostgreSQL | Database dump plus matching application encryption keys |
| Native sessions, password/verification tokens, 2FA, passkeys, and API tokens | PostgreSQL | Database dump plus matching encryption keys; invalidate sessions after a suspected compromise |
| Source/completed PDFs and attachments | PostgreSQL `DocumentData` and attachment rows | Database dump sized for encoded binary data |
| Envelopes, recipients, fields, signatures, and audit facts | PostgreSQL | Same transactionally consistent database dump |
| Local job queue and results | PostgreSQL | Same dump; reconcile pending/processing work before enabling outbound effects |
| Session and application encryption keys | Protected runtime secret files | Separately encrypted, access-controlled recovery copy with tested custody |
| Database and SMTP credentials | Protected runtime secret files/provider | Provider-side reset plus protected recovery procedure; do not rely on database dumps |
| PDF-signing identity and passphrase | Separate protected secret files | Separately encrypted recovery copy and retained public chain for historical verification |
| Edge OIDC and cookie secrets | Protected edge secret files | Recreate/rotate through the identity provider and protected recovery store |
| Public/internal TLS keys | Ingress/origin protected stores | Reissue or restore under the applicable CA procedure |
| Images, Compose templates, and route inventories | Git plus immutable image records | Rebuild/redeploy exact reviewed release; no database dump dependency |
| Application/edge logs | Host logging system | Security/operations retention only; never a document system of record |

## Backup And Restore Gate

The provisioned PostgreSQL service takes scheduled custom-format dumps of every
connectable non-template database to protected off-host storage. Each backup has
a manifest, globals snapshot, and SHA-256 catalog; automation validates both
checksums and `pg_restore` catalogs and performs scheduled isolated restores.
The backup system must continue to show a non-empty `VASI.dump` in the latest
successful set.

For a VASI release gate:

1. Trigger or identify a fresh backup and validate its checksum/catalog.
2. Restore `VASI.dump` into a disposable `restorecheck_` database whose restored
   objects are owned by the intended VASI application role. The fixed-name,
   fail-before-promote helper `ops/recovery/restore-vasi-for-application.sh`
   creates `restorecheck_VASI_app` for this purpose; it never targets the live
   database.
3. Run `ops/recovery/verify-vasi-restore.sql`; it refuses a non-restore database,
   checks the pinned 163-migration state, required tables, safe aggregate row
   counts, encoded document/attachment presence, and an orphan check without
   printing document or identity data.
4. Start the exact release image against that isolated database with an
   isolated copy of the matching encryption/signing material. Disable outbound
   mail, callbacks, webhooks, and public ingress. Verify health, synthetic
   document access, audit history, signature validation, and job reconciliation.
5. Destroy the disposable runtime and database after preserving redacted result
   evidence. Never promote a restore-drill database over production directly.

The separately encrypted secret-recovery copy must be tested in this drill.
Unencrypted database dumps or a signing private key stored beside its
passphrase do not satisfy that requirement.

## Retention And Deletion Policy Gate

Before go-live, the business owner and legal reviewer must approve explicit
periods and legal-hold behavior for:

- drafts and abandoned uploads;
- completed documents, signatures, certificates, and audit evidence;
- recipient identity, authentication, access, and delivery metadata;
- user/security audit records and expired credentials;
- completed/failed job records and redacted operational logs; and
- online data, regular backups, archived backups, and secret-recovery copies.

Deletion must cover related encoded PDFs, attachments, recipients, signatures,
share links, and tokens without silently destroying records subject to a legal
hold. Backup expiry follows its own approved schedule; deletion from the live
database does not promise immediate removal from immutable or retained backups.
Test draft deletion, completed-document deletion/retention, account
deactivation, legal-hold blocking, export, and eventual backup expiry using only
synthetic data.

## RPO, RTO, And Observation

Record the scheduled backup interval as the maximum unreplicated-data window
only after accounting for failed or stale runs. Measure RTO from incident
declaration through secret recovery, database restore, application checks, edge
reconnection, and business approval—not only `pg_restore` duration. Production
acceptance requires approved RPO/RTO targets and alerts for backup age/failure,
checksum or restore failure, off-host capacity, signing/encryption material
expiry, and the age/result of the last full VASI application restore drill.
