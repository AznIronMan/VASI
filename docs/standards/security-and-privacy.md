# Security And Privacy Standard

## Prohibited Repository Content

- Production documents, completed PDFs, signature images, recipient lists, and
  audit exports.
- Private keys, signing certificates, certificate passwords, TLS keys,
  application/encryption secrets, database credentials, SMTP credentials,
  access codes, tokens, cookies, or production `.env` files.
- Private host details, live database URLs, raw logs, dumps, and backups.

## Required Engineering Practices

- Use least privilege and deny-by-default authorization.
- Validate input and authorization on the server, not only in the browser.
- Keep secrets out of URLs, frontend bundles, logs, exception text, analytics,
  and screenshots.
- Pin production images/dependencies and review upstream security changes.
- Protect administrative and recipient sessions with secure cookie/token
  settings appropriate to the selected upstream baseline.
- Make destructive document/account operations explicit, authorized, audited,
  and recoverable where policy requires.
- Treat webhooks and integrations as authenticated, replay-aware trust
  boundaries.

## Production Release Evidence

Before production, retain secret-free evidence that TLS, access control, signing,
certificate validation, audit generation, SMTP delivery, health checks,
backup/restore, upgrades, rollback, and tamper detection were tested. Evidence
must use synthetic identifiers and must not expose live secrets or documents.
