# Transactional Email Delivery

VASI's supported production mail path is Azure Communication Services Email
over authenticated SMTP. This keeps the pinned application's ordinary
username/password SMTP interface while the provider links that SMTP username
to a Microsoft Entra application. VASI does not rely on Exchange Online basic
SMTP client submission.

## Provider Boundary

An authorized Azure operator must provision and connect:

- an Azure Communication Services resource;
- an Email Communication Services resource and verified sending domain;
- a single-purpose Microsoft Entra application with the minimum Communication
  Services role required for email submission;
- an SMTP username linked to that application; and
- a client secret used only as the SMTP password.

The tracked repository contains none of the resulting tenant IDs, resource
names, SMTP usernames, client secrets, or DNS verification tokens. Record those
only in the protected operator system and `.private` notes where necessary.

## Required Runtime Profile

| Setting | Required value |
| --- | --- |
| Host | `smtp.azurecomm.net` |
| Port | `587` |
| Implicit TLS (`secure`) | `false` |
| Mandatory STARTTLS (`requireTLS`) | `true` |
| Ignore TLS | `false` |
| Username | Mounted ACS SMTP username |
| Password | Mounted Entra application client secret |
| Sender | Address in the verified sending domain |

Port 587 begins as SMTP and must upgrade with STARTTLS. In Nodemailer,
`secure=false` selects that mode; it does not mean plaintext delivery.
`requireTLS=true` makes the connection fail if the server does not offer the
upgrade, and normal certificate/hostname validation remains enabled.

## Verification

After provisioning the two SMTP secret files, validate authentication and TLS
without sending mail:

```sh
docker compose --env-file /protected/vasi-origin.env --profile tools run --rm smtp-probe
```

Set `VASI_SMTP_PROBE_TO` to an approved synthetic test mailbox to submit a
content-free delivery probe:

```sh
VASI_SMTP_PROBE_TO=operator-test@example.com \
  docker compose --env-file /protected/vasi-origin.env --profile tools run --rm smtp-probe
```

The probe never prints credentials, sender/recipient addresses, or provider
message IDs. Provider acceptance is not the full delivery gate: inspect the
received headers and verify SPF, DKIM, DMARC alignment, display name, sender,
canonical links, junk classification, and reply behavior. Then exercise real
synthetic invitation, reminder, completion, and authentication messages through
the application.

## Rotation And Failure Handling

Create a replacement client secret before the current secret expires, stage the
new mounted password, run the probe, restart the application, verify delivery,
and only then revoke the old secret. Treat repeated authentication failures,
provider rejection, queue failures, or stale delivery evidence as operational
alerts. Logs must identify the failure class without recording recipients,
document names, invitation tokens, message bodies, usernames, or credentials.

Provider setup reference: [Azure Communication Services SMTP authentication](https://learn.microsoft.com/en-us/azure/communication-services/quickstarts/email/send-email-smtp/smtp-authentication).
