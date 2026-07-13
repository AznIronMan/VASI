# Transactional Email Delivery

VASI's supported production mail path is Microsoft Graph using OAuth 2.0
client credentials. A dedicated, single-tenant Microsoft Entra application may
send only as the approved transactional mailbox. The application does not use a
mailbox password, delegated user session, SMTP AUTH, or a WAN-exposed mail
service.

## Authorization Boundary

Create a separate Entra application for VASI mail. Do not reuse the staff-login
application. The mail application needs no redirect URI and its client secret
must be mounted only on the private origin.

Use Exchange Online Application RBAC to grant the `Application Mail.Send` role
through a management scope containing only the transactional mailbox. Do not
also grant the Entra `Mail.Send` application API permission: Entra grants and
Exchange Application RBAC grants are additive, so an unscoped Entra grant would
defeat the mailbox restriction.

When registering the service principal in Exchange, use the enterprise
application/service-principal object ID, not the app-registration object ID.
The following example uses reserved addresses and names:

```powershell
Connect-ExchangeOnline

New-ServicePrincipal `
  -AppId '<application-client-id>' `
  -ObjectId '<enterprise-application-object-id>' `
  -DisplayName 'VASI Transactional Mail'

New-ManagementScope `
  -Name 'VASI Transactional Mailbox' `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'signing@example.test'"

New-ManagementRoleAssignment `
  -Name 'VASI Transactional Mail Send' `
  -App '<enterprise-application-object-id>' `
  -Role 'Application Mail.Send' `
  -CustomResourceScope 'VASI Transactional Mailbox'
```

Verify both the intended mailbox and an explicit control mailbox. The first
result must have `InScope=True`; the second must have `InScope=False`:

```powershell
Test-ServicePrincipalAuthorization `
  -Identity '<enterprise-application-object-id>' `
  -Resource 'signing@example.test'

Test-ServicePrincipalAuthorization `
  -Identity '<enterprise-application-object-id>' `
  -Resource 'control@example.test'
```

Exchange authorization changes can take time to reach normal API caches even
when `Test-ServicePrincipalAuthorization` already reports the new assignment.

## Runtime Profile

| Setting       | Required value                                        |
| ------------- | ----------------------------------------------------- |
| Transport     | `microsoft-graph`                                     |
| OAuth grant   | Client credentials                                    |
| OAuth scope   | `https://graph.microsoft.com/.default`                |
| Tenant ID     | Dedicated tenant UUID                                 |
| Client ID     | Dedicated VASI mail application UUID                  |
| Client secret | File-mounted application credential                   |
| Sender        | The single Exchange RBAC-scoped mailbox               |
| Graph action  | `POST /v1.0/users/{sender}/sendMail` with base64 MIME |

The transport obtains and caches an app-only access token, renders the normal
Nodemailer message as MIME, and submits it through Graph. A message is rejected
locally if its From address differs from the configured mailbox. Provider error
bodies, access tokens, credentials, and recipient addresses are not included in
transport errors.

Microsoft Graph write requests have a 4 MB request limit. Because MIME is
base64-encoded in the request body, VASI currently fails closed when the raw
message exceeds 3,000,000 bytes. Completion emails can include signed PDFs;
production acceptance must therefore test the maximum approved document set
and either keep the resulting message below this boundary or implement a
separately reviewed large-attachment workflow.

## Verification

Validate app-only token acquisition without sending mail:

```sh
docker compose --env-file /protected/vasi-origin.env \
  --profile tools run --rm graph-mail-probe
```

Set `VASI_GRAPH_MAIL_PROBE_TO` to an approved synthetic test mailbox to submit
a content-free delivery probe:

```sh
VASI_GRAPH_MAIL_PROBE_TO=operator-test@example.test \
  docker compose --env-file /protected/vasi-origin.env \
  --profile tools run --rm graph-mail-probe
```

The probe reports only token or provider acceptance status. It does not print
credentials, tokens, sender/recipient addresses, response bodies, or provider
message IDs. Also attempt a probe with an out-of-scope sender and require HTTP
403 before accepting the authorization boundary.

Provider acceptance is not the full delivery gate. Inspect the received
headers and verify SPF, DKIM, DMARC alignment, display name, sender, canonical
links, junk classification, and reply behavior. Then exercise synthetic
invitation, reminder, completion-with-attachment, and authentication messages
through the application.

## Rotation And Failure Handling

Create a replacement client secret before the current secret expires, stage the
new mounted file, run the probe, restart the application, verify delivery, and
only then revoke the old credential. Re-run both in-scope and out-of-scope tests
after any app, Exchange role, scope, or mailbox-address change.

Treat repeated token failures, HTTP 401/403/413/429 responses, provider
rejection, queue failures, or stale delivery evidence as operational alerts.
Logs must identify the failure class without recording recipients, document
names, invitation tokens, message bodies, tenant/client IDs, or credentials.

Primary references:

- [Microsoft Graph app-only authentication](https://learn.microsoft.com/en-us/graph/auth-v2-service)
- [Microsoft Graph sendMail](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0)
- [Exchange Online Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [Microsoft Graph API request limits](https://learn.microsoft.com/en-us/graph/use-the-api)
