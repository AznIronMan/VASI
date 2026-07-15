# Authentication setup

The VASI portal uses Better Auth with a PostgreSQL datastore. The canonical
public production origin is installation-specific; examples below use `https://vsign.example.com`. A separately configured
private HTTPS origin serves the internal administration console. Sessions are
host-only and are not shared between the public and internal hosts.

Authenticated company roles use the private owner control plane to configure
workflows and requests. VASI 0.7.0 also lets roles with `artifact.read` inspect
authorized document revisions, while only `artifact.manage` roles can upload or
publish them; the engine enforces both permissions independently of the UI.

## Runtime settings

VASI does not read application configuration from environment files. The local,
untracked `data/VASI.settings` SQLite database is the bootstrap boundary. It
contains only:

- a random installation identifier;
- the PostgreSQL connection URL, verified-TLS selection, and pool limit; and
- a random 256-bit key used to decrypt runtime settings in PostgreSQL.

All settings named in this document—including origins, allowlists, identity
provider clients, auth secrets, mail credentials, and private-engine client
trust—are encrypted with AES-256-GCM in `vasi_runtime_setting`. Encryption binds
each value to its installation, scope, and name.
`vasi_runtime_setting_audit` records set/unset operations without recording
values. Gateway settings use the `gateway` scope. The separately deployed
engine has its own bootstrap and uses the `engine` scope.

Initialize a source deployment with `npm run settings:init`, or a container
deployment with:

```bash
install -d -m 700 data
docker compose -f compose.production.yaml --profile tools run --rm --build settings init
```

Use `npm run settings -- set SETTING_NAME` or the Compose `settings` tool to
change one value through hidden terminal input. `settings list` reveals only
configured names, versions, and secret classifications. Restart the app after
changing a setting because each process intentionally loads one consistent
settings snapshot.

Private-engine settings are managed only from its deployment. Its Compose tool
selects the `engine` scope automatically; a source command must explicitly use
`node scripts/settings.mjs --scope engine ...`. Never point the gateway and
engine at the same bootstrap database.

`VASI.settings` is mode `0600`, ignored by Git, excluded from the container
build context, and mounted read-only into the app. Back it up securely together
with PostgreSQL. Neither half is independently sufficient for recovery.

Public gateway branding is installation configuration rather than source code.
The sanitized defaults are VASI/V·Sign and `support@example.invalid`. Set these
non-secret gateway values for a deployment, then restart the gateway:

- `BRAND_ORGANIZATION_NAME`
- `BRAND_PRODUCT_NAME`
- `BRAND_PRODUCT_MARK`
- `BRAND_SUPPORT_EMAIL`

The public `/api/brand` endpoint returns only those presentation values so
client-rendered marks can match server email/auth branding. It never returns
provider configuration, origins, allowlists, or secrets. Company-specific
branding within evidence is governed separately by the engine tenant profile
and is snapshot-bound at request issuance.

## Identity provider callbacks

Register these HTTPS redirect URIs with the corresponding provider:

| Provider | Public callback | Internal callback path |
| --- | --- | --- |
| Microsoft Entra ID | `https://vsign.example.com/api/auth/callback/microsoft` | `/api/auth/callback/microsoft` |
| Google | `https://vsign.example.com/api/auth/callback/google` | `/api/auth/callback/google` |
| Apple | `https://vsign.example.com/api/auth/callback/apple` | `/api/auth/callback/apple` |
| Yahoo | `https://vsign.example.com/api/auth/oauth2/callback/yahoo` | `/api/auth/oauth2/callback/yahoo` |
| Zoho | `https://vsign.example.com/api/auth/oauth2/callback/zoho` | `/api/auth/oauth2/callback/zoho` |

Prefix each internal callback path with the exact `VASI_ADMIN_ORIGIN` and
register it with the provider before enabling that provider for internal admin
sign-in. Better Auth validates both allowed hosts and trusted origins before
constructing a host-specific callback.

Local callbacks use the same paths on `http://localhost:3000`.

### Microsoft

Create a web application registration in Microsoft Entra ID. `common` is the
default tenant, allowing organizational accounts and external Microsoft
accounts. Set `MICROSOFT_TENANT_ID` to an organization tenant ID if policy should
restrict Microsoft sign-in to that tenant. Stable provider subject identifiers,
not mutable email addresses, remain the identity anchor.

### Google

Create a Web application OAuth client and add both local and production redirect
URIs. The portal requests only identity scopes. A Google Workspace hosted-domain
restriction can be added later for an organization-only entry path without affecting
external signer accounts.

### Apple

Create an Apple Service ID for the web portal and register the installation domain plus the
production return URL. Apple requires a signed client-secret JWT. VASI supports
either:

- `APPLE_CLIENT_SECRET`, which must be rotated before its maximum six-month
  expiry; or
- `APPLE_TEAM_ID`, `APPLE_KEY_ID`, and `APPLE_PRIVATE_KEY`, which generate a new
  180-day client secret at runtime.

Store the `.p8` private-key value through the VASI settings tool. If it is
represented on one line, encode newlines as `\n`. Do not add the key file to the
repository or keep it as a runtime file.
Apple is excluded from public login and onboarding by default while Developer
Program approval is pending. Set `APPLE_LOGIN_ENABLED=true` only after the
Service ID, callback, signing key, and Private Email Relay configuration have
been approved and verified. The dormant Apple integration and admin connector
status remain available while the public option is hidden.

### Yahoo

Yahoo supports OpenID Connect and the authorization-code grant. Create a Yahoo
application, request the `openid`, `profile`, and `email` scopes, and register the
generic OAuth callback shown above. VASI uses Yahoo discovery metadata, a
database-backed OAuth state, and client-secret Basic authentication.

### Zoho

Create a server-based application in the Zoho API Console for the same data
center as the intended accounts and register the generic OAuth callback shown
above. Configure `ZOHO_CLIENT_ID`, `ZOHO_CLIENT_SECRET`, and the matching
`ZOHO_ACCOUNTS_ORIGIN`; the origin defaults to `https://accounts.zoho.com` for
the United States data center. VASI uses that origin's OIDC discovery metadata,
requests only `openid`, `profile`, and `email`, and uses the stable subject claim
as the connector identity. Review Zoho's multi-data-center requirements before
accepting accounts homed outside the configured application data center.

## Username and password

Registration starts with an email address. Common consumer domains map directly
to Microsoft, Google, Apple, Yahoo, or Zoho. Provider visibility is then applied
to the recommendation, so iCloud-family addresses are not presented with Apple
while `APPLE_LOGIN_ENABLED` is false. For custom domains, VASI performs a bounded
DNS MX lookup and recognizes Microsoft 365, Google Workspace, and known Zoho
Mail infrastructure. This lookup describes a domain's likely identity provider
and never checks whether a user account exists.

When a configured provider is found, its SSO action is the primary choice. On
sign-in, username/password and password recovery are hidden initially under an
accessible `Other methods` disclosure. Registration keeps the manual-password
action keyboard-accessible but visually secondary. If selected, registration
collects a name, a public username, and a password of 12 to 128 characters.
Usernames allow letters, numbers, dots, underscores, and hyphens. The public
username-availability endpoint is disabled. Passwords are stored only through
Better Auth's password hashing; VASI never stores or logs plaintext credentials.

Email verification is required before password sign-in. Verification and reset
links expire after one hour, and a completed password reset revokes the user's
other active sessions. Sign-in and recovery responses use generic language to
reduce account enumeration.

An opaque evidence request path under `/r/` is preserved through social sign-in,
manual registration, and email verification. The return value is accepted only
when it exactly matches the fixed high-entropy request-path shape; arbitrary or
external callback destinations are rejected. Link possession selects a request
but does not authorize it. The private engine separately requires the intended
verified email and binds first access to the stable V·Sign principal.

On an authorized request page, VASI records separately labeled server-observed
request headers and fixed browser-reported context at presentation and before a
save/submission. The browser contract is limited to locale/time zone,
viewport/screen, touch, basic storage/cookie/PDF capabilities, accessibility
preferences, online state, and coarse connection values when exposed. It does
not enumerate plugins/fonts, create canvas/WebGL/audio fingerprints, request
precise location, capture hidden media, or retain keys, input contents, pointer
coordinates, credentials, or tokens. Collection failure never prevents the
participant from responding.

## Internal identity administration

Configure the private console with:

- `VASI_ADMIN_ORIGIN`, an exact HTTPS origin with no path; and
- `VASI_ADMIN_EMAILS`, a comma-separated allowlist of operator email addresses.

Set both values through the VASI settings tool.

The `/admin` page, custom admin APIs, and Better Auth admin endpoints return 404
on every other hostname. On the internal hostname they additionally require an
authenticated `admin` role and an allowlisted email. State-changing routes also
require an exact `Origin` header. The public and internal hosts retain separate
host-only sessions.

For each user, the console shows Microsoft, Google, Apple, Yahoo, and Zoho connectors:

- green: connected, configured, and authenticated within 90 days;
- yellow: connected but not authenticated for more than 90 days;
- red: a stored connection whose provider is unavailable or whose link is
  invalid; and
- gray: not connected.

Connector health uses a dedicated last-authenticated timestamp with bounded
provenance. Only the post-create hook of a completed session attributed to the
exact supported provider account advances it. Password and email-verification
sessions, token refreshes, ordinary provider-account updates, unsupported
providers, and unattributed sessions cannot make a connector appear recently
used. The migration prefers the latest exact historical session attribution;
when none exists, the prior account-update time is retained only as a clearly
labeled legacy activity estimate until the next successful provider sign-in.
That estimate remains in the red/unknown state and is not represented as
verified authentication in either the light or connector description.

Force disconnect removes the local V·Sign account link and revokes every
V·Sign session for that user; it does not delete the external provider account.
V·Sign refuses to remove the user's final working sign-in method.

The username/password checkbox controls the credential account. Enabling it
creates a random, unknown bootstrap credential and immediately emails the user
a one-hour password setup link. Disabling it removes the credential and revokes
sessions, but only when a configured SSO connector remains. Reset password is
available only while the credential account is enabled.

Disabling a user uses Better Auth's administrative ban operation, prevents new
sign-in, and revokes existing sessions. Invitations expire after seven days,
store only a SHA-256 token digest, and are single-use. Administrative changes
are recorded in `vasi_admin_audit`; audit metadata never contains invitation
tokens, provider tokens, credentials, or message bodies.

The main `/admin` console is the supported company-provisioning surface. It
requires an initial owner email and reports the durable private-engine owner
grant independently from the optional V·Sign login invitation. The
browser preserves one UUID command for an unchanged retry. The private engine
returns the exact committed company for that command, and the identity service
binds any requested invitation to it. Confirmed provider acceptance replays
without another email; a provider/receipt crash window is reported as
`delivery_unknown` and never redelivered automatically. The
UUID and a SHA-256 digest of normalized form choices may persist in per-tab
session storage for at most 24 hours so a reload can recover an ambiguous
result. Company and owner fields are never stored there; corrupt or extended
state is removed. The
`/admin/evidence` first-slice console remains a compatibility adapter for
issuing the narrow terms/response transaction and delegates company creation to
the same supported provisioning route. The engine creates a separate tenant
membership and enforces it for every issue and record query.
Identity-administrator status is used only to bootstrap that membership; it is
not treated as cross-tenant evidence authorization. The
`/owner` control plane accepts any active, verified account on the private
origin, then relies exclusively on engine-owned company roles. An identity
`admin` role alone grants no workflow, request, or evidence access.

For the sealed slice, V·Sign signs and forwards bounded engine context from the
authenticated session: stable principal and session IDs, verified email, the
session-specific authentication method/provider/subject and capture provenance,
separately labeled linked-provider context, authentication time, roles, and
available gateway-observed IP headers, user agent, language, and browser client hints.
These fields are contextual evidence with stated provenance. VASI does not
collect raw keystrokes, browser plugin inventories, hidden camera/microphone
data, or invasive device fingerprints, and does not claim that a user agent or
duration proves comprehension.

## Transactional email

Microsoft Graph is the preferred transport for Microsoft 365. Create a
dedicated, single-tenant app registration for the mailer and configure:

- `AUTH_EMAIL_PROVIDER=graph`
- `GRAPH_TENANT_ID`
- `GRAPH_CLIENT_ID`
- `GRAPH_CLIENT_SECRET`
- `GRAPH_SENDER_EMAIL`

Use [Exchange Online RBAC for Applications](https://learn.microsoft.com/exchange/permissions-exo/application-rbac)
to assign the `Application Mail.Send` role to that service principal with a
management scope that matches only the sender mailbox. Do not also grant an
unscoped `Mail.Send` application permission in Entra; Entra permissions and
Exchange RBAC assignments are additive, so that would defeat the mailbox scope.
Validate both an in-scope and an out-of-scope mailbox with
`Test-ServicePrincipalAuthorization`.

SMTP remains available as a fallback. Set `AUTH_EMAIL_PROVIDER=smtp`, then
configure `AUTH_EMAIL_FROM` and `SMTP_HOST`. Add `SMTP_USER` and `SMTP_PASSWORD`
when the relay requires authentication; both must be set together. Use
`SMTP_SECURE=true` for implicit TLS, normally on port 465. The default is
required STARTTLS on port 587. Set `SMTP_REQUIRE_TLS=false` only for a trusted
local relay.

Production must not launch until verification and reset delivery has been
exercised against the real sender domain. Graph secrets and SMTP credentials
must be entered through hidden settings-tool input and remain encrypted in
PostgreSQL.

## Security and release checklist

1. Initialize a unique `VASI.settings`; the initializer generates a
   `BETTER_AUTH_SECRET` longer than 32 characters and stores it encrypted in
   PostgreSQL.
2. Use a dedicated PostgreSQL role. Select verified PostgreSQL TLS during
   bootstrap for remote database traffic. Disable it only over a trusted private
   or loopback path when that PostgreSQL service does not offer TLS.
3. Apply the tracked migration with `npm run db:migrate` before application
   rollout, or run the production migrator service with `--build`; the command
   in the production-container section is safe to repeat and verifies every
   migration checksum.
4. Keep the origin reachable only through the trusted HTTPS reverse proxy.
5. Confirm every provider callback and remove unused local callbacks from
   production provider registrations.
6. Back up `VASI.settings` and PostgreSQL as a matched recovery set. Protect the
   auth secret and bootstrap settings key; encrypted provider tokens and runtime
   settings depend on them.
7. Exercise registration, verification, recovery, sign-out, and session expiry.
8. For Graph email, confirm the mailer is authorized for the sender mailbox and
   denied for a second mailbox outside its Exchange management scope.
9. Run `npm run check`, `npm run build`, and `npm audit` in CI.
10. Require MFA at the operator's identity provider before granting internal
    administration access, and keep the internal hostname off public ingress.
11. Confirm `/admin` and `/api/admin/*` return 404 on the public hostname and
    require an allowlisted administrator on the private hostname.
12. Confirm `VASI.settings` is mode `0600`, absent from the image and repository,
    and that the running app has no application secrets in its environment.
13. If the private engine is configured, run `npm run engine:probe`, confirm the
    replay attempt is rejected, and confirm engine and worker publish no host
    ports. Verify `/api/admin/engine` is 404 on the public host and requires an
    allowlisted administrator on the private host.
