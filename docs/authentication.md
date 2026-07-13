# Authentication setup

The VASI portal uses Better Auth with a PostgreSQL datastore. The canonical
production origin is `https://vsign.cnb.llc`; all provider applications and
email links must use that origin exactly.

## Identity provider callbacks

Register these HTTPS redirect URIs with the corresponding provider:

| Provider | Production callback |
| --- | --- |
| Microsoft Entra ID | `https://vsign.cnb.llc/api/auth/callback/microsoft` |
| Google | `https://vsign.cnb.llc/api/auth/callback/google` |
| Apple | `https://vsign.cnb.llc/api/auth/callback/apple` |
| Yahoo | `https://vsign.cnb.llc/api/auth/oauth2/callback/yahoo` |

Local callbacks use the same paths on `http://localhost:3000`.

### Microsoft

Create a web application registration in Microsoft Entra ID. `common` is the
default tenant, allowing organizational CNB accounts and external Microsoft
accounts. Set `MICROSOFT_TENANT_ID` to the CNB tenant ID later if policy should
restrict Microsoft sign-in to that tenant. Stable provider subject identifiers,
not mutable email addresses, remain the identity anchor.

### Google

Create a Web application OAuth client and add both local and production redirect
URIs. The portal requests only identity scopes. A Google Workspace hosted-domain
restriction can be added later for a CNB-only entry path without affecting
external signer accounts.

### Apple

Create an Apple Service ID for the web portal and register `cnb.llc` plus the
production return URL. Apple requires a signed client-secret JWT. VASI supports
either:

- `APPLE_CLIENT_SECRET`, which must be rotated before its maximum six-month
  expiry; or
- `APPLE_TEAM_ID`, `APPLE_KEY_ID`, and `APPLE_PRIVATE_KEY`, which generate a new
  180-day client secret at runtime.

Store the `.p8` private key in the deployment secret store. If it is represented
on one line, encode newlines as `\n`. Do not add the key file to the repository.

### Yahoo

Yahoo supports OpenID Connect and the authorization-code grant. Create a Yahoo
application, request the `openid`, `profile`, and `email` scopes, and register the
generic OAuth callback shown above. VASI uses Yahoo discovery metadata, a
database-backed OAuth state, and client-secret Basic authentication.

## Username and password

Registration collects a name, a public username, an email address, and a password
of 12 to 128 characters. Usernames allow letters, numbers, dots, underscores, and
hyphens. The public username-availability endpoint is disabled. Passwords are
stored only through Better Auth's scrypt password hashing; VASI never stores or
logs plaintext credentials.

Email verification is required before password sign-in. Verification and reset
links expire after one hour, and a completed password reset revokes the user's
other active sessions. Sign-in and recovery responses use generic language to
reduce account enumeration.

## Transactional email

Configure `AUTH_EMAIL_FROM` and `SMTP_HOST`. Add `SMTP_USER` and `SMTP_PASSWORD`
when the relay requires authentication; both must be set together. Use
`SMTP_SECURE=true` for implicit TLS, normally on port 465. The default is required
STARTTLS on port 587. Set `SMTP_REQUIRE_TLS=false` only for a trusted local relay.
Production must not launch until verification and reset delivery has been
exercised against the real sender domain.

## Security and release checklist

1. Set a unique `BETTER_AUTH_SECRET` of at least 32 random characters.
2. Use a dedicated PostgreSQL role and require TLS for remote database traffic.
3. Apply the tracked migration with `npm run auth:migrate` before application
   rollout; the migration runner verifies its checksum and is safe to repeat.
4. Keep the origin reachable only through the trusted HTTPS reverse proxy.
5. Confirm every provider callback and remove unused local callbacks from
   production provider registrations.
6. Back up the auth encryption secret before rollout; provider tokens are
   encrypted at rest and depend on this key.
7. Exercise registration, verification, recovery, sign-out, and session expiry.
8. Run `npm run check`, `npm run build`, and `npm audit` in CI.
9. Add MFA or passkeys before enabling high-impact staff administration or
   signing-policy changes.
