# Staff Authentication

VASI's initial Community Edition staff model uses two independent controls:

1. the public edge requires a CNB-managed OIDC session for every staff route;
2. VASI then requires its own account, session, role, object authorization, and
   optional native two-factor authentication.

The edge does not turn an OIDC email or group claim into a VASI role and does
not forward provider access or identity tokens to the application. This keeps
application authorization inside the supported Community code path and avoids
Documenso's separately licensed Organisation Authentication Portal.

## Provider Requirements

The chosen identity system must provide a stable HTTPS OIDC issuer, confidential
client credentials, authorization-code flow with PKCE, verified email claims,
MFA policy, account disablement, and an administrator-owned recovery process.
Register only the canonical VASI callback. Restrict the client to the approved
staff email domain/tenant and do not permit wildcard redirect URIs.

For Microsoft Entra, use the tenant-specific v2 issuer, a single-tenant web app,
the `preferred_username` ID-token claim as the edge email value, and Enterprise
Application assignment in addition to the CNB email-domain check. Disable
implicit grants and personal Microsoft accounts. Apply MFA through Conditional
Access and rotate the confidential client credential before expiry.

The generic edge contract pins
[OAuth2 Proxy v7.15.2](https://github.com/oauth2-proxy/oauth2-proxy/releases/tag/v7.15.2)
by image digest. It enables OIDC discovery, nonce verification, PKCE S256,
host-only secure cookies, and explicit trusted-proxy handling. Provider and
cookie secrets are mounted as files and never forwarded to VASI.

## Session And Deactivation Policy

The portal cookie lasts at most eight hours, is `Secure`, `HttpOnly`,
`SameSite=Lax`, and contains the minimum session data rather than provider
tokens. Staff still sign in to VASI and may enable VASI-native 2FA. A normal
deactivation disables both the identity-provider account and the VASI user.
Rotating the portal cookie secret invalidates every edge session during an
emergency; rotating the VASI session secret separately invalidates every VASI
session.

Staff logout must clear both sessions. After a successful native VASI sign-out,
the edge appends an expiry cookie for its OIDC portal session. The dedicated
edge logout endpoint can also clear only the portal cookie. Provider-global
logout is provider-specific and must be verified before production.

## First Administrator

Keep public signup disabled. The private-origin deployment includes a one-time,
fail-closed `bootstrap-admin` tool that:

- runs only from the protected tools profile;
- reads its database and bootstrap password from mounted files;
- refuses to run once any administrator exists or when the requested email is
  already present;
- creates one verified native administrator with a bcrypt-hashed password;
- does not seed sample data or silently create a second administrator.

The initial administrator signs in through the OIDC edge and VASI, changes the
bootstrap password, enables native 2FA, creates the real organisation, and then
removes the bootstrap password file. Later staff are created through the VASI
administrator workflow, receive only their intended VASI roles, and must also
be authorized by the OIDC provider.

## Recipient Separation

Recipient signing pages, token file routes, and the exact public recipient TRPC
procedures do not call OIDC. They remain protected by VASI's opaque invitation
token, configured recipient authentication, CSRF/origin checks, rate limits,
and object authorization. A sender may require recipient email-password,
passkey, access-code, or other supported verification without creating a CNB
staff identity.

The executable classification and generated pinned TRPC inventory live in the
[edge deployment contract](../../ops/deploy/edge/README.md). Unknown,
duplicate, mixed public/staff, and enterprise TRPC batches terminate at the edge.

## Production Gate

Before enabling the listener, verify provider MFA and deactivation, both logout
layers, session expiry, first-admin recovery, disabled-user rejection, native
role boundaries, recipient bypass, forwarded-address integrity, and direct
origin isolation. Preserve a private management recovery path, but do not add a
WAN bypass around the staff edge.
