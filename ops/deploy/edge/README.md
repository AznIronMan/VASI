# Staff Authentication Edge

This public-safe contract places a deny-by-default VASI gateway and a pinned
OAuth2 Proxy OIDC client on the private edge host. The outer ingress remains the
public TLS endpoint. The gateway accepts traffic only from the configured outer
ingress CIDR and connects to the VASI origin with mandatory CA and hostname
verification.

Staff routes require both an OIDC edge session and the normal VASI application
session/role checks. The gateway deliberately does not forward OAuth identity or
access tokens as VASI authorization. Recipient token routes and the exact public
authentication/TRPC calls bypass staff OIDC but still rely on VASI's token,
credential, CSRF, origin, object-authorization, and rate-limit checks.

## Identity Policy

Register one confidential OIDC client with callback
`https://sign.example.test/oauth2/callback`. Use a provider tenant/domain that
enforces CNB staff lifecycle and MFA. The initial session policy is a host-only
`Secure`, `HttpOnly`, `SameSite=Lax` cookie with an eight-hour maximum and no
background token refresh, allowing the cookie to omit provider tokens.
Deactivating staff requires disabling the identity-provider account and the
corresponding VASI user; rotate the edge cookie secret to revoke every portal
session during an emergency. The edge is an additional gate, not role mapping.
On a successful native VASI sign-out response, the gateway also expires its
host-only portal cookie.

For Microsoft Entra, use the single-tenant v2 issuer, set
`VASI_OIDC_EMAIL_CLAIM=preferred_username`, require assignment to the Enterprise
Application, and apply the tenant's MFA/Conditional Access policy. Do not use
the multi-tenant `common` issuer or permit personal Microsoft accounts.

OAuth2 Proxy is pinned to `v7.15.2` and its published image digest. Its client
secret file contains exactly the provider secret with no trailing newline. Its
cookie-secret file is exactly 32 random binary bytes. Docker Compose file-backed
secrets retain host ownership, so both files must be numeric UID/GID
`65532:65532`, mode `0400`, inside a root-only directory.

## Build And Validate

Copy `deployment.env.example` to a protected file outside Git and use a unique
VASI commit tag for `VASI_EDGE_IMAGE`:

```sh
docker compose --env-file /protected/vasi-edge.env config --quiet
docker compose --env-file /protected/vasi-edge.env build gateway
```

The production gateway image intentionally contains the policy source and
generated procedure inventory but not the test file. From the repository root,
verify that the inventory still matches the pinned TypeScript router and run
the policy suite before building:

```sh
node scripts/generate-edge-trpc-inventory.mjs --check
node --test ops/deploy/edge/gateway/policy.test.mjs
```

## Stage And Verify

Do not replace the maintenance listener until the OIDC registration, full route
matrix, origin firewall, and synthetic staff/recipient tests pass. Start on an
unused private bind during staging, then verify:

- anonymous staff pages redirect to `/oauth2/start` while staff APIs return
  `401` without an HTML redirect;
- authenticated staff still need a valid VASI login and receive only their VASI
  roles;
- recipient token pages and exact public TRPC batches bypass staff OIDC;
- mixed/duplicate/enterprise TRPC batches and unknown routes return locally;
- forged forwarding headers, wrong Host/Origin values, WebSockets, oversized
  bodies, and untrusted source addresses fail;
- upstream TLS uses the approved internal CA/name, and application cookies and
  redirects never name an internal or fallback host.

The public `/healthz` response is content-free and does not contact the origin.
The loopback-only `/readyz` used by the container health check requires both the
OIDC proxy and verified origin health. Rollback is the prior edge image or the
content-free maintenance placeholder; never run two projects on the same bind
address and port.
