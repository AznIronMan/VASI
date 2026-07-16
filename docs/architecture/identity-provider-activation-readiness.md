# Identity-provider activation readiness

Status: implemented in VASI 0.54.0.

VASI treats absence of an optional identity provider differently from a
partially configured provider. Absence is an ordinary installation choice. A
partial credential tuple, invalid visibility flag, or unsupported issuer
origin is an activation error and must fail before the authentication runtime
starts.

One framework-independent contract owns Microsoft, Google, Apple, Yahoo, and
Zoho provider IDs, labels, callback paths, credential completeness, public
visibility, and readiness classification. The gateway authentication runtime,
settings validator, login availability, per-user connector health, and private
administrator readiness panel all consume that contract.

## States

Each provider has a separate configuration and public-visibility result:

- `ready`: the exact credential tuple is present;
- `required`: no credential tuple is present;
- `invalid`: a tuple is partial or another provider invariant is violated;
- `visible`: the provider can appear on the public login surface; and
- `hidden`: Apple is deliberately excluded while its activation flag is false.

The administrator panel combines these into `ready`, `hidden`,
`configuration_required`, or `invalid`. It shows only the label, state, and
derived public/private callback URLs. It never receives a client ID, client
secret, Apple private key, provider token, or discovery response.

Microsoft, Google, Yahoo, and Zoho require their client ID and client secret
together. Apple requires a client ID plus either a complete signed client
secret or the complete team ID, key ID, and private key generation tuple. If
any field from an unused Apple generation route is stored, that route must also
be complete. `APPLE_LOGIN_ENABLED` accepts only `true` or `false`, and `true`
requires a complete Apple credential route.

## Callback and issuer boundary

Callback paths are fixed by the authentication adapter:

| Provider | Callback path |
| --- | --- |
| Microsoft | `/api/auth/callback/microsoft` |
| Google | `/api/auth/callback/google` |
| Apple | `/api/auth/callback/apple` |
| Yahoo | `/api/auth/oauth2/callback/yahoo` |
| Zoho | `/api/auth/oauth2/callback/zoho` |

The panel derives one callback from the exact public origin and one from the
exact private administrator origin. An origin containing credentials, a path,
query, or fragment is rejected. Provider-console registration remains an
external action; VASI cannot prove registration merely by deriving the correct
URL.

Zoho discovery is restricted to the HTTPS account origins documented for its
US, EU, India, Australia, Japan, Canada, Saudi Arabia, and United Kingdom data
centers. Arbitrary HTTPS issuers, paths, credentials, queries, fragments, and
unencrypted origins are rejected before discovery or client authentication.
The canonical list comes from Zoho's
[Multi-DC OAuth documentation](https://www.zoho.com/accounts/protocol/oauth/multi-dc.html).
An installation that serves more than one Zoho data center must also enable
the corresponding Multi-DC policy in the Zoho API Console; VASI's structural
check does not grant that provider-side capability.

## Activation workflow

1. Register both exact callbacks at the provider when the private console will
   also use that provider.
2. Store a complete tuple through the protected settings tool. Secret values
   use hidden input and never appear in listing or validation output.
3. Run `npm run settings -- validate`. A partial tuple or invalid provider
   boundary exits nonzero before service restart.
4. Restart the gateway, inspect **Sign-in providers / Activation readiness** on
   the private console, and perform a real login on each intended origin.
5. Retain provider-console approval and end-to-end test evidence outside the
   source repository under the installation's approved evidence custody.

Readiness proves local structural consistency and callback derivation. It does
not prove that a provider recognizes the client, a secret is current, consent
is approved, MFA or account recovery satisfies policy, the callback was
registered, or an end-to-end login succeeds. Those are deliberate
provider/operator activation gates.
