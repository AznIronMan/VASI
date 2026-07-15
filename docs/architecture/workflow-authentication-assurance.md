# Workflow authentication assurance

Status: implemented in VASI 0.31.0.

## Decision

Authentication assurance is an immutable, provider-neutral workflow policy. A
company can require one or more verified VASI sign-in classes and can optionally
limit how old the authentication may be when a participant opens protected
content or records a material action. The private engine, not the browser or
identity gateway UI, makes the authorization decision.

The `vasi-workflow/v1` access contract contains:

```json
{
  "authentication": "verified_email",
  "authenticationAssurance": {
    "acceptedMethods": ["federated"],
    "maximumAgeSeconds": 900
  },
  "postCompletion": "receipt_only"
}
```

`acceptedMethods` is either the single value `any_verified` or a non-empty
subset of `federated`, `password`, and `email_verification`. The engine sorts
the set canonically. `maximumAgeSeconds` is `null`, or a whole number from 300
through 2,592,000 seconds. Omitting the new object preserves earlier behavior
as `any_verified` with no additional freshness limit.

The policy is bound to an immutable published workflow revision and copied into
the request at issuance. Provider names are observations, not policy keys. A
federated policy therefore works with any current or future connector whose
gateway session has exact federated provenance; it does not couple VASI engine
logic to Microsoft, Google, Yahoo, Zoho, Apple, or another identity product.

## Enforcement boundary

The V·Sign gateway sends the private engine a short-lived signed actor assertion
containing the exact gateway-session authentication method, provider when
available, authentication time, stable principal, verified email, and bounded
request context. It never forwards cookies, provider tokens, passwords, or
connector credentials.

For a request handle, the engine first performs normal intended-email and bound
principal authorization. Only then does it evaluate authentication assurance.
This ordering preserves the same `not_found` response for a different
participant and does not reveal that a request exists or which sign-in policy it
uses.

The engine evaluates the immutable policy before:

- opening an incomplete assignment or creating a new interaction session;
- saving or submitting an activity response;
- opening or streaming a PostgreSQL document artifact;
- opening external media or accepting its material telemetry batch.

A disallowed method fails with `authentication_method_not_allowed`; a missing,
invalid, future-skewed, or stale authentication time fails with
`reauthentication_required`. Failed evaluations do not create accepted evidence
events or mutate participant progress. Receipt and durable transaction-history
access remain governed by their existing authenticated participant and
retention controls, so an assurance challenge cannot make a completed record
disappear. Continuing access to original protected content still requires the
workflow assurance policy.

If a participant returns with a different gateway session, the engine closes
the prior incomplete interaction and creates a new session-bound interaction.
This makes a deliberate reauthentication visible in the evidence trail and
prevents a response from being attached to an obsolete browser session.

## Evidence and verification

Every accepted material event contains a bounded
`vasi-authentication-assurance-evaluation/v1` object. It records the canonical
policy, evaluation time, satisfied result, authentication method, optional
provider/provenance, optional authentication time, and calculated age when a
freshness limit applies. It deliberately excludes provider subjects, linked
accounts, tokens, cookies, credentials, and identity-provider claims not needed
for the decision.

Manifest `vasi-evidence-manifest/v10` adds
`vasi-authentication-assurance-evidence/v1`, which binds the immutable policy
and each accepted evaluation to its exact event ID and type. The portable
verifier:

- canonicalizes and compares the request, workflow-snapshot, and manifest
  policy;
- requires an evaluation for every participant open, response save/submission,
  document presentation/download, and media-telemetry event;
- recomputes each evaluation from the sealed event actor and server receipt
  time;
- rejects missing, duplicate, extra, unsatisfied, altered, or incorrectly
  bound evaluations.

Participant and plain-language reports summarize the accepted methods,
freshness limit, evaluation count, and latest accepted method/provider without
exposing provider subjects or forensic request context. Technical and structured
profiles retain the complete bounded evaluation objects already present in the
sealed record.

## User experience

The owner workflow builder defaults new workflows toward federated SSO and
offers explicit alternatives for SSO plus password, any verified method,
password only, or email verification only. It also accepts an optional freshness
window in minutes. The participant request disclosure states the bound method
and freshness requirement before an action.

When a session is stale or uses a disallowed method, the gateway preserves only
the safe reason code needed by the participant UI. The participant must choose
`Sign in again`; V·Sign signs out the current session and returns through the
normal SSO-first portal to the exact opaque request path. VASI does not silently
upgrade, guess, or relabel a password session as federated.

## Assurance limits

This control proves which VASI session properties the engine evaluated and
accepted at each recorded material event. It does not prove who physically
controlled the account, require an identity provider's MFA by itself, establish
legal enforceability, or replace a customer's identity-provider conditional
access policy. MFA, phishing resistance, account recovery, provider tenant
policy, independent security review, and legal/privacy approval remain pilot or
installation responsibilities.
