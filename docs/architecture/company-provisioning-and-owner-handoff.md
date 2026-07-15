# Company provisioning and owner handoff

Status: implemented in VASI 0.27.0.

## Purpose and boundary

First-company creation is an installation-administrator operation on the
private admin origin. The public login origin does not expose provisioning, and
the private VASI engine remains unreachable from participant networks. The
gateway authenticates and authorizes the administrator, validates a strict
bounded command, and translates the session into the existing short-lived
actor assertion.

The supported command contains only:

- a normalized company name;
- a lowercase stable identifier;
- the verified-email address to receive the initial `owner` grant; and
- an explicit choice whether to send a V·Sign login invitation.

Unknown fields, unsafe control characters, malformed identifiers, invalid
email domains, missing invitation choice, wrong admin host, missing session,
non-administrator role, and invalid mutation origin fail before provisioning.

## Durable engine transaction

```mermaid
sequenceDiagram
  participant A as Installation administrator
  participant G as Private admin gateway
  participant E as Private VASI engine
  participant D as Engine PostgreSQL
  participant I as Identity invitation service

  A->>G: Company, identifier, owner email, invite choice
  G->>G: Host, session, role, origin, and command validation
  G->>E: mTLS plus signed actor assertion
  E->>D: Begin provisioning transaction
  E->>D: Company and administrator owner membership
  E->>D: Requested owner-email grant
  E->>D: Profile, disabled integrations, pending admission
  E->>D: Hash-chained configuration events
  E->>D: Commit
  E-->>G: Durable company and owner-grant outcome
  opt Invitation requested for a different identity
    G->>I: Create and deliver login invitation
    I-->>G: Sent, existing account, or delivery failure
  end
  G-->>A: Company result plus separate invitation status
```

The engine either commits every company-bound record or rolls the transaction
back. The creating administrator receives an engine-owned tenant `owner`
membership so the company can be configured. When the requested owner email is
different, the same transaction creates an active owner grant. On that user's
next authenticated company listing, the engine claims the grant against the
stable identity principal. An identity `admin` role never grants implicit
cross-tenant workflow or evidence access.

Every new company starts with disabled notification and malware-scanning
bindings and a pending production-admission revision. Provisioning permits
configuration work only. Request issuance and active outbound integration
bindings remain blocked until all eight assurance gates are approved.

## Invitation outcome and recovery

Identity invitation delivery occurs after the engine commit because the
identity and engine databases are intentionally separate authorities and email
cannot participate in the engine PostgreSQL transaction. The response uses one
of five bounded outcomes:

| Outcome | Meaning | Operator action |
| --- | --- | --- |
| `sent` | The durable owner grant exists and a seven-day login invitation was sent | Wait for owner sign-in |
| `existing_account` | The owner already has a V·Sign account | Ask the owner to sign in; the engine claims the grant |
| `not_required` | The creating administrator is the requested owner | Continue in the company control plane |
| `skipped` | The operator explicitly declined invitation delivery | Share the approved login path separately |
| `delivery_failed` | The company and owner grant committed, but invitation delivery failed | Do not recreate the company; retry only the identity invitation |

Provider acceptance or SMTP success still does not prove inbox delivery,
receipt, reading, identity, or attention. Invitation tokens remain single-use,
expire after seven days, and are stored only as SHA-256 digests. A failed
delivery revokes its invitation record and produces the existing value-free
administrator audit event.

## User interfaces and compatibility

The main internal `/admin` console presents company provisioning before the
assurance-gate panel. After success it refreshes the admission list, labels the
company production-pending, and links the authorized administrator to the
company control plane. Mail failure is displayed as a recoverable partial
success rather than a failed tenant transaction.

The `/admin/evidence` first-slice screen remains available for compatibility,
but it now collects the initial owner email and delegates creation to the same
supported route. Deployment and health verification never create a real
company; a named pilot owner and approved admission evidence are required
before production work begins.
