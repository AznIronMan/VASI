# Tenant production admission

Status: implemented in VASI 0.25.0 and extended through VASI 0.51.0.

## Purpose

VASI distinguishes a technically runnable tenant from a tenant approved for
production work. Provisioning creates an active company workspace so owners can
prepare profiles, workflows, retention policy, documents, and disabled
integrations. It does not authorize VASI to issue participant requests or
contact an outbound provider.

Production admission is derived only when all eight required gates are
approved:

1. exact release;
2. isolation and integrity;
3. identity and delivery;
4. privacy and legal;
5. accessibility;
6. malware and content safety;
7. recovery and custody; and
8. capacity and support.

The gate names are a versioned product contract. A client cannot omit a gate,
add a substitute, or assert the aggregate `admitted` state.

## Immutable record

Migration `0015_engine_tenant_admission` adds an immutable revision table and a
single active pointer per tenant. A revision contains the exact ordered gate
set, derived aggregate state, and—only for an approved gate—these bounded
fields:

- an opaque reviewer reference;
- an opaque evidence reference;
- a lowercase SHA-256 digest of the reviewed evidence; and
- the server-recorded UTC decision time.

The API accepts one gate decision at a time with an expected revision. Only an
installation administrator can write it. Approval creates a new immutable
revision; revocation creates another revision whose selected gate is pending
and whose prior approval fields are absent. The tenant configuration hash chain
records the actor, gate, previous and resulting aggregate state, revision, and
admission fingerprint. A stale expected revision fails with no partial write.

Reviewer and evidence references allow letters, digits, period, underscore,
colon, and hyphen. VASI deliberately rejects URLs, uploaded approval files,
credentials, and unrestricted narrative notes in this control plane. The
underlying reviewed package remains in the installation's approved records
system; its digest makes later substitution detectable.

VASI 0.50.0 provides a deterministic offline package for that separately
controlled evidence. It enforces the complete gate-specific checklist, indexes
only strict local artifacts, derives the exact admission digest, and verifies
the package again without network or VASI access. Packaging proves file
integrity and checklist completeness, not review sufficiency or approval. See
[Pilot-gate evidence packages](pilot-gate-evidence-packages.md).

VASI 0.51.0 lets an administrator select that canonical manifest in the
private console. A bounded browser-local verifier shares the offline contract,
requires the selected gate and exact package digest to match, and populates
only the existing opaque reviewer/evidence references and digest. It never
uploads or retains the manifest and cannot record the decision automatically.
Artifact-byte and custody verification remain the offline review system's
responsibility.

## Fail-closed enforcement

Admission is checked at more than the user interface:

- The private engine takes a shared lock on the active admission pointer before
  request issuance and before an active integration revision is created.
- PostgreSQL rejects every new request unless it contains the exact current
  admitted revision ID, canonical snapshot, and hash. It also rejects an active
  integration revision for a tenant that is not currently admitted.
- The integration gateway locks and validates the current admission revision,
  canonical hash, adapter revision, and installation destination immediately
  before delivery or document scanning. A queued notification discovered after
  revocation is recorded as suppressed with `tenant_not_admitted`; no provider
  connection is opened.
- Disabled bindings, workflow preparation, record review, participant data
  rights, retention processing, and request revocation remain available while
  admission is pending. Revoking a gate alone blocks new production expansion.
  The atomic production-stop command described below also ends every
  non-terminal participant request when existing access must end.

## Atomic tenant production stop

Migration `0016_engine_tenant_production_stop` extends the immutable
configuration event contract with `tenant.production.stopped` and a unique
command-ID index. The administrator supplies an expected admission revision,
the gate to revoke, a fixed reason code, and an opaque incident reference.
URLs, credentials, and narrative case notes are rejected.

The private engine takes a transaction-scoped advisory command lock and an
exclusive admission-pointer lock before it locks request rows. The same
transaction then:

1. creates and selects a pending admission revision when the chosen gate was
   approved;
2. changes every scheduled, issued, or in-progress request and assignment to
   `revoked`;
3. suppresses pending invitation and reminder jobs and redacts their payloads;
4. appends a `request.revoked` event to every affected assignment evidence
   chain and one matching immutable lifecycle event per request; and
5. appends a hash-chained tenant event with counts, hashes, reason code, opaque
   reference, actor, and resulting revision.

Any error rolls the complete transaction back. Reusing the command ID fails.
Reissue follows the admission-before-request lock order, preventing a
simultaneous reissue from deadlocking with or escaping a stop. New issuance and
outbound provider work fail closed as soon as the pending admission commits.
Provider work that completed before the stop obtained the exclusive admission
lock cannot be recalled and remains part of the audit record.

Completed and expired requests are terminal and are not rewritten. Their
sealed evidence, participant history, retention schedule, and legal holds
remain available under existing policy. Recovery is deliberate: an
administrator records fresh evidence for the selected admission gate, and an
owner issues new requests. A stopped request is never silently reopened.

The database triggers also keep a rollback to an admission-unaware release
fail closed: that release can review historical records but cannot insert a new
request without the admission snapshot required by migration `0015`.

A request issued before migration `0015` has no admission snapshot. If it is
completed after the upgrade, VASI preserves the prior version 8 evidence
contract instead of misrepresenting it as admission-bound version 9 evidence.
It remains verifiable under that earlier contract; only a request created while
the current tenant revision is admitted can produce a version 9 manifest.

## Evidence binding

Every newly issued request retains the admitted revision ID, complete canonical
snapshot, hash, and `issued` binding provenance. The scheduled-or-issued event
contains the same object. Workflow manifest `vasi-evidence-manifest/v9`
introduced this binding; current manifest `vasi-evidence-manifest/v10` carries
it alongside requester provenance, authentication assurance, tenant profile,
workflow, activity, browser context, notification delivery, and outcome
evidence.

PostgreSQL rejects any later change to the request's issuance-time admission or
tenant-profile revision, snapshot, hash, or provenance fields. Normal request
status and completion transitions remain writable; their identity and policy
bindings do not.

The offline verifier independently:

- validates the exact gate set and derives the aggregate state;
- requires all gates to be approved;
- recomputes the admission hash;
- validates the revision and issuance provenance; and
- compares the manifest admission object with the immutable issuance event.

Participant and plain-language reports show only admitted state, gate count,
revision, and admission fingerprint. Technical and structured reports retain
the complete sealed record. An admission record proves which approvals VASI
bound at issuance; it does not replace or create the underlying legal,
security, accessibility, recovery, custody, or pilot opinions.

## Administration and operations

The internal admin console lists every company tenant and all eight gates. An
administrator can record or replace an approval, or revoke it after an explicit
confirmation. The panel displays the immutable revision, actor, time, and
fingerprint without exposing secrets. It also exposes a separately confirmed
production stop and shows the last bounded stop outcome and configuration-event
fingerprint. VASI 0.45.0 adds machine JSON and printable human readiness
dossiers from the same panel. Export is an audited administrative mutation
because observing and releasing configuration evidence is security-relevant;
the dossier packages recorded state but cannot approve a gate. See
[Pilot readiness dossier](pilot-readiness-dossier.md).

The evidence-package manifest and artifacts remain outside the VASI release and
database. The console can read the canonical manifest locally to populate its
form, but the server receives only the opaque references and package digest.

The privacy-safe operational snapshot reports active, admitted, disabled, and
pending-admission tenant counts. Any active tenant without a current admitted
revision produces `tenants_pending_admission` attention. The snapshot remains
aggregate and contains no tenant ID, reviewer reference, evidence reference,
participant identity, request ID, content, or credential.

## Upgrade and transfer

New and existing tenants start pending after migration `0015`; no tenant is silently
grandfathered. Before enabling production traffic, an administrator records
dated evidence for every gate in the internal console. Encrypted tenant export
and import include admission revisions and the active pointer before request
rows, preserving foreign keys and historical issuance snapshots.

The authenticated importer uses a transaction-local `vasi.tenant_import`
marker while restoring that immutable history. For a historical request, the
database still requires the archived revision to belong to the same tenant and
requires its admitted snapshot and fingerprint to match exactly, but does not
require that historical revision to be the tenant's current pointer. The marker
also permits archived active integration revisions to be restored without
rewriting their state. It exists only for the import transaction: normal writes
still require the current admitted pointer, and the integration gateway checks
that pointer again before every outbound operation. A destination whose
current imported pointer is pending therefore remains unable to issue or
deliver production work.

For rollback, stop issuance and delivery, retain migrations `0015` and `0016`,
and run the verified prior release only for read/recovery operations. Returning
to normal production issuance with the atomic stop contract requires VASI
0.26.0 or later. Do not remove the admission triggers, stop-command index, or
immutable history to make an older binary write.
