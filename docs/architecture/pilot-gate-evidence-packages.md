# Pilot-gate evidence packages

Status: implemented in VASI 0.50.0 and extended through VASI 0.52.0.

## Purpose and boundary

VASI's tenant admission record stores an opaque evidence reference, reviewer
reference, and lowercase SHA-256 for each approved gate. The evidence itself
belongs in the installation's separately controlled review-record system. This
contract gives reviewers and installation administrators a deterministic,
offline way to index that evidence and derive the exact digest entered into
admission without uploading evidence to VASI.

Integrity packaging is not approval. A passing package proves only that the
canonical manifest is complete for its declared checklist and that the indexed
local files still match their byte counts and SHA-256 values. It does not prove
that a reviewer is independent or authorized, that an assessment is correct or
sufficient, that an exception is acceptable, or that a legal, security,
accessibility, custody, or customer decision has been made. The accountable
admission owner still decides the gate through the private admin workflow.

The tool has no network, database, settings, credential, archive-extraction, or
VASI API path. It never copies, uploads, parses, renders, interprets, signs, or
prints an evidence artifact. Its successful output contains only the gate ID,
artifact/checklist/exception counts, aggregate bytes, package digest, and
whether an independently supplied digest matched. Failures disclose one fixed
message.

## Exact checklist

The version 1 descriptor requires every item for exactly one of the eight
admission gates. Every item must reference at least one indexed artifact and
declare either `satisfied` or `accepted_exception`. An accepted exception also
requires a separately governed opaque exception reference; it is not treated
as evidence that the exception was appropriate.

| Gate ID | Required checklist items |
|---|---|
| `exact_release` | Source assurance; image assurance; build/test conformance; backup/settings/migrations; rollback readiness |
| `isolation_integrity` | First-party isolation/tamper; public/private/tenant scope; independent penetration assessment; finding disposition |
| `identity_delivery` | Approved identity providers; callback/origin policy; MFA or conditional access; authentication mail; tenant delivery path; recovery/support |
| `privacy_legal` | Notice/consent language; field/disclosure inventory; data-request process; retention/hold policy; jurisdiction analysis; electronic-act analysis |
| `accessibility` | Automated accessibility; keyboard; screen reader; zoom/reflow; motion/animation; media alternatives; supported browser/device review |
| `malware_content` | Content risk classification; scanner or trusted-source policy; external-media policy; content-owner acceptance; outage/retry policy |
| `recovery_custody` | Disposable recovery drill; RPO/RTO; encrypted off-host custody; key rotation/revocation; break glass; certificate/TSA/HSM decision |
| `capacity_support` | Pilot owner/users/scenarios; concurrency/volume limits; load evidence; alert/escalation; incident contacts; support hours; rollback/stop criteria |

The identifiers are a closed versioned contract, not free-form labels. An
artifact not referenced by any item, an unknown item, an omitted item, a
duplicate reference, or a noncanonical order fails closed.

## Private filesystem contract

Create three separate physical directories for the descriptor, evidence, and
output. Each directory must be canonical, owned by root or the invoking user,
and mode `0700`. Descriptor, artifact, and manifest files must be physical
regular single-link files owned by root or the invoking user and mode `0600`.
Symlinks, hardlinks, subdirectories, extra evidence-directory entries,
noncanonical paths, output overlap, and files that change while read are
rejected.

Evidence and generated manifests contain review metadata and must remain
outside the VASI release tree. They must not be committed, copied into an image,
placed under the runtime `data/` directory, or stored in a public web root. The
descriptor and evidence directories must remain outside the VASI release tree
as well. Use the installation's approved encrypted review-record custody and
access policy.

The evidence directory contains exactly the files indexed by the descriptor.
Version 1 allows 1–64 nonempty artifacts, at most 16 MiB each and 128 MiB in
aggregate. Supported media/extension pairs are JSON/`.json`, PDF/`.pdf`,
ZIP/`.zip`, CSV/`.csv`, HTML/`.html`, Markdown/`.md`, and plain text/`.txt`.
Filenames are one-level ASCII names of at most 128 characters. Traversal,
hidden names, and names suggesting credentials, environment files, settings,
private material, secrets, or tokens are rejected. These restrictions reduce
accidental collection; an administrator must still inspect and classify the
artifacts before custody.

## Canonical descriptor

The descriptor is strict UTF-8 canonical JSON ending in one newline. References
are opaque identifiers of at most 160 characters using only letters, digits,
period, underscore, colon, and hyphen; URLs and narrative text are not accepted.
`reviewedAt` is an exact UTC ISO timestamp supplied by the review process. Keep
customer facts, credentials, contact details, findings, and prose in the
separately controlled artifacts, not in identifiers.

This sanitized exact-release example indexes one JSON result:

```json
{
  "artifacts": [
    {
      "id": "release_review",
      "mediaType": "application/json",
      "path": "release-review.json"
    }
  ],
  "checklist": [
    {
      "artifactIds": [
        "release_review"
      ],
      "exceptionReference": null,
      "id": "source_assurance",
      "outcome": "satisfied"
    },
    {
      "artifactIds": [
        "release_review"
      ],
      "exceptionReference": null,
      "id": "image_assurance",
      "outcome": "satisfied"
    },
    {
      "artifactIds": [
        "release_review"
      ],
      "exceptionReference": null,
      "id": "build_test_conformance",
      "outcome": "satisfied"
    },
    {
      "artifactIds": [
        "release_review"
      ],
      "exceptionReference": null,
      "id": "backup_settings_migrations",
      "outcome": "satisfied"
    },
    {
      "artifactIds": [
        "release_review"
      ],
      "exceptionReference": null,
      "id": "rollback_readiness",
      "outcome": "satisfied"
    }
  ],
  "evidenceReference": "review-package:release-001",
  "gateId": "exact_release",
  "reviewedAt": "2026-07-15T20:00:00.000Z",
  "reviewerReference": "reviewer:release-owner-001",
  "schema": "vasi-pilot-gate-evidence-descriptor/v1",
  "scopeReference": "scope:release-001"
}
```

Generate canonical descriptor bytes with the exported library helper when a
review system constructs descriptors programmatically. Hand-edited key order,
indentation, line endings, or trailing whitespace is intentionally rejected.

## Create and verify

Run creation on the controlled review system. The output manifest must not
already exist:

```bash
npm run pilot:evidence -- create DESCRIPTOR_FILE EVIDENCE_DIRECTORY OUTPUT_MANIFEST
```

Creation validates the descriptor, exact directory inventory, permissions,
ownership, link count, stable metadata, byte limits, and every artifact digest.
It adds only byte counts, digests, fixed limitations, and the canonical
`vasi-pilot-gate-evidence-manifest/v1` schema. `packageDigest` is SHA-256 over
the canonical manifest fields excluding `packageDigest` itself. The generated
manifest is a new mode-`0600` file and is read back through the same physical
file boundary before success.

Transfer the unchanged manifest and separately controlled evidence directory to
the reviewer through the approved custody path. When possible, communicate the
expected package digest through a separate authenticated channel. Verify
offline:

```bash
npm run pilot:evidence -- verify MANIFEST_FILE EVIDENCE_DIRECTORY
npm run pilot:evidence -- verify MANIFEST_FILE EVIDENCE_DIRECTORY \
  --expected-sha256 LOWERCASE_SHA256
```

Verification requires exact canonical manifest bytes, recomputes the package
digest, re-inventories the directory, and recomputes every artifact. A changed
artifact, filename, checklist assertion, limitation, digest, expected digest,
permission, link, directory entry, or presentation fails. Recreating from the
same canonical descriptor and unchanged artifacts produces the same manifest
bytes and digest.

## Admission and readiness handoff

After the responsible reviewer and accountable owner complete their external
workflow, open the selected gate in the private tenant admission console and
choose the canonical manifest. The browser does not upload the manifest. It
reads at most 1 MiB into browser memory, requires strict UTF-8 and exact
canonical JSON, validates the shared closed schema and checklist, requires the
manifest gate to match the selected gate, and recomputes `packageDigest` with
the browser's SHA-256 implementation. The local verifier returns only aggregate
counts, review time, and these three admission values:

- `reviewerReference` from the manifest;
- `evidenceReference` from the manifest; and
- `evidenceDigest` equal to the manifest `packageDigest`.

Those values populate the existing editable fields; the administrator must
still choose **Record immutable approval**. Manually changing a populated field
clears the local-verification status. Only the three fields above enter the
existing admission API request. The file input has no submitted name, the
manifest is not retained in component state or sent to the server, and artifact
paths, identifiers, hashes, checklist details, exception references, scope
reference, and manifest filename are not returned by the verifier.

Browser handoff verifies the manifest contract and package digest only. It
does not re-read or verify the indexed artifact files, their permissions,
directory inventory, physical-file identity, or custody. Run the offline CLI
verification against the separately controlled artifact directory before the
accountable gate decision. The console states this limitation beside the file
control and never presents local verification as gate approval.

The console creates the immutable gate decision and server decision time. It
does not ingest or verify the evidence directory. Export a new signed readiness
dossier after all decisions. VASI 0.52.0 supplies a separate offline verifier
that requires exactly one canonical manifest for every gate and compares all
eight reviewer references, evidence references, and package digests with the
signed admitted dossier without uploading or printing them:

```bash
npm run pilot:admission:verify -- DOSSIER_FILE MANIFEST_DIRECTORY \
  --expected-key-fingerprint LOWERCASE_SHA256
```

That final verifier confirms package-to-dossier binding, a shared review scope,
and review/decision/export time ordering. Its explicit
`artifactVerification: "not_performed"` result means it does not replace the
earlier per-package artifact verification. Preserve the descriptor, manifest,
artifacts, separately communicated digest, review
decision, readiness dossier, and custody history under the installation's
retention and legal-hold policy.

See [Tenant production admission](tenant-production-admission.md),
[Pilot readiness dossier](pilot-readiness-dossier.md),
[Pilot-admission evidence verification](pilot-admission-evidence-verification.md), and
[Assurance and pilot readiness](../assurance-and-pilot-readiness.md).
