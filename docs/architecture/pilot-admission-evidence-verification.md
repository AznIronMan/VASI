# Pilot-admission evidence verification

Status: implemented in VASI 0.52.0 and extended in VASI 0.53.0.

## Purpose

The immutable tenant-admission record and the separately controlled
pilot-gate packages have complementary integrity boundaries. Each gate package
proves its canonical checklist and indexed artifact digests; the signed
readiness dossier proves the engine's current admission revision. This offline
verifier closes the final handoff by proving that one technically admitted,
signed dossier contains the exact reviewer reference, evidence reference, and
package digest from exactly one canonical manifest for every admission gate.
VASI 0.53.0 adds an optional complete-set mode that also re-inventories and
hashes every underlying artifact in all eight packages during the same
offline run. The original manifest-only mode remains available and continues
to state explicitly that it did not inspect artifact bytes.

This is a binding and optional byte-integrity check, not another approval. Even
complete-set verification does not parse or assess artifact contents, approve
a checklist assertion or exception, identify or authorize a reviewer,
establish certificate-chain or timestamp trust, or provide a security,
accessibility, legal, privacy, custody, capacity, or support opinion. Keep the
accountable external decisions separate.

## Private input contract

Place the eight unchanged manifests in one dedicated physical directory whose
owner is root or the invoking user and whose mode is `0700`. The directory must
contain exactly these mode-`0600`, single-link physical regular files:

- `exact_release.json`
- `isolation_integrity.json`
- `identity_delivery.json`
- `privacy_legal.json`
- `accessibility.json`
- `malware_content.json`
- `recovery_custody.json`
- `capacity_support.json`

The signed JSON or HTML readiness dossier must be a separate mode-`0600`,
single-link physical file in a mode-`0700` physical directory. Inputs may be
owned by root or the invoking user. Final symlinks, hardlinks, permissive modes,
extra or missing manifest entries, nested dossier overlap, unstable reads, and
noncanonical paths fail closed. Keep the dossier, manifests, artifacts, and
review records outside the VASI release tree, images, runtime `data/`
directory, and public web roots under the installation's approved encrypted
review-record custody.

For complete-set verification, create a third separate mode-`0700` physical
artifact root. It must contain exactly eight physical mode-`0700` directories,
named `exact_release`, `isolation_integrity`, `identity_delivery`,
`privacy_legal`, `accessibility`, `malware_content`, `recovery_custody`, and
`capacity_support`. Each directory must contain exactly the mode-`0600`
physical artifact files indexed by its same-named manifest. The root,
manifests, and dossier may not overlap. Symlinked directories, nested or extra
entries, and gate substitution fail closed.

## Verification contract

The verifier has no network, API, database, settings, credential, or signing
path. It reuses the product's existing strict dossier verifier, pilot-gate
manifest validator, and per-gate physical artifact verifier rather than
interpreting those formats independently. Verification always requires:

1. an exact JSON or byte-reproducible script-free HTML dossier no larger than
   2 MiB, using the signed `vasi-tenant-readiness-export/v2` schema with a valid
   VASI integrity signature;
2. an `admitted` current revision in which all eight immutable gates are
   approved;
3. exactly eight canonical manifests, each no larger than 1 MiB and bound to
   the gate named by its fixed filename;
4. an exact match for every gate's manifest `packageDigest`,
   `evidenceReference`, and `reviewerReference` in the signed dossier;
5. one consistent opaque `scopeReference` across all eight manifests; and
6. review time no later than the immutable gate decision, gate decisions no
   later than the admission revision, and the admission revision no later than
   dossier capture.

When `--artifact-root` is supplied, it additionally requires the exact
eight-directory inventory, then applies each manifest to its matching gate
directory and recomputes every underlying artifact byte count and SHA-256. The
existing 1–64 artifact, 16 MiB per-artifact, and 128 MiB per-package bounds
remain authoritative. The complete set is therefore bounded to at most 512
artifacts and 1 GiB. Every directory and file is rechecked for canonical
physical identity, ownership, mode, link count, exact inventory, stable
metadata, and digest before success.

An independently obtained dossier SHA-256 and VASI integrity-key fingerprint
can be required. The fingerprint must come through a separately authenticated
channel, not from the dossier or the same transfer.

## Offline use

The compatible two-input command verifies the signed dossier and manifests but
does not open artifact directories:

```bash
npm run pilot:admission:verify -- DOSSIER_FILE MANIFEST_DIRECTORY
```

For the strongest final handoff, place each unchanged artifact set under its
fixed gate directory and run complete-set verification:

```bash
npm run pilot:admission:verify -- DOSSIER_FILE MANIFEST_DIRECTORY \
  --artifact-root ARTIFACT_DIRECTORY_ROOT \
  --expected-sha256 LOWERCASE_SHA256 \
  --expected-key-fingerprint LOWERCASE_SHA256
```

Manifest-only success preserves the fixed
`vasi-pilot-admission-evidence-verification/v1` schema and explicit
`artifactVerification: "not_performed"` limitation. Complete-set success uses
`vasi-pilot-admission-evidence-verification/v2`, reports
`artifactVerification: "matched"`, and adds only aggregate artifact count and
bytes. Both schemas report only dossier digest and public integrity-key
fingerprint, format/presentation and seal states, eight-package count,
independently pinned-value results, and scope/time/binding states. Neither
prints tenant, gate, artifact, filename, reviewer, evidence, scope, exception,
path, certificate-subject, or approval content. Every failure emits one
generic message without parsed facts or input paths.

Preserve the signed dossier and all eight verified packages with their
separately authenticated expected digests, external decisions, custody
history, and underlying artifacts. An investigator still needs those records,
the tenant audit chain, applicable trust policy, and domain-specific review to
reach a substantive conclusion.

See [Pilot-gate evidence packages](pilot-gate-evidence-packages.md),
[Pilot readiness dossier](pilot-readiness-dossier.md), and
[Tenant production admission](tenant-production-admission.md).
