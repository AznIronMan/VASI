# Pilot readiness dossier

VASI 0.45.0 provides a portable, administrator-only snapshot for accountable
pilot review. It converts the product's existing installation profile, tenant
profile, admission gates, integration bindings, capacity counters, and latest
production-stop record into two representations:

- machine-readable JSON for review tools and LLM-assisted analysis; and
- a printable, script-free HTML report for technical and non-technical people.

Both representations carry the SHA-256 of the same canonical dossier object.
The HTML representation embeds the exact export wrapper and a separate exact
dossier copy as inert `application/json`; neither block is executable.
VASI 0.48.0 adds a signed export attestation over the dossier digest,
immutable export-event hash, capture time, format, schema, and exact signing
key identities. Every new export carries the configured Ed25519 VASI integrity
seal and also carries the configured optional certificate seal.
The export is a handoff artifact, not a new approval system. It does not certify
VASI, provide legal advice, establish evidence sufficiency, or replace an
independent reviewer.

## Boundary and authorization

The browser calls `POST /api/admin/product/tenant-readiness-exports` only on the
internal administrator origin. The route uses the same authenticated
administrator, canonical-host, origin, and mutation controls as other internal
configuration changes. It sends a short-lived actor assertion across the mTLS
private-ingress boundary to the unexposed engine action
`POST /v1/admin/tenant-readiness-exports`. The command accepts only one tenant
UUID and the explicit format `json` or `html`.

The engine requires the installation `admin` role before opening a database
connection. Owners, participants, public callers, and service identities other
than the private ingress cannot invoke the action. The gateway marks both
formats `no-store`, `nosniff`, attachment-only, referrer-free, and sandboxed.
HTML also contains a restrictive CSP meta policy, escaped text, no executable
script, and an inert copy of the exact dossier JSON.

## Repeatable snapshot

The engine opens one PostgreSQL transaction at repeatable-read isolation. That
transaction observes a consistent set of:

1. the exact running engine release and active installation profile revision;
2. the selected tenant identity, status, profile revision, retention profile,
   quota limits, and current quota use;
3. the active admission revision and every gate's bounded reviewer reference,
   evidence reference, evidence digest, state, and decision time;
4. active integration capability, adapter identity and version, status,
   revision, creation time, and configuration hash; and
5. the latest production-stop reason, accountable gate, effects, result,
   timestamp, and immutable event hash, when one exists.

The dossier derives approved and pending gate lists and reports VASI's current
technical admission state. `externalReviewRequired` is always true and the
classification is always `recorded_evidence_not_certification`.

The engine hashes canonical VASI JSON for the dossier, then appends a
`tenant.readiness.exported` event to the tenant's immutable configuration chain.
The event binds the dossier hash, requested format, admission hash/revision,
installation and tenant profile hashes/revisions, signed export schema, and
public signing-key IDs, roles, and fingerprints. Its actor and event hash
make the disclosure attributable without putting the operator identifier in
the portable file. The export wrapper returns that audit-event hash alongside
the dossier hash and capture time. After the event exists, the engine creates a
strict `vasi-tenant-readiness-attestation/v1` record and signs it through the
same replaceable signing provider used for VASI evidence. A signing failure
rolls the export transaction back rather than returning an unsigned new-format
file.

The dossier hash by itself does not cover the wrapper's capture time, requested
format, or audit-event hash. Consequently, JSON and HTML created from unchanged
readiness facts retain the same dossier hash while each disclosure still has a
new immutable audit event. The signed attestation covers those wrapper facts
and the signing-key fingerprints. It is still not a trusted timestamp, proof
of certificate-chain trust or revocation, or proof that a referenced review
was correct.

## Deliberate privacy boundary

The export includes enough state to verify which technical configuration and
approvals were presented to reviewers. It deliberately excludes:

- integration credentials, encrypted envelopes, credential fingerprints, and
  raw configuration;
- SMTP hosts, webhook URLs, scanner hosts, Microsoft tenant/client identifiers,
  sender addresses, and all allowlist values;
- installation and tenant support addresses or other personal contact data;
- production-stop command IDs, incident references, and operator identifiers;
  and
- participant, request, workflow, document, response, authentication, browser,
  network, and evidence-record content.

Only allowlist entry counts and configuration hashes are exported. A dossier
should still be handled as internal company information because it names the
tenant, exposes usage and quota facts, identifies enabled adapter types, and
contains bounded reviewer/evidence references.

## Offline verification and use

The JSON format is the authoritative portable representation. The HTML report
embeds the exact export wrapper plus the same dossier object as inert
`application/json` data and prints its expected hash. VASI ships a
framework-independent offline verifier:

```bash
# On the trusted engine host, from its selected VASI release:
npm run readiness:trust-anchor

# On the independent review system:
npm run readiness:verify -- DOSSIER_FILE
npm run readiness:verify -- DOSSIER_FILE --expected-sha256 LOWERCASE_SHA256
npm run readiness:verify -- DOSSIER_FILE \
  --expected-sha256 LOWERCASE_SHA256 \
  --expected-key-fingerprint LOWERCASE_SHA256
```

After all eight gate decisions are approved, VASI 0.52.0 can also verify the
complete package-to-dossier handoff offline. Place exactly one canonical
manifest per gate in the private fixed-name directory and run:

```bash
npm run pilot:admission:verify -- DOSSIER_FILE MANIFEST_DIRECTORY \
  --expected-sha256 LOWERCASE_SHA256 \
  --expected-key-fingerprint LOWERCASE_SHA256
```

The admission verifier reuses this dossier verifier, requires a signed admitted
revision, and compares every immutable reviewer reference, evidence reference,
and digest with the eight manifests. It does not reverify the indexed artifact
bytes; see [Pilot-admission evidence verification](pilot-admission-evidence-verification.md).

VASI 0.53.0 can reverify those bytes in the same final run when the separately
controlled packages are available under the exact eight-directory root:

```bash
npm run pilot:admission:verify -- DOSSIER_FILE MANIFEST_DIRECTORY \
  --artifact-root ARTIFACT_DIRECTORY_ROOT \
  --expected-key-fingerprint LOWERCASE_SHA256
```

The complete-set result remains aggregate-only and does not interpret the
artifacts or substitute for the accountable reviews.

The engine-host command reads the protected installation settings and emits a
fixed privacy-safe aggregate containing the configured integrity key ID,
algorithm, fingerprint, and seal profile plus the equivalent bounded
certificate record when configured. It does not emit a public JWK, certificate
chain or subject, private material, settings, tenant facts, or database
location. Give the integrity fingerprint to the reviewer through a separately
authenticated operations channel; do not treat a fingerprint copied from the
dossier or delivered beside it as an independent trust anchor.

The verifier opens one physical regular file without following a final
symlink, accepts no more than 2 MiB of strict UTF-8, and recognizes only the
exact JSON or script-free HTML export. It requires the complete wrapper and
dossier schemas, all eight admission gates, internally consistent admission,
readiness, quota, usage, adapter, and production-stop bindings, and the exact
fixed interpretation limitations. It recomputes canonical VASI JSON SHA-256.
For HTML it reconstructs the report with the same shared renderer and requires
byte-for-byte equality, so a visible wording/style edit, added executable
element, changed or duplicate embedding, or covered-data edit fails.

For signed `vasi-tenant-readiness-export/v2` files, the verifier additionally
requires one exact VASI integrity signing-key record and seal, permits at most
one matching certificate key and seal, recomputes every public-key fingerprint,
and verifies every signature over the exact attestation. A key ID, role,
fingerprint, public JWK, certificate metadata, certificate chain, event hash,
capture time, format, schema, signature, or attestation change fails. The
certificate check proves the leaf certificate signature and public-key match;
it deliberately does not claim chain trust, policy acceptance, revocation
status, trusted time, or legal identity.

Successful output uses only the fixed
`vasi-readiness-dossier-verification/v2` aggregate schema, input format,
presentation status, dossier digest, integrity-key fingerprint, seal presence
and verification states, and whether independently supplied dossier and key
fingerprints matched. It never prints tenant, reviewer, evidence, integration,
certificate-subject, or approval content. A failure emits one generic message
and no parsed facts.

Signature verification with only the embedded public key proves integrity but
does not establish who controls that key. Obtain the installation's integrity
key fingerprint through an independently controlled channel and supply
`--expected-key-fingerprint`; a match then binds the export to that expected
VASI signing identity. `--expected-sha256` independently pins the dossier
facts. Neither option establishes trusted time, certificate policy, legal
sufficiency, or gate approval. To prove configuration-chain inclusion, an
authorized investigator must additionally compare the signed audit-event hash
with the tenant configuration chain inside the installation.

The verifier retains compatibility with exact 0.47.0
`vasi-tenant-readiness-export/v1` JSON and HTML. Those files return
`integritySeal: not_present` and a null integrity-key fingerprint; supplying an
expected key fingerprint for a legacy file fails. Legacy compatibility never
upgrades an unsigned disclosure into signed evidence.

Use the dossier as the cover sheet for the gate owners listed in
[Assurance and pilot readiness](../assurance-and-pilot-readiness.md). The
referenced assessment packages remain separately controlled; do not place
credentials, narrative case notes, URLs, or approval documents into admission
reference fields merely to make the dossier self-contained.
