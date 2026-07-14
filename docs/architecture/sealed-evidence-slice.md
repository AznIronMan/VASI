# First sealed evidence slice

Status: implemented in VASI 0.5.0.

## Scope

The first vertical slice proves one complete evidence transaction without
pretending to be the general workflow engine. An authorized company member can
publish and issue one immutable text/terms activity with either acknowledgement
or yes/no response. V·Sign produces a high-entropy participant link, stores only
its SHA-256 digest in the engine, preserves that path through authentication,
and never treats possession of the link as sufficient authorization.

On first open, the engine requires the intended verified email and permanently
binds the assignment to the stable V·Sign principal. It records an interaction
start using server time. A response can be committed once. The state change,
response, event-chain update, manifest, and seal are committed in one PostgreSQL
transaction. Replays, a different participant, and a company member outside the
tenant fail.

## Authoritative record

The PostgreSQL slice contains tenant/membership, immutable workflow revision,
request, participant assignment, interaction session, immutable response,
chain head, append-only evidence event, deterministic manifest, and seal rows.
Published workflow, response, event, manifest, and seal tables reject ordinary
update/delete operations.

Each assignment starts with an all-zero genesis hash. The engine serializes
chain updates with a row lock and hashes canonical VASI JSON containing:

- schema, event ID/type, tenant/request/assignment, and sequence;
- previous hash and authoritative server receive time;
- bounded actor principal, gateway session, roles, email, available provider
  method/subject, and authentication time;
- available gateway-observed IP/header, user-agent, language, and browser client
  hints, labeled as contextual rather than proof of a person's comprehension;
- exact workflow content hash, interaction, response, and server duration; and
- engine version and typed event payload.

The sealed manifest covers the immutable workflow content, participant binding,
outcome, material timestamps, ordered event hashes, and chain head. The standard
seal signs canonical manifest bytes with Ed25519 and records the profile,
algorithm, key ID, public JWK, signature, and manifest SHA-256 hash.

## Verification and disclosure

Every participant receipt, owner record, report, and bundle is verified before release: event
sequence, previous hashes, recomputed event hashes, manifest event inventory,
chain head, manifest hash, Ed25519 signature, and configured public-key anchor
must agree. The participant receipt is intentionally understandable and does
not expose the detailed contextual footprint. The owner record includes the
structured chain for authorized forensic/reporting use. VASI 0.9.0 adds
deterministic participant, plain-language, forensic, and structured reports,
portable bundles, offline verification, and privacy-minimized public
fingerprint verification. A future participant data-request workflow supplies
the broader transparent export path.

This seal establishes integrity and VASI-key origin. It does not by itself prove
legal enforceability, identity beyond the recorded authentication context,
comprehension, independent time, certificate-chain trust, or long-term
validation. A separately configured X.509 certificate seal can add a leaf
certificate signature, while public-chain trust, HSM/KMS, RFC 3161, revocation
archival, and long-term validation remain separate adapters/milestones.
