# Pinned Documenso Upstream Baseline

## Selection

- Upstream project: [Documenso](https://github.com/documenso/documenso)
- Release: [`v2.14.0`](https://github.com/documenso/documenso/releases/tag/v2.14.0)
- Commit: `037170f6253d8b2bdeaf2eb0a08d04f152a41a58`
- Commit date: 2026-06-28
- Imported: 2026-07-12
- Upstream history at the tag: 4,067 commits
- Toolchain: Node.js `>=22.0.0`, npm `>=11.11.0`

This was the newest stable, non-draft, non-prerelease upstream tag available at
selection time. The release includes changes relevant to VASI: recipient-route
branding fixes, branded-email fixes and color support, PostgreSQL-backed email
job migration, S3-compatible storage fixes, typed-signature Unicode support,
and certificate/audit-log API downloads.

## Import Method

The tag was merged into VASI with an unrelated-history, two-parent Git merge.
This preserves upstream commit attribution and gives future updates a common
upstream ancestry rather than copying a source snapshot without history.

Four downstream root conflicts were resolved deliberately:

- `README.md` keeps the VASI product identity and links to this baseline record.
- `AGENTS.md` keeps VASI governance and incorporates the upstream code rules.
- `.gitignore` combines VASI secret/runtime protection with upstream tooling.
- `.editorconfig` preserves upstream formatting plus VASI Markdown behavior.

The rest of the upstream monorepo structure, lockfile, source, assets, Docker
files, migrations, tests, documentation, license, and notices are retained.

## License Boundary

The Community Edition core is covered by AGPL-3.0. The root `LICENSE` imported
from `v2.14.0` is byte-identical to VASI's existing AGPL-3.0 license.

The exact upstream tree also contains `packages/ee/` under the separate
Documenso Commercial License. Upstream Community code compiles against gated
helpers from that package, so VASI retains the exact subtree and its license for
baseline fidelity. VASI does not configure an enterprise license key or enable
enterprise-only behavior.

The upstream enterprise feature list at this baseline includes:

- Stripe billing.
- Organisation Authentication Portal.
- Document-action reauthentication using passkeys or 2FA.
- 21 CFR functionality.
- Email domains.
- Embed authoring and embed-authoring white label.

VASI's planned staff authentication therefore remains an external edge control.
Any future use or modification of `packages/ee/` requires explicit authorization
and license review.

AGPL network-use obligations apply to modified AGPL-covered code. Before VASI is
available to users, the deployment must expose or clearly link the corresponding
source, build/install scripts, license, notices, and modification statement.

## Runtime Requirements

The selected baseline requires PostgreSQL 14+, outbound transactional email, a
canonical public URL/reverse proxy, application/encryption secrets, and a PDF
signing certificate. PostgreSQL stores documents by default; S3-compatible
storage is optional. The default job provider uses PostgreSQL, with Redis/BullMQ
and Inngest as optional alternatives.

The upstream production Compose example is a starting point, not the VASI
deployment contract: it uses an embedded database, a floating `latest` image,
and direct port exposure. VASI will instead use the provisioned private
PostgreSQL service, a pinned VASI image, protected secret mounts, internal-only
origin ingress, persistent storage, and the public CNB edge.

## Update Procedure

For a future upstream update:

1. Fetch stable tags from the `upstream` remote.
2. Review release notes, migrations, licenses, security changes, and enterprise
   boundaries between the current tag and candidate tag.
3. Reproduce the candidate locally and run the VASI acceptance suite.
4. Merge the exact tag without flattening history.
5. Reapply/review the documented VASI delta and update this record.
6. Do not deploy until backup, migration, upgrade, and rollback gates pass.

## Verification Status

Completed:

- Stable release metadata and immutable commit recorded.
- Upstream history and two-parent import strategy preserved.
- Root AGPL license hash matched.
- Community/Enterprise boundary documented.
- Runtime/toolchain requirements recorded.

Still required before claiming a runnable VASI release:

- Dependency installation.
- Prisma generation and local migrations.
- Upstream lint, typecheck/test, and build checks.
- Synthetic local send/sign/complete flow.
