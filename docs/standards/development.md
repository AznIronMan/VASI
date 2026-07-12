# Development Standard

## Change Discipline

- Track work locally before editing.
- Keep changes scoped and explain any upstream divergence.
- Prefer upstream-supported extension/configuration points.
- Do not mix a mechanical upstream update with unrelated VASI features.
- Pin and record the upstream Documenso tag or commit used by each release.
- Keep `VERSION`, `AGENTS.md`, README status, and changelog aligned.

## Quality Gate

Once the application is imported, every change must run the baseline's required
format, lint, typecheck, unit/integration test, and production build checks.
Risk-sensitive signing, authentication, authorization, audit, storage, email,
and deployment changes also require focused regression coverage.

User-interface changes require visual review at supported desktop and mobile
sizes. Signing-flow changes require an end-to-end synthetic document test.

## Upstream Maintenance

- Keep an `upstream` Git remote pointing to the official Documenso repository.
- Review upstream release notes and migrations before merging.
- Never update a production baseline without a backup and tested rollback plan.
- Preserve locally required branding/configuration through documented patches or
  overlays that can be re-applied and reviewed.

## Definition Of Done

A change is complete only when code/docs, tests, version metadata, task state,
secret review, and applicable operational guidance agree. Deployment work is
complete only after target-environment verification; a valid local build alone
is not a production deployment.
