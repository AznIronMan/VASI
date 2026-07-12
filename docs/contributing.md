# Contributing

## Local Workflow

VASI follows the pinned Documenso `v2.14.0` npm workspace and lockfile. The
baseline commands are:

```sh
npm ci
npm run lint
npm run build
```

The full development bootstrap additionally requires Docker Compose:

```sh
npm run dx
npm run dev
```

`npm run dx` starts the upstream development PostgreSQL, mail-capture, Redis,
MinIO, and document-conversion services, then applies migrations and seeds
synthetic development data. Do not run it against VASI production services.
The complete, verified setup and signing check is in
[Local development](operator/local-development.md).

Application or documentation work should:

1. Create or activate a local ignored `VASI-xxxx` task.
2. Make the smallest coherent change.
3. Check version alignment and all affected public documentation.
4. Review the diff for secrets, private infrastructure, customer data, and
   accidental claims of unimplemented behavior.
5. Commit and push `main` when the tracked task is complete.

The VASI-supported baseline has been reproduced through clean install,
migration, seed, lint, typecheck, library tests, production build, captured
mail, synthetic browser signing, valid PDF sealing, and tamper detection. The
documented baseline exceptions remain release blockers rather than hidden
failures.

## Rules

- Follow root `AGENTS.md` and the standards under `docs/standards/`.
- Keep `.tasks/` and `.private/` local and ignored.
- Use synthetic documents and fictitious identities only.
- Preserve upstream license, notices, attribution, source layout, and lockfiles.
- Keep branding and operational deltas narrow and reviewable.
- Update the VASI version for each completed change.
