# Contributing

## Local Workflow

Until the Documenso baseline is imported, VASI has no application build or test
command. Documentation work should:

1. Create or activate a local ignored `VASI-xxxx` task.
2. Make the smallest coherent change.
3. Check version alignment and all affected public documentation.
4. Review the diff for secrets, private infrastructure, customer data, and
   accidental claims of unimplemented behavior.
5. Commit and push `main` when the tracked task is complete.

After upstream import, this page must be updated with the exact supported
install, development, lint, typecheck, test, and build commands.

## Rules

- Follow root `AGENTS.md` and the standards under `docs/standards/`.
- Keep `.tasks/` and `.private/` local and ignored.
- Use synthetic documents and fictitious identities only.
- Preserve upstream license, notices, attribution, source layout, and lockfiles.
- Keep branding and operational deltas narrow and reviewable.
- Update the VASI version for each completed change.
