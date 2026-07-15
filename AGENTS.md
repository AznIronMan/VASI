# AGENTS.md

## Task Rules

- Create a unique `VASI-xxxx` task before any implementation, configuration,
  or documentation change begins.
- Store local task records under `.tasks/active/`, `.tasks/pending/`,
  `.tasks/completed/`, or `.tasks/cancelled/` as appropriate.
- Keep `.tasks/` local and untracked. Never include VASI task IDs in public
  documentation, release notes, commit messages, or pull requests.
- Update the task state when work is completed, cancelled, or deferred.

## Private Rules

- Preserve `.private/` and its contents unless the operator explicitly requests
  a change.
- Keep `.private/` local and untracked.
- Never commit or disclose private notes, credentials, secrets, customer data,
  production details, logs, backups, or signing material.

## Documentation and Version Rules

- The current VASI version is `0.31.0`.
- Increment the VASI version for every completed tracked change according to
  semantic versioning.
- Keep the version in `README.md` and this file aligned.
- Update `README.md` and any applicable documentation whenever behavior, setup,
  architecture, configuration, deployment, security, or support policy changes.
- Keep all status statements current and accurate.

## Git Rules

- Work on `main` by default.
- Review staged changes for secrets and private artifacts before every commit.
- At the end of completed work, commit the changes and push `main` to `origin`
  unless the operator explicitly says not to push.
