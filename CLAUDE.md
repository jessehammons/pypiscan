@README.md

## Before declaring work done

- `scripts/check.sh` must pass.
- New behavior has tests; output format changes bump `schema_version`.
- Work only on the roadmap item marked current in the README; don't skip
  ahead. When an item is finished, mark it done (✓) and move the "current"
  marker to the end of the next item's text in the same change.
- Items marked *(maintainer input)* need a decision from the maintainer
  before any code is written: ask, don't guess.

## Working rules

- Never weaken a check to make it pass: no lowering the coverage threshold,
  disabling or ignoring lint rules, relaxing type strictness, or removing or
  skipping CI steps (this includes `# noqa`, `# type: ignore` and
  `# pragma: no cover` added only to get green). If a check can't be met
  properly, leave it failing and explain the problem in the PR description.
- Keep non-test changes under about 300 lines per pull request. If an item
  needs more, stop and say so in the PR rather than growing it.
- Call out any change to CI, `scripts/check.sh` or tool configuration
  (`pyproject.toml` tool sections, `.pre-commit-config.yaml`, workflows) in
  the PR description, with the reason.
