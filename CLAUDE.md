# pypiscan

Batch CLI that scans PyPI packages for known CVE issues. Run as
`python -m pypiscan <subcommand>`.

## Dev

- `uv sync` — install deps and the project in editable mode.
- `uv run python -m pypiscan verify` — run the stub subcommand.
- `uv run pytest` — tests (coverage wired in via pyproject addopts).
- `scripts/check.sh` — mirrors CI exactly; one source of truth.

After `uv tool install pre-commit`, run `pre-commit install` once per
clone to enable git hooks. `~/.local/bin` must be on your PATH so `uv`
and `pre-commit` resolve.

## Before declaring work done

- `scripts/check.sh` must pass.
- `uv run python -m pypiscan verify` output must be unchanged from the
  baseline (`pypiscan verify: no packages specified; nothing to do.`).
