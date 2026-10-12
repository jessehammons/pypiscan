#!/usr/bin/env bash
# Mirror of CI: run the same checks in the same order.
set -euo pipefail

uv sync --locked

# lint
uv run ruff check
uv run ruff format --check

# typecheck
uv run pyright

# test (coverage wired via pyproject addopts)
uv run pytest

# audit
reqs="$(mktemp -t pypiscan-reqs.XXXXXX)"
trap 'rm -f "$reqs"' EXIT
uv export --no-dev --no-emit-project --output-file "$reqs" >/dev/null
uv run pip-audit --strict --disable-pip --no-deps --requirement "$reqs"
uv run deptry src

# smoke: the CLI starts and lists its subcommands
uv run python -m pypiscan --help >/dev/null
