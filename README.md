# pypiscan

Inventories the compiled C libraries bundled inside PyPI wheels, identifies
their versions from the binaries themselves, and measures how long wheels kept
shipping library versions affected by known CVEs.

Status: early development. `inspect` works; see [Pipeline](#pipeline) for
what is being built and in what order.

## Why

Many popular Python packages ship compiled C libraries inside their wheels:
copies of zlib, libjpeg, libpng, libwebp, OpenSSL and others. They arrive
either as shared libraries that auditwheel copies into a `<package>.libs/`
directory, or statically linked into extension modules.

Dependency scanners such as Dependabot and pip-audit match *Python package*
versions against advisories. They don't look inside wheels, so these bundled
libraries are invisible to them.

[PEP 770](https://peps.python.org/pep-0770/) defines a standard location for
SBOMs inside wheels, and auditwheel generates one automatically from version
6.5.0 on. Wheels already published won't gain one, because PyPI doesn't allow
replacing an uploaded file.

pypiscan measures this layer directly from the binaries.

## Non-goals

- Not a Python-dependency vulnerability scanner. pip-audit and OSV already
  check Python package versions.
- Binaries from wheels are never executed. They are read as data.

## Pipeline

Built in this order:

1. **`inspect <wheel>`**: list the ELF binaries in a wheel, offline.
2. **`fingerprint`**: identify library and version from the binaries
   (zlib first). **← current**
3. **`fetch <package>`**: download latest-release wheels and check them
   against the sha256 that PyPI publishes.
4. **SBOM comparison**: what a PEP 770 SBOM claims versus what the binaries
   contain.
5. **Time-to-patch analysis**: how long each wheel kept shipping a
   CVE-affected library version after a fix was available. Pilot: libwebp,
   CVE-2023-4863.

## Data handling and disclosure

- CVE matches against *current* releases are never written into this
  repository or printed in CI logs. Commands that produce them take an
  explicit output path outside the working tree.
- Findings that affect current releases are reported privately to the
  package's maintainers, with the fix, before anything about them is
  published.
- Published results name only cases that are already resolved. Aggregate
  statistics include unresolved cases without naming them, so reported patch
  times aren't biased toward the fast cases.

## Conventions

- Output is JSON Lines with a `schema_version` field. Changing the output
  format means bumping `schema_version`.
- ELF parsing uses pyelftools, not `readelf` or `nm`, so the tool behaves the
  same on macOS and Linux.
- Tests build synthetic wheels in `tmp_path`. No real wheels or binaries are
  committed. Tests don't use the network; any that must are marked `network`
  and deselected in CI.
- Wheels for manual checks are downloaded with `uvx pip download`, since uv
  virtual environments don't include pip. For example:

  ```bash
  uvx pip download --only-binary=:all: --no-deps \
    --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
    --python-version 3.12 -d /tmp/wheels pillow
  ```

## Development

Run as `python -m pypiscan <subcommand>`.

- `uv sync`: install dependencies and the project in editable mode.
- `uv run python -m pypiscan --help`: list subcommands.
- `uv run pytest`: run the tests (coverage is wired in via `pyproject.toml`).
- `scripts/check.sh`: runs exactly what CI runs. If it passes locally, CI
  should pass.

After `uv tool install pre-commit`, run `pre-commit install` once per clone to
enable the git hooks. `~/.local/bin` must be on your `PATH` so `uv` and
`pre-commit` resolve.

## License

MIT. See [LICENSE](LICENSE).
