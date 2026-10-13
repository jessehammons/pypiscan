# pypiscan

Inventories the compiled C libraries bundled inside PyPI wheels, identifies
their versions from the binaries themselves, and measures how long wheels kept
shipping library versions affected by known CVEs.

Status: early development. `inspect` works; see the [Roadmap](#roadmap) for
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

## Scope (version 1)

In scope:

- Linux x86_64 (manylinux) wheels for one Python version (CPython 3.12).
- A committed list of packages, so every run uses the same pinned input.
- An inventory of *every* bundled shared library in those wheels.
- Version detection for a growing list of libraries, starting with zlib and
  zlib-ng, libpng, libjpeg-turbo, libtiff, libwebp, OpenSSL, expat and
  sqlite. The order of additions is set by how often each library appears in
  the scanned wheels (roadmap item 3.4).
- A curated CVE table covering high and critical CVEs from 2020 onward for
  those libraries.
- A time-to-patch pilot for libwebp CVE-2023-4863.

Out of scope for version 1: macOS, Windows, ARM and musl wheels; source
distributions; conda packages; automated disclosure; automated parsing of
packages' build scripts (they are read by hand during triage).

## Non-goals

- Not a Python-dependency vulnerability scanner. pip-audit and OSV already
  check Python package versions.
- Binaries from wheels are never executed. They are read as data.
- No exploit or proof-of-concept code in this repository.

## How findings are classified

A version match alone shows that vulnerable code *ships* in a wheel, not that
it can be reached. Every finding records the level of evidence behind it:

1. **Version in range**: the bundled library's detected version falls inside
   a CVE's affected range.
2. **Vulnerable code present**: the affected function is compiled into the
   binary, and the library came from an upstream build rather than a
   distribution package that may carry backported fixes.
3. **Reachable by argument**: a written path from a public Python API to the
   vulnerable function, citing the binding's source code.

Reports to maintainers state the level plainly. Findings judged unreachable
are not sent as security reports.

## Sources of truth

- **The wheel's binaries** are what users actually run, and the primary
  measurement.
- **A package's build scripts** show what the maintainers intended (for
  example, Pillow pins its bundled library versions in
  `.github/dependencies.json`). They serve as an answer key for checking
  version detection, and for triage. Disagreements between the two are
  findings.
- **The upstream library's git history** is the ground truth for a CVE's
  fixed version: the first release whose tag contains the fix commit. The CVE
  table stores the fix commits, so every range can be recomputed.
- **NVD, OSV and the GitHub Advisory Database** are used to find candidate
  CVEs and fix commits, and as cross-checks. Their version ranges for C
  libraries are often wrong and are never used unverified.

## Roadmap

Each item is one pull request, sized to be implemented in about 20–30 agent
turns and reviewed on a phone. Items marked *(maintainer input)* need a
decision before any code is written. Done items are marked ✓.

### 0. Guardrails

- **0.1** ✓ Working rules in `CLAUDE.md`: never weaken a check (coverage
  threshold, lint rules, type strictness, CI steps) to make it pass, and
  explain the problem in the PR instead; keep non-test changes under about
  300 lines; call out any CI or tool-configuration change in the PR
  description.
- **0.2** ✓ Pyright strict mode for all of `src/pypiscan` instead of a file
  list; raise the coverage threshold to 90%.
- **0.3** ✓ pytest-socket blocks all network access in tests, with no
  per-test opt-out: a collection hook rejects its `enable_socket` marker and
  `socket_enabled` fixture.
- **0.4** ✓ A pull request template: summary, manual-check output, and a
  checkbox for "touches CI, `check.sh` or tool configuration".
- **0.5** *(optional; a GitHub settings change made by the maintainer, not
  code, so the "current" marker skips it)* Branch protection on `main`:
  require a pull request, require all CI checks to pass, block force pushes.

Later, optional: Dependabot updates for the pinned GitHub Actions; the
OpenSSF Scorecard workflow; Hypothesis property tests for detectors and
version parsing.

### 1. Inspect

- **1.1** ✓ `inspect <wheel>`: list the ELF binaries in a wheel, offline.
- **1.2** ✓ Add each binary's shared-library dependencies (`DT_NEEDED`) to
  `inspect` output, using pyelftools. Makes static linking visible: a
  library whose code appears in a binary that doesn't list it as a
  dependency was linked in statically. Bumps `schema_version` to 2.

### 2. Fingerprint

- **2.1** Detector framework plus the zlib family: `fingerprint <wheel>`
  reports library, version and the evidence that matched, and tells classic
  zlib apart from zlib-ng (their CVE histories differ). Manual check: Pillow
  12.3.0 should show zlib-ng 2.3.3. **← current**
- **2.2** libpng, libjpeg-turbo and libtiff detectors.
- **2.3** OpenSSL (told apart from BoringSSL, LibreSSL and AWS-LC), expat and
  sqlite detectors.
- **2.4** *(maintainer input)* libwebp: it embeds no plain version string, so
  choose a detection method before implementing it.
- **2.5** Report binaries no detector recognized, so gaps are visible.

Manual checks for 2.1–2.4 compare results against Pillow 12.3.0's
`.github/dependencies.json`.

### 3. Fetch and scan

- **3.1** `fetch <package>`: find the latest release with PyPI's JSON API,
  pick the wheel for the target platform, download it to a cache outside the
  repository, and verify its sha256. Tests use recorded API responses.
- **3.2** *(maintainer input: the package list)* `scan <package-list>`:
  batch fetch, inspect and fingerprint into one inventory file; resumable.
- **3.3** Hardening for untrusted input: a bad zip or malformed ELF becomes
  an error record, not a crash; limits on member size and per-wheel time.
- **3.4** Frequency table of bundled libraries across scanned wheels. Sets
  the order for adding detectors.

### 4. SBOM comparison

- **4.1** Read PEP 770 SBOMs (CycloneDX JSON) into components.
- **4.2** Compare SBOM claims against fingerprint results: coverage and
  agreement statistics.

### 5. CVE data

- **5.1** CVE table format, loader and validation. Each row stores evidence,
  not just conclusions: fix commits, fixed version and release date per
  maintained branch, introduced version (or "unknown"), affected component
  (library code or a bundled tool), disputed status and sources. Seeded with
  CVE-2023-4863.
- **5.2** Importer: draft candidate rows for one library from NVD and OSV.
- **5.3** Range verifier: given the library's repository and a row's fix
  commits, compute the release tags that contain them and their dates;
  compare against the imported ranges and flag disagreements. Tests use a
  small synthetic git repository.
- **5.4** *(maintainer input)* Curation review: resolve flagged rows, one
  library per pull request. Corrections to public advisories are submitted
  upstream.

### 6. Matching and time-to-patch

- **6.1** `match`: compare fingerprints against the CVE table and output
  candidates with their evidence level. Refuses output paths inside the
  repository, enforced in code and tested.
- **6.2** Evidence for levels 2 and 3: whether the affected function is
  present in the binary, and which extension modules import functions from
  the bundled library.
- **6.3** Release history: every release of a package, with upload times per
  file.
- **6.4** Historical pilot: which releases of each affected package bundled
  which libwebp version.
- **6.5** Time-to-patch: the clock starts when a fixed library release was
  public (the later of the fixed release and the CVE's publication) and stops
  at the first release whose wheel for that platform bundles a fixed version.
  Wheels still unpatched are counted as unfinished, not dropped. Also counts
  releases shipped with the stale library after the fix was available.
- **6.6** Summary report as Markdown and CSV. Named examples only for
  resolved cases.

### 7. Publishing

- **7.1** Release script: a dated data snapshot plus a `SHA256SUMS` file,
  signed by the maintainer.

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
  committed.
- Tests never touch the network, and there is no per-test escape hatch. Code
  that talks to PyPI, NVD or OSV is tested with recorded responses injected
  at the HTTP-client layer, not through a local server. Anything that
  genuinely needs a live network is an end-to-end check that lives outside
  the pytest suite.
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
