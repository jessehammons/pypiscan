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
  the scanned wheels (roadmap item 3.5).
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

## How versions are identified

A version number found in a binary means different things depending on where
the string comes from. Detectors record every match as one of three kinds of
evidence:

- **Library string**: a string defined in one of the upstream library's own
  source files, such as zlib's `deflate` and `inflate` copyright banners.
  Only this kind shows that a binary contains the library, and only this
  kind sets its version.
- **Header string**: a version macro from the library's public header, such
  as `ZLIB_VERSION`. Code that *calls* a library embeds it; for example,
  zlib's `deflateInit()` passes `ZLIB_VERSION` to the library. It shows
  which headers a binary was compiled against, never that the binary
  contains the library.
- **Filename**: the version suffix on a wheel member's name, such as
  `libz-….so.1.3.1`. It isn't part of the binary's contents, and for some
  libraries (libtiff, libwebp) it's an ABI number rather than a release. It
  is recorded as corroboration only: it never sets a version and never
  produces a record on its own.

Exported symbols and `DT_SONAME` are not version evidence.

Rules for detectors:

- Patterns match whole strings, such as a full banner, and capture the
  version from inside them. A pattern for a bare version number also matches
  header strings and unrelated data.
- Candidate patterns come from discovery across real wheels (roadmap 2.3
  and 3.5): version-like strings grouped by the text around them. Upstream
  source then confirms each candidate: which file defines it, and whether
  it is a library string or a header string.
- Each pattern cites the upstream source file that defines its string, at a
  release tag. Patterns come from reading upstream source, not from memory.
- Each pattern is tested against its string at *every* upstream release tag,
  from a committed fixture generated from the upstream repository (roadmap
  2.2). Reading one release isn't enough: before 2.1.0, zlib-ng named and
  worded its identity string differently, and a pattern written from 2.3.3
  alone missed it.
- Versions are kept exactly as the string gives them, including four-part
  versions such as zlib 1.3.1.1.
- Some libraries have derivatives that carry their strings (zlib-ng for
  zlib; BoringSSL, LibreSSL and AWS-LC for OpenSSL). A binary is reported as
  the original only if it has the original's library strings and none of a
  derivative's. A derivative is reported with its own version, not the
  version it claims compatibility with. If upstream source offers no library
  string that tells them apart, stop and ask the maintainer.

`fingerprint` writes JSON Lines with its own `schema_version`, one record
per binary, library and relation:

- `wheel`, `path`, `sha256`: as in `inspect`.
- `library`: such as `zlib` or `zlib-ng`.
- `relation`: `contains` when library strings matched; `compiled_against`
  when only header strings did.
- `version`: from library strings for `contains`; the header string
  verbatim for `compiled_against`; `null` when library strings in one binary
  disagree.
- `conflict`: `true` when library strings in one binary give different
  versions.
- `evidence`: every match, with its kind, the matched text, its file offset
  and its ELF section name (offset and section are `null` for filename
  evidence, and the section is `null` when it can't be mapped).

A binary with no matches produces no record. No record means "not detected",
not "not present".

## How a scan runs

`scan` runs every package on a committed list through a fixed sequence of
phases, finishing each phase for all packages before starting the next. It
covers breadth: the latest release of many packages. Depth, every release of
one package, belongs to the time-to-patch items (section 7).

```
pypiscan scan <package-list> --episode-dir D --cache-dir C --count N
```

- `--count` is required and takes the first N rows of the list: 1, 2, 5 or
  10 for smoke tests, 100 for a full run. If it is missing, `scan` prints
  its full help to stderr and exits 2. (argparse's `required=True` prints
  only the usage line, so the check is made after parsing.) A value below 1
  is an error and exits 2; a value larger than the list is clamped to its
  length.
- The episode directory holds one run's results. The cache directory holds
  downloaded wheels, named by sha256 and shared between episodes.

Each package's **target wheel** is the one pip would choose for CPython 3.12
on manylinux x86_64 with glibc 2.28 or older. That includes `abi3` wheels
(cryptography's are abi3 and link OpenSSL statically) and
`py3-none-manylinux…` wheels. Yanked files are never chosen, and a release
with only pure-Python wheels has no target. A target wheel larger than
100 MB, by the size PyPI reports, is skipped as `too_large` before anything
is downloaded.

Phases, in order:

1. `01-resolve` (network): read the release from PyPI's JSON API and record
   the target wheel's filename, URL, sha256, size and upload time.
2. `02-fetch` (network): download the wheel into the cache, unless it is
   already there, and verify its sha256.
3. `03-inspect`: `inspect` records for the wheel's binaries.
4. `04-strings`: `strings` records.
5. `05-fingerprint`: `fingerprint` records.
6. `06-report`: the discovery and library frequency tables (roadmap 3.5).

Rules:

- **Pre-flight finishes before anything is written.** Any failure is
  printed to stderr and exits 2:
  1. The episode and cache directories are outside any git working tree.
  2. The package list loads (roadmap 3.2).
  3. The episode's phase files are a run of finished phases with no gaps
     (01, 02, …) and no `.partial` file. Otherwise the error names every
     file to delete.
  4. If the episode has an `episode.json`, it matches this run's inputs: the
     list file's sha256, the count, the target and the size limit. A smoke
     run at `--count 2` and another at `--count 10` therefore need separate
     episode directories. The code version is recorded but not matched, so a
     phase can be rerun after a fix.
- **One line per package per phase**, in list order: `schema_version`,
  `name`, `status` (`ok`, `skipped` or `error`), `reason`, and the phase's
  data. Per-binary results are nested inside the package's line, in the
  `inspect`, `strings` and `fingerprint` record formats. A package whose
  line in the previous phase isn't `ok` gets a `skipped` line, never a
  missing one, so every finished phase file has exactly one line per
  package. A bad zip or malformed ELF becomes an `error` line, not a crash.
- **Phase files are written whole or not at all.** A phase writes
  `NN-<phase>.jsonl.partial` and renames it to `NN-<phase>.jsonl` when it
  finishes. A rerun skips finished phases. There is no resuming partway
  through a phase: to rerun one, delete its file and every later one. For
  example:

  ```
  pypiscan scan: error: 03-inspect.jsonl.partial exists; an earlier run
  stopped in phase 03. Delete it to rerun phase 03.
  ```

- **Ctrl-C** is handled by one flag for the whole run, checked between
  packages. The current package finishes, the `.partial` file stays, and
  `scan` exits 130. The next run stops at pre-flight until the file is
  deleted.
- **One phase at a time, no retries.** An `error` line stands. Only phases 01
  and 02 use the network, through an HTTP client that tests replace with
  recorded responses.
- When every phase finishes, `scan` exits 0, even if some lines are
  `error`: errors are data. Counts by status go to stderr, and nothing goes
  to stdout.

## Roadmap

Each item is one pull request (see
[Branches and pull requests](#branches-and-pull-requests)), sized to be
implemented in about 20–30 agent turns and reviewed on a phone. Items marked
*(maintainer input)* need a decision before any code is written. Done items
are marked ✓.

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

- **2.1** ✓ Detector framework plus the zlib family, following
  [How versions are identified](#how-versions-are-identified):
  `fingerprint <wheel>` reports library, version and the evidence that
  matched, and tells classic zlib apart from zlib-ng (their CVE histories
  differ). Adding a library later means adding one detector, not changing
  the scanner or the output format. Manual checks:
  - lxml 6.1.3: zlib 1.3.2, `contains`, in both `lxml/etree` and
    `lxml/objectify` (one record each).
  - grpcio 1.84.0: zlib 1.3.1.1, `contains`, in `grpc/_cython/cygrpc`.
  - Pillow 12.3.0 ships no zlib code. Its build scripts pin zlib-ng 2.3.3,
    but its binaries load the system's `libz.so.1`. It should show no
    `contains` for zlib or zlib-ng, only `compiled_against` zlib-ng
    `1.3.1.zlib-ng` in `_imaging`, `libfreetype`, `libpng16` and `libtiff`.
  - zlib-ng: no wheel examined so far carries zlib-ng code. Build zlib-ng
    2.3.3 from upstream source in a temporary directory, in both compat and
    native modes, pack each shared library into a throwaway wheel, and
    confirm both report zlib-ng 2.3.3, never classic zlib.
- **2.2** Upstream string fixtures. A script reads a library's upstream git
  repository and, at every release tag, extracts each string the detector's
  patterns cite. It reads the C literal directly, and runs the preprocessor
  only when a string is assembled from macros. It writes
  `tests/upstream/<library>.tsv` with one row per tag and string: tag, file
  and line, and the string. The fixtures are text and are committed;
  generating them needs the network, so the script runs outside pytest.
  Tests place each tag's strings in a synthetic binary and check that the
  detector reports that tag's library and version, allowing for spelling
  differences between tag names and strings (`2.1.0-beta1` versus
  `2.1.0.beta1`). A tag the detector misclassifies or misses fails the
  tests. Covers zlib and zlib-ng at every release tag. **← current**
- **2.3** `pypiscan strings <wheel>` lists, for each ELF binary, every
  printable string that contains a version-like token (digit runs separated
  by dots), with its offset and a template in which each digit run becomes
  `#`: `deflate 1.3.2 Copyright 1995-2026 …` becomes
  `deflate #.#.# Copyright #-# …`. Offline, like `inspect`. Grouping
  templates across many wheels is `scan`'s report phase (3.5). Manual check:
  for lxml 6.1.3, `lxml/etree` lists zlib's `deflate` banner with that
  template.

### 3. Breadth-first scan

Builds `scan`, following [How a scan runs](#how-a-scan-runs). It produces
the discovery table that section 4's detectors start from.

- **3.1** PyPI client and wheel selection, plus
  `fetch <name>==<version> --cache-dir C`: read one release from PyPI's JSON
  API, choose its target wheel, download it into the cache and verify its
  sha256. Tests use recorded responses. Manual check: for five packages, the
  chosen file matches what `uvx pip download` picks with the flags in
  [Conventions](#conventions).
- **3.2** The package list: `data/packages.csv`, with columns `name` and
  `version`, at most 100 rows, in processing order. The loader rejects an
  empty list, missing fields, and names that collide after PEP 503
  normalization (`Pillow` and `pillow` are the same package). A script
  outside pytest generates the list: it walks a top-pypi-packages snapshot
  in rank order, keeps each project whose latest final release has a target
  wheel, and stops at 100. Most top packages are pure Python, so this goes
  well past rank 100. Wheels over the size limit stay on the list; the
  limit is applied when scanning, so raising it doesn't mean regenerating
  the list. The snapshot month and the selection rule go in
  `data/README.md`. Versions are pinned, and refreshing the list is its own
  pull request.
- **3.3** `scan` with pre-flight, the episode directory and phases 01 and
  02.
- **3.4** Phases 03 to 05. A bad zip or malformed ELF becomes an `error`
  line; zip members over an uncompressed size limit are recorded and
  skipped.
- **3.5** Phase 06 writes two tables into the episode directory. The
  discovery table lists each template from `strings`: how many wheels and
  binaries it appears in, example strings, and which detector pattern
  explains it, if any. Unexplained templates that recur across wheels are
  candidates for new detectors, or for variants existing ones miss. The
  frequency table counts how often each bundled library appears across the
  scanned wheels, and sets the order of section 4. Manual check: a full run
  with `--count 100`; the PR includes the most frequent templates,
  explained and unexplained, and the frequency table.

Later: a per-wheel time limit, which needs a subprocess per wheel.

### 4. Detectors

- **4.1** libpng, libjpeg-turbo and libtiff detectors.
- **4.2** OpenSSL (told apart from BoringSSL, LibreSSL and AWS-LC), expat and
  sqlite detectors.
- **4.3** *(maintainer input)* libwebp: it embeds no plain version string, so
  choose a detection method before implementing it.
- **4.4** Report binaries no detector recognized, so gaps are visible.

Each detector item starts from 3.5's discovery table and ships with
2.2-style fixtures covering every upstream release tag.

Manual checks for 4.1 and 4.3 compare results against Pillow 12.3.0's
`.github/dependencies.json`. Pillow bundles no OpenSSL, expat or sqlite, so
4.2 needs other wheels, found with 3.5's discovery table.

### 5. SBOM comparison

- **5.1** Read PEP 770 SBOMs (CycloneDX JSON) into components.
- **5.2** Compare SBOM claims against fingerprint results: coverage and
  agreement statistics.

### 6. CVE data

- **6.1** CVE table format, loader and validation. Each row stores evidence,
  not just conclusions: fix commits, fixed version and release date per
  maintained branch, introduced version (or "unknown"), affected component
  (library code or a bundled tool), disputed status and sources. Seeded with
  CVE-2023-4863.
- **6.2** Importer: draft candidate rows for one library from NVD and OSV.
- **6.3** Range verifier: given the library's repository and a row's fix
  commits, compute the release tags that contain them and their dates;
  compare against the imported ranges and flag disagreements. Tests use a
  small synthetic git repository.
- **6.4** *(maintainer input)* Curation review: resolve flagged rows, one
  library per pull request. Corrections to public advisories are submitted
  upstream.

### 7. Matching and time-to-patch

- **7.1** `match`: compare fingerprints against the CVE table and output
  candidates with their evidence level. Refuses output paths inside the
  repository, enforced in code and tested.
- **7.2** Evidence for levels 2 and 3: whether the affected function is
  present in the binary, and which extension modules import functions from
  the bundled library.
- **7.3** Release history: every release of a package, with upload times per
  file.
- **7.4** Historical pilot: which releases of each affected package bundled
  which libwebp version.
- **7.5** Time-to-patch: the clock starts when a fixed library release was
  public (the later of the fixed release and the CVE's publication) and stops
  at the first release whose wheel for that platform bundles a fixed version.
  Wheels still unpatched are counted as unfinished, not dropped. Also counts
  releases shipped with the stale library after the fix was available.
- **7.6** Summary report as Markdown and CSV. Named examples only for
  resolved cases.

### 8. Publishing

- **8.1** Release script: a dated data snapshot plus a `SHA256SUMS` file,
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

## Branches and pull requests

- One pull request is open at a time. Each starts on a new branch cut from
  the current `main` after the previous pull request has merged. A branch is
  never reused for a second pull request.
- Every pull request targets `main`. Branches are never stacked on other
  branches, rebased or force-pushed. Work that has to wait goes on its own
  branch from `main` and becomes a pull request when it's next.
- Pull requests are squash-merged, and the branch is deleted afterwards.
- Branch names are lowercase words joined by hyphens, with no `/`: one of
  four prefixes, then a slug of two to four words.
  - `roadmap-<item>-<slug>` for a roadmap item, such as
    `roadmap-2.2-upstream-fixtures`.
  - `docs-<slug>` for documentation changes outside the roadmap.
  - `fix-<slug>` for fixes outside the roadmap.
  - `chore-<slug>` for tooling, CI and dependency changes.
- No dates, random suffixes or tool names in branch names. A session that
  starts on an automatically named branch (such as `claude/…`) creates a
  correctly named branch from `main` before its first commit.

## License

MIT. See [LICENSE](LICENSE).
