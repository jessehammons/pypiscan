# pypiscan

Inventories the compiled C libraries bundled inside PyPI wheels, identifies
their versions from the binaries themselves, and matches those versions
against known CVEs.

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
- The latest release of each listed package, and the shared libraries
  auditwheel bundles into its `<package>.libs/` directory.
- Version detection for a growing list of libraries, starting with zlib and
  zlib-ng, libpng, libjpeg-turbo, libtiff, libwebp, OpenSSL, expat and
  sqlite. The order of additions is set by how often each library appears in
  the scanned wheels (roadmap item 3.7), and a library is added as rows in
  the [library map](#the-library-map).
- A curated CVE table covering high and critical CVEs from 2020 onward for
  those libraries.

Out of scope for version 1, and listed under [Later](#later-tbd):
statically linked libraries, and time-to-patch (how long wheels kept
shipping an affected version).

Also out of scope for version 1: macOS, Windows, ARM and musl wheels; source
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
- Candidate patterns come from discovery across real wheels (roadmap 3.5
  and 3.7): version-like strings grouped by the text around them, and the
  library map's identity strings. Upstream
  source then confirms each candidate: which file defines it, and whether
  it is a library string or a header string.
- Each pattern cites the upstream source file that defines its string, at a
  release tag. Patterns come from reading upstream source, not from memory.
- Each pattern is tested against its string at *every* upstream release tag,
  from a committed fixture generated from the upstream repository (roadmap
  2.2; from 4.1 on, by `scan`'s phase 06). Reading one release isn't enough:
  before 2.1.0, zlib-ng named and worded its identity string differently, and
  a pattern written from 2.3.3 alone missed it.
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
phases, finishing each phase before starting the next. It covers breadth:
the latest release of many packages, and only the shared libraries bundled
in their `<package>.libs/` directories. Statically linked libraries and
time-to-patch are [Later](#later-tbd).

A scan runs in two parts with a manual step between them. Part 1 finds the
bundled libraries; the maintainer then says, in the
[library map](#the-library-map), which upstream project each one comes
from; part 2 builds recognizers from those projects' release tags and
matches the versions it finds against CVEs. The same command runs both
parts: a rerun skips finished phases, so after the map is edited, `scan`
picks up at phase 06.

```
pypiscan scan <package-list> --library-map M --episode-dir D --cache-dir C --count N
```

- `--count` is required and takes the first N rows of the list: 1, 2, 5 or
  10 for smoke tests, 100 for a full run. If it is missing, `scan` prints
  its full help to stderr and exits 2. (argparse's `required=True` prints
  only the usage line, so the check is made after parsing.) A value below 1
  is an error and exits 2; a value larger than the list is clamped to its
  length.
- `--library-map` names the committed library map, normally
  `data/libraries.csv`. It arrives with phase 05 (roadmap 3.7); until then
  `scan` doesn't take it.
- The episode directory holds one run's results. The cache directory holds
  downloaded wheels and upstream clones, both shared between episodes. A
  wheel is stored as `wheels/<sha256>/<filename>`: a directory named by
  its sha256, holding the file under its original name. It is written as
  `<filename>.partial` and renamed only once its sha256 matches PyPI's.

Each package's **target wheel** is the one pip would choose for CPython 3.12
on manylinux x86_64 with glibc 2.28 or older. That includes `abi3` wheels
(cryptography's are abi3 and link OpenSSL statically) and
`py3-none-manylinux…` wheels. Yanked files are never chosen. A release
with only pure-Python wheels has no target, and phase 01 records it as
`skipped` with reason `no_target`. A target wheel larger than the wheel
size limit, 100 MB by the size PyPI reports, resolves normally in phase 01,
and phase 02 records it as `skipped` with reason `too_large` without
downloading it. Phase 03 skips zip members larger than the zip-member size
limit, 512 MB uncompressed, since each member is read into memory.

Phases, in order. Per-package phases have one line per package; per-library
phases have one line per library in the map.

Part 1:

1. `01-resolve` (network, per package): read the release from PyPI's JSON
   API and record the target wheel's filename, URL, sha256, size and
   upload time.
2. `02-fetch` (network, per package): download the wheel into the cache,
   unless it is already there, and verify its sha256.
3. `03-inspect` (per package): `inspect` records for the wheel's binaries.
4. `04-strings` (per package): `strings` records.
5. `05-libraries` (per package): each shared library in the wheel's
   `.libs/` directory, with its prefix: the filename without auditwheel's
   hash and version suffix (`libjpeg-1a2b3c4d.so.62.4.0` becomes
   `libjpeg`). Then the phase writes the library report into the episode:
   for each prefix, how many wheels and files carry it and its most
   common `strings` templates.

**Manual step.** Once phase 05 is finished, in this run or an earlier one,
every run compares phase 05's prefixes with the current library map and
rewrites `library-map-todo.csv` in the episode, one row per prefix the map
doesn't list. It is derived from the map, not a phase file, so it is never
skipped as finished. If it has rows, `scan` lists the prefixes on stderr and
exits 3. The maintainer reads the report and, for each prefix, adds rows to
the library map (or marks the prefix `skip`), commits the map, and reruns
`scan`, which goes on to phase 06 once the todo is empty.

Part 2:

6. `06-upstream` (network, per library): clone the library's repository
   into the cache, or fetch into the existing clone (see
   [Conventions](#conventions)), and at every release tag read each
   identity string the map names, as a C literal. A string assembled from
   macros is an `error` line for that library until a preprocessor step is
   added.
7. `07-recognizers` (per library): build a recognizer from phase 06's
   strings and check that it reports every tag's library and version
   (see [How versions are identified](#how-versions-are-identified)). A
   library with any tag misidentified gets an `error` line and isn't used.
8. `08-fingerprint` (per package): run the recognizers on each shared
   library whose prefix maps to them, giving `fingerprint` records.
9. `09-cves` (network, per library): candidate CVEs from NVD, by the map's
   CPE, and OSV, by its OSV identifier, checked against the curated CVE
   table (section 6). Fixed versions come from the release tags that
   contain each fix commit, in phase 06's clone.
10. `10-match` (per package): each library version that falls inside a
    CVE's affected range, with its evidence level. A match is a candidate
    for investigation, not a finding.

### The library map

`data/libraries.csv` is curated input, edited by hand and committed like
the package list. One row per prefix, library and identity string:

| prefix | library | repo | identity_file | identity_symbol | cpe | osv |
|---|---|---|---|---|---|---|
| `libz` | `zlib` | `https://github.com/madler/zlib` | `deflate.c` | `deflate_copyright` | `zlib:zlib` | … |
| `libz` | `zlib` | `https://github.com/madler/zlib` | `inftrees.c` | `inflate_copyright` | `zlib:zlib` | … |
| `libz` | `zlib-ng` | … | … | … | `zlib-ng:zlib-ng` | … |
| `libgfortran` | `skip` | | | | | |

- **prefix** is how a file is found, **library** is what it turns out to
  be, and **cpe** and **osv** are how advisories name it. The three
  differ: no advisory says `libz`, and zlib-ng's CVEs name zlib-ng, not
  zlib.
- A prefix can map to several libraries (`libz` may be zlib or zlib-ng in
  compat mode). The prefix picks which recognizers to try; the strings in
  the file decide which one it is.
- A library can have several identity strings, one row each. Each must be
  a library string, not a header string: choosing it means reading
  upstream source, and that is what the manual step is for.
- `skip` marks a prefix the maintainer has looked at and isn't tracking,
  so it doesn't come back as a TODO.
- A map with only its header row is valid: part 1's first run starts from
  one.
- To find a prefix's upstream, read its most common strings in the library
  report (most libraries embed their project name and copyright), and
  check the package's build scripts, such as Pillow's
  `.github/dependencies.json`. If the strings fit two upstreams equally
  well, stop and ask the maintainer.

Rules:

- **Pre-flight finishes before anything is written.** Any failure is
  printed to stderr and exits 2:
  1. The episode and cache directories are outside any git working tree.
  2. The package list loads (roadmap 3.2), and so does the library map
     (roadmap 3.7).
  3. The episode's phase files are a run of finished phases with no gaps
     (01, 02, …) and no `.partial` file. Otherwise the error names every
     file to delete.
  4. If the episode has an `episode.json`, it matches this run's inputs: the
     list file's sha256, the count after clamping, the target and both size
     limits. A smoke run at `--count 2` and another at `--count 10`
     therefore need separate episode directories. The code version is
     recorded but not matched, so a phase can be rerun after a fix.
  5. The library map is expected to change between parts 1 and 2, so it
     isn't matched from the start. Phase 06 records its sha256; if the map
     has changed since, the error names phase 06's file and every later one
     to delete.
- **One line per package, or per library, per phase**, in list or map
  order: `schema_version`, `name` or `library`, `status` (`ok`, `skipped`
  or `error`), `reason`, and the phase's data. Per-binary results are
  nested inside the package's line, in the `inspect`, `strings` and
  `fingerprint` record formats. A package whose line in the previous
  per-package phase isn't `ok` gets a `skipped` line, never a missing one,
  whose reason is the phase where its line first wasn't `ok` (such as
  `02-fetch`). Every finished phase file has exactly one line per package
  or library. A bad zip or malformed ELF becomes an `error` line, not a crash.
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
  packages and libraries. The current one finishes, the `.partial` file
  stays, and `scan` exits 130. The next run stops at pre-flight until the
  file is deleted.
- **One phase at a time, no retries.** An `error` line stands. Only phases
  01, 02, 06 and 09 use the network, through an HTTP client (or, for 06,
  the git command) that tests replace with recorded responses or a
  synthetic repository.
- When every phase finishes, `scan` exits 0, even if some lines are
  `error`: errors are data. It exits 3 when it stops for the manual step.
  Counts by status go to stderr, and nothing goes to stdout.

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
- **2.2** ✓ Upstream string fixtures. A script reads a library's upstream git
  repository and, at every release tag, extracts each string the detector's
  patterns cite. It reads the C literal directly; no zlib or zlib-ng string
  is assembled from macros, so one that is stops the script with an error
  until a preprocessor step is added. It writes
  `tests/upstream/<library>.tsv` with one row per tag and string: tag, file
  and line, and the string. The fixtures are text and are committed;
  generating them needs the network, so the script runs outside pytest.
  Tests place each tag's strings in a synthetic binary and check that the
  detector reports that tag's library and version, allowing for spelling
  differences between tag names and strings (`2.1.0-beta1` versus
  `2.1.0.beta1`). A tag the detector misclassifies or misses fails the
  tests. Covers zlib and zlib-ng at every release tag.

### 3. Scan, part 1: find the bundled libraries

Builds `scan` through the manual step, following
[How a scan runs](#how-a-scan-runs).

From 3.3 on there is a `scan` that runs, and each later item adds to it.
`scan` runs the phases built so far and exits 0 after the last one; the
stop for the manual step arrives with phase 05 (3.7). After an item
merges, rerun the same command on the same episode: finished phases are
skipped, so only the new phase runs, because pre-flight matches the run's
inputs and not the code version. To rerun a phase after a fix, delete its
file and every later one. Smoke runs use the smoke list (3.2) with a small
`--count` and one episode directory per count, outside the repository:

```bash
uv run python -m pypiscan scan data/smoke.csv \
  --episode-dir ~/pypiscan/episodes/smoke-4 \
  --cache-dir ~/pypiscan/cache --count 4
```

- **3.1** ✓ PyPI client and wheel selection, plus
  `fetch <name>==<version> --cache-dir C`: read one release from PyPI's JSON
  API, choose its target wheel, download it into the cache and verify its
  sha256. Tests use recorded responses. Manual check: for five packages, the
  chosen file matches what `uvx pip download` picks with the flags in
  [Conventions](#conventions).
- **3.2** The package list format and loader, and the smoke list. A package
  list is a CSV file with columns `name` and `version`, at most 100 rows, in
  processing order. The loader rejects an empty list, more than 100 rows,
  missing fields, and names that collide after PEP 503 normalization
  (`Pillow` and `pillow` are the same package). The smoke list,
  `data/smoke.csv`, is hand-picked, at most 10 rows, ordered so that small
  counts exercise the most: first a wheel with a `<package>.libs/`
  directory (such as Pillow) and one with statically linked zlib (such as
  lxml), then a release with only pure-Python wheels (`no_target`) and one
  whose target wheel is over the wheel size limit (`too_large`). Each row
  pins the package's latest final release when the list is written.
  `data/README.md` says why each row is there. Manual check: every row's
  release exists on PyPI. **← current**
- **3.3** `scan`'s first runnable version: the command-line rules,
  pre-flight checks 1 to 4 without the library map, `episode.json`, and
  the phase runner
  (`.partial` files, one line per package, `skipped` lines, Ctrl-C, exit
  codes, counts on stderr), with phase 01. `episode.json` records both size
  limits from the start, although the zip-member limit is first applied in
  3.4, so episodes from smoke runs stay usable as phases are added. Manual
  check: a smoke run with `--count 4`, its `01-resolve.jsonl`, and a
  second run of the same command that skips phase 01 and exits 0.
- **3.4** Phases 02 and 03. Phase 02 reuses 3.1's download and skips
  wheels over the wheel size limit as `too_large`. In phase 03, a bad zip or
  malformed ELF becomes an `error` line, and zip members over the
  zip-member size limit are recorded and skipped. Manual check: rerunning
  3.3's smoke episode runs only phases 02 and 03.
- **3.5** `pypiscan strings <wheel>` and phase 04. `strings` lists, for each
  ELF binary, every printable string that contains a version-like token
  (digit runs separated by dots), with its offset and a template in which
  each digit run becomes `#`: `deflate 1.3.2 Copyright 1995-2026 …` becomes
  `deflate #.#.# Copyright #-# …`. Offline, like `inspect`. Grouping
  templates across many wheels is `scan`'s library report (3.7). Manual
  check: for lxml 6.1.3, `lxml/etree` lists zlib's `deflate` banner with
  that template, and rerunning the smoke episode runs only phase 04.
- **3.6** The full package list, `data/packages.csv`. A script outside
  pytest generates it: it walks a top-pypi-packages snapshot in rank order,
  keeps each project whose latest final release has a target wheel, and
  stops at 100. Most top packages are pure Python, so this goes well past
  rank 100. Wheels over the wheel size limit stay on the list; the limit is
  applied when scanning, so raising it doesn't mean regenerating the list.
  The snapshot month and the selection rule go in `data/README.md`.
  Versions are pinned, and refreshing the list is its own pull request.
- **3.7** Phase 05, `--library-map`, the library map's format and loader
  (pre-flight check 2), the library report, `library-map-todo.csv` and the
  stop for the manual step. The loader accepts a map with only its header
  row, and rejects missing fields, unknown columns and a prefix that is both
  `skip` and mapped. Manual check: a full run of `data/packages.csv` with
  `--count 100`; the PR includes the library report's prefixes, ordered by
  how many wheels carry them.
- **3.8** *(maintainer input)* The first library map: rows for the prefixes
  in 3.7's report, most frequent first, chosen by the maintainer.

Later: a per-wheel time limit, which needs a subprocess per wheel.

### 4. Scan, part 2: recognizers

Adding a library means adding rows to the library map, not code.

- **4.1** Phase 06, upstream strings. Moves the tag-walking in
  `scripts/upstream_fixtures.py` (2.2) into `scan`, reading the library map
  instead of the detectors' citations, and removes the script. The
  committed `tests/upstream/*.tsv` fixtures become copies of phase 06's
  output, so tests still check recognizers offline. Tests use a small
  synthetic git repository. Upstream repositories are read with the git
  command, replacing the script's dulwich code, as described in
  [Conventions](#conventions). This item adds that convention's test
  guard and its ruff exception, the one the maintainer has approved; the
  PR still calls the exception out.
- **4.2** Phase 07, recognizers built from phase 06's strings and checked at
  every tag. The hand-written zlib detector (2.1) is replaced once the
  generated recognizers pass its fixtures, including telling zlib from
  zlib-ng.
- **4.3** Phase 08, fingerprint with the recognizers. Manual check: compare
  results against Pillow 12.3.0's `.github/dependencies.json`.
- **4.4** *(maintainer input)* libwebp: it embeds no plain version string, so
  choose a detection method before implementing it.
- **4.5** Report shared libraries no recognizer identified, so gaps are
  visible.

### 5. SBOM comparison

- **5.1** Read PEP 770 SBOMs (CycloneDX JSON) into components.
- **5.2** Compare SBOM claims against fingerprint results: coverage and
  agreement statistics.

### 6. CVE data

- **6.1** CVE table format, loader and validation. Each row stores evidence,
  not just conclusions: fix commits, fixed version and release date per
  maintained branch, introduced version (or "unknown"), affected component
  (library code or a bundled tool), disputed status and sources. Seeded with
  CVE-2023-4863. Adds the `cpe` and `osv` columns to the library map.
- **6.2** Phase 09's importer: draft candidate rows for each library from
  NVD, by CPE, and OSV, by OSV identifier.
- **6.3** Range verifier: given phase 06's clone and a row's fix commits,
  compute the release tags that contain them and their dates; compare
  against the imported ranges and flag disagreements. Tests use a small
  synthetic git repository.
- **6.4** *(maintainer input)* Curation review: resolve flagged rows, one
  library per pull request. Corrections to public advisories are submitted
  upstream. A bug in an original library can also be in a fork's code
  (zlib-ng began as a fork of zlib) without any advisory naming the fork;
  that is decided here, by reading the code, not guessed by matching.

### 7. Matching

- **7.1** Phase 10, `match`: compare fingerprints against the CVE table and
  write candidates with their evidence level into the episode, which is
  outside the repository.
- **7.2** Evidence for levels 2 and 3: whether the affected function is
  present in the binary, and which extension modules import functions from
  the bundled library.

### 8. Publishing

- **8.1** Release script: a dated data snapshot plus a `SHA256SUMS` file,
  signed by the maintainer.

### Later (TBD)

- **Statically linked libraries.** Library code compiled into extension
  modules rather than shipped in `.libs/`: zlib in lxml and grpcio,
  OpenSSL in cryptography. There is no filename to start from, so
  discovery has to work from `strings` across every binary, and header
  strings (`compiled_against`) must not be mistaken for the library itself.
  Much more involved than the shared-library case.
- **Time-to-patch.** How long wheels kept shipping an affected version.
  Needs every release of each affected package, with upload times per file
  (depth, where `scan` is breadth). The clock starts when a fixed library
  release was public (the later of the fixed release and the CVE's
  publication) and stops at the first release whose wheel for that
  platform bundles a fixed version. Wheels still unpatched are counted as
  unfinished, not dropped. A pilot would follow libwebp CVE-2023-4863.

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
- Upstream repositories are read with the git command, not dulwich or a
  forge's API. `git tag --contains` answers the range verifier's question
  (6.3) locally, any host works (libtiff is on GitLab, libwebp on
  googlesource), and nothing needs a token.
  - Each repository is a bare, blobless clone in the cache
    (`git clone --bare --filter=blob:none`): every commit and tag, with a
    file's contents fetched the first time it is read. OpenSSL's is about
    80 MB.
  - A bare clone has no fetch refspec, so later runs fetch with explicit
    ones, `+refs/heads/*:refs/heads/*` and `+refs/tags/*:refs/tags/*`.
    `--mirror` would also copy GitHub's pull-request refs.
  - git runs from one module, by the absolute path `shutil.which` returns,
    with an argument list and never a shell. That module alone ignores
    ruff's S603, which flags every subprocess call however it is made.
- Tests build synthetic wheels in `tmp_path`. No real wheels or binaries are
  committed.
- Tests never touch the network, and there is no per-test escape hatch. Code
  that talks to PyPI, NVD or OSV is tested with recorded responses injected
  at the HTTP-client layer, not through a local server. Anything that
  genuinely needs a live network is an end-to-end check that lives outside
  the pytest suite.
- pytest-socket only sees sockets in the test process, not in a `git`
  subprocess. An autouse fixture in `tests/conftest.py` therefore sets
  `GIT_ALLOW_PROTOCOL=file` for every test, so git can only reach local
  repositories. It also sets `GIT_CONFIG_GLOBAL=/dev/null` and
  `GIT_CONFIG_NOSYSTEM=1`, so a developer's own git settings, such as commit
  signing or URL rewrites, don't change what tests do. Tests build their
  synthetic repositories with the git command in `tmp_path`.
- Wheels for manual checks are downloaded with `uvx pip download`, since uv
  virtual environments don't include pip. pip doesn't widen an explicit
  `--platform manylinux_2_28_x86_64` to older glibc versions (it widens only
  the legacy `manylinux2014` and `manylinux2010` tags), so every
  `manylinux_2_N` tag is listed to match the target wheel's rule. For
  example:

  ```bash
  uvx pip download --only-binary=:all: --no-deps \
    $(for n in $(seq 28 -1 5); do echo --platform manylinux_2_${n}_x86_64; done) \
    --platform manylinux2014_x86_64 \
    --python-version 3.12 -d /tmp/wheels pillow
  ```

## Development

Run as `python -m pypiscan <subcommand>`.

- `uv sync`: install dependencies and the project in editable mode.
- `uv run python -m pypiscan --help`: list subcommands.
- `uv run pytest`: run the tests (coverage is wired in via `pyproject.toml`).
- `scripts/check.sh`: runs exactly what CI runs. If it passes locally, CI
  should pass.
- `uv run python scripts/upstream_fixtures.py <library>`: clone the
  library's upstream repository into a temporary directory and regenerate
  `tests/upstream/<library>.tsv` from the detectors' citations. Needs the
  network.

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
