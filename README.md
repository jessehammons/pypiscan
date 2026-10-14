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

Each finding also carries the basis of the version it rests on (see
[How versions are identified](#how-versions-are-identified)). Identification
is best effort, so before anything is sent to a maintainer, the bundled
library and its version are confirmed by hand, whatever the basis.

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

Identification is best effort. Any string that can say which library a
binary holds, and which version, is used, and every result records the kind
of evidence it rests on. That way a wrong answer can be traced to its cause,
weaker results can be confirmed by hand, and aggregate statistics can say
which kinds they include. A version number means different things depending
on where it comes from, so each match is recorded as one of five kinds,
strongest first:

- **Library string**: a string from the upstream library's own source that
  identifies the library, usually by name, and gives its version, such as
  zlib's `deflate` and `inflate` copyright banners, `libpng version 1.6.58`
  or bzip2's `1.0.8, 13-Jul-2019`.
- **Build path**: a source path left in the binary by the library's build,
  usually through `assert` or `__FILE__`, whose directory names the library
  and its version, such as
  `/project/build/openjpeg-2.5.4/src/lib/openjp2/t1.c`. It shows which
  release's source was built.
- **Bare version**: a string that is only a version, such as `2.5.4`,
  defined in the library's own source, typically what its version function
  returns. It counts only in a `.libs/` file whose prefix the library map
  ties to that library, since such a file holds one library; anywhere else
  a bare version is ignored. When the prefix maps to several libraries, a
  bare version doesn't choose between them. Nothing around a bare version
  anchors it, so it must be three or more numbers separated by dots. That
  keeps out other libraries' header strings, such as `1.3.1.zlib-ng` in
  libpng, and numbers such as `001.000` in harfbuzz.
- **Header string**: a version macro from the library's public header, such
  as `ZLIB_VERSION`. Code that *calls* a library embeds it; for example,
  zlib's `deflateInit()` passes `ZLIB_VERSION` to the library. It shows
  which headers a binary was compiled against, never that the binary
  contains the library.
- **Filename**: the version suffix on a wheel member's name, such as
  `libz-….so.1.3.1`. It isn't part of the binary's contents, and for some
  libraries (libtiff, libwebp) it's an ABI number rather than a release.

The first three kinds show that a binary contains the library, and the
strongest kind present sets its version. A header string alone gives
`compiled_against`. A filename is corroboration only: it never sets a
version and never produces a record on its own.

Some libraries' version functions return a macro from their own public
header, such as OpenSSL's `OPENSSL_VERSION_TEXT` and harfbuzz's
`HB_VERSION_STRING`, so the same string can be a header string in code
that calls the library. In a `.libs/` file whose prefix the library map
ties to that library it is the library's own, and recognizers only run on
such files (phase 08).

Exported symbols and `DT_SONAME` are not version evidence.

Strings that can't identify a library are dropped before they are used.
Only strings in data sections (`.rodata`, `.data` and `.data.rel.ro`)
count, and known noise is removed: compiler and build notes (`GCC:`,
`annobin`), symbol versions (`@GLIBC_`), the build image's own paths
(`/opt/_internal/`) and object identifiers. A string is an object
identifier when every version-like token in it has six or more
dot-separated parts, such as OpenSSL's
`AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42`. Release versions can have
five (numpy's `OpenBLAS 0.3.34.106.0 …`), and a noise rule that drops a
real version hides it from matching too, so a string that also holds a
token of two to five parts, such as `ANSI X9.62`, is kept, along with a
few five-part spec references and OIDs. The noise list grows as the
library report shows more.
`strings` output and phase 04 keep everything; the filter applies where
strings are used, in the library report (phase 05) and in matching.

Rules for recognizers:

- A recognizer is a library map row's **pattern**: the string's text with
  `{version}` where the version is and `{any}` where text varies, such as
  `LIBTIFF, Version {version}` or `OpenSSL {version} {any}`. `{version}`
  captures a digit followed by letters, digits, `.`, `+`, `~` or `-`, and
  `{any}` matches any text, including none. A pattern matches whole
  strings, so `Since libtiff 4.5.1, …` in a libtiff 4.7.1 binary is never
  read as its version. A bare-version pattern is `{version}` alone, with
  the stricter shape above.
- Patterns start from the library report's templates (roadmap 3.5 and
  3.7). Upstream source then confirms each library string and bare
  version: which file defines or assembles it, and that it is the
  library's own string rather than another library's header string. Rows
  cite that file, at the release the report found, and come from reading
  upstream source, not from memory. Build paths come from the build, not
  from upstream source.
- Every pattern is tested against real strings. A committed fixture,
  `tests/recognizer_examples.tsv`, holds at least one string from the
  library report for each recognizer row, with the version it must give and
  the wheel and member it was seen in, and strings that must not match,
  such as libtiff's deprecation message.
- Patterns are not checked against older releases in version 1. Most
  version strings are filled in by the build system (OpenSSL's from
  `VERSION.dat`, libjpeg-turbo's from `CMakeLists.txt`) or assembled from
  macros, so a release tag doesn't hold the final string. Even where one
  does, as a C literal, it isn't always what shipped: harfbuzz's committed
  `hb-version.h` still said 1.7.6 at its 1.7.7 and 1.8.0 tags. Version 1
  scans current releases only, and before anything is sent to a maintainer
  the version is confirmed by hand. Checking patterns at every release tag
  returns with the work that needs older releases (see
  [Later](#later-tbd)).
- Versions are kept exactly as the string gives them, including four-part
  versions such as zlib 1.3.1.1.
- Some libraries have derivatives that carry their strings (zlib-ng for
  zlib; BoringSSL, LibreSSL and AWS-LC for OpenSSL). A binary is reported as
  the original only if it has the original's library strings and none of a
  derivative's. A derivative is reported with its own version, not the
  version it claims compatibility with. Only library strings can tell the
  two apart; if upstream source offers none that does, stop and ask the
  maintainer.

`fingerprint` writes JSON Lines with its own `schema_version`, one record
per binary, library and relation:

- `wheel`, `path`, `sha256`: as in `inspect`.
- `library`: such as `zlib` or `zlib-ng`.
- `relation`: `contains` when a library string, build path or bare version
  matched; `compiled_against` when only header strings did.
- `basis`: the kind that set the version (`library_string`, `build_path` or
  `bare_version`), or `header_string` for `compiled_against`.
- `version`: from the strongest kind present for `contains`; the header
  string verbatim for `compiled_against`; `null` when matches of that
  strongest kind disagree.
- `conflict`: `true` when any two matches that can set a version give
  different versions, even when a stronger kind settled it. Such records
  are checked by hand.
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
from and how to recognize it; part 2 clones those projects, builds
recognizers from the map and matches the versions it finds against CVEs.
The same command runs both parts: a rerun skips finished phases, so after
the map is edited, `scan` picks up at phase 06.

```
pypiscan scan <package-list> --library-map M --episode-dir D --cache-dir C --count N
```

- `--count` is required and takes the first N rows of the list: 1, 2, 5 or
  10 for smoke tests, 100 for a full run. If it is missing, `scan` prints
  its full help to stderr and exits 2. (argparse's `required=True` prints
  only the usage line, so the check is made after parsing.) A value below 1
  is an error and exits 2; a value larger than the list is clamped to its
  length.
- `--library-map` is required and names the committed library map,
  normally `data/libraries.csv`.
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
   `.libs/` directory, with its path and prefix: the filename cut at
   auditwheel's hash, `-` and 8 hex digits, so `libjpeg-1a2b3c4d.so.62.4.0`
   becomes `libjpeg`. A library repaired twice has two hashes, and the
   first one cuts. A name with no hash is cut at its first `.so`. Then the
   phase writes the library report into the episode, `library-report.md`:
   prefixes ordered by how many wheels carry them, and for each, how many
   wheels and files carry it, the packages carrying it, and all of its
   `strings` templates, ranked by how many wheels carry each one with ties
   in alphabetical order, each with one real example string. The report
   uses only strings that pass the noise filter (see
   [How versions are identified](#how-versions-are-identified)), and cuts
   templates longer than 200 characters to 200, so a long run of text
   doesn't become a template of its own.

**Manual step.** Once phase 05 is finished, in this run or an earlier one,
every run compares phase 05's prefixes with the current library map and
rewrites `library-map-todo.csv` in the episode, one row per prefix the map
doesn't list, in the map's columns with only `prefix` filled in. It is
derived from the map, not a phase file, so it is never skipped as
finished. If it has rows, `scan` lists the prefixes on stderr and
exits 3. The maintainer reads the report and, for each prefix, adds rows to
the library map (or marks the prefix `skip`), commits the map, and reruns
`scan`, which goes on to phase 06 once the todo is empty.

Part 2:

6. `06-upstream` (network, per library): clone the repository of every
   library the map names, with a recognizer or not, into the cache, or
   fetch into the existing clone (see [Conventions](#conventions)). The
   clone is needed for fixed versions (phase 09). The line lists the
   release tags the library's **tags** matches, each with the version it
   names. A library whose **tags** matches no tag is an `error` line, so a
   wrong repo or a misspelled pattern shows up before phase 09 relies on
   it.
7. `07-recognizers` (per library): build a recognizer from each of the
   library's rows that has a kind (see
   [How versions are identified](#how-versions-are-identified)), and list
   them in the library's line. A library with no recognizer gets a
   `skipped` line with reason `no_recognizer`.
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
the package list. One row per prefix, library and way of identifying it:

| prefix | library | repo | tags | kind | pattern | identity_file | identity | cpe | osv |
|---|---|---|---|---|---|---|---|---|---|
| `libtiff` | `libtiff` | `https://gitlab.com/libtiff/libtiff` | `v{version}` | `library_string` | `LIBTIFF, Version {version}` | `libtiff/tiffvers.h.in` | | `libtiff:libtiff` | … |
| `libfreetype` | `bzip2` | `https://sourceware.org/git/bzip2.git` | `bzip2-{version}` | `library_string` | `{version}, {any}` | `bzlib_private.h` | | `bzip:bzip2` | … |
| `libopenjp2` | `openjpeg` | `https://github.com/uclouvain/openjpeg` | `v{version}` | `build_path` | `{any}/openjpeg-{version}/{any}` | | | `uclouvain:openjpeg` | … |
| `libopenjp2` | `openjpeg` | `https://github.com/uclouvain/openjpeg` | `v{version}` | `bare_version` | `{version}` | `src/lib/openjp2/opj_config_private.h.cmake.in` | | `uclouvain:openjpeg` | … |
| `libwebp` | `libwebp` | `https://chromium.googlesource.com/webm/libwebp` | `v{version}` | | | | | `webmproject:libwebp` | … |
| `libgfortran` | `skip` | | | | | | | | |

- **prefix** is how a file is found, **library** is what it turns out to
  be, and **cpe** and **osv** are how advisories name it. The three
  differ: no advisory says `libz`, and zlib-ng's CVEs name zlib-ng, not
  zlib.
- A prefix can map to several libraries (`libz` may be zlib or zlib-ng in
  compat mode, and Pillow's `libfreetype` has bzip2 compiled into it). The
  prefix picks which recognizers to try; the strings in the file decide
  which one it is.
- **repo** is where the library's source is, and **tags** how its release
  tags are named, with `{version}` where the version is (`v{version}`,
  `openssl-{version}`). **repo** is required on every mapped row, and so
  is **tags** from roadmap 4.1 on: phase 06 clones every library and lists
  its release tags, and the range verifier (6.3) reads them. **tags** has
  exactly one `{version}` and no other placeholder. Some projects spell
  versions in tags with `_` or `-` (PostgreSQL's `REL_18_6`, OpenLDAP's
  `OPENLDAP_REL_ENG_2_6_15`, FreeType's `VER-2-14-3`), so in **tags**,
  `{version}` also takes `_`, and the version listed for a tag has each `_`
  or `-` between two digits replaced by `.`: `REL_{version}` lists
  `REL_18_6` as 18.6. Rows for one library agree on **repo**, **tags**,
  **cpe** and **osv**.
- **kind** is one of the version-setting kinds in
  [How versions are identified](#how-versions-are-identified), and
  **pattern** is the recognizer:
  - For `library_string` and `bare_version`, **identity_file** is the
    upstream source file that defines or assembles the string, at the
    release the report found. The string must be the library's own;
    choosing it means reading upstream source, and that is what the manual
    step is for.
  - **identity** is empty in version 1. It is kept for checking patterns
    at every release tag (see [Later](#later-tbd)): the variable or macro
    that holds the string, when it is one C literal.
  - A `bare_version` row's pattern is `{version}`.
  - For `build_path`, **identity_file** and **identity** are empty.
- A library can have several rows, one per way of identifying it. Prefer a
  library string; use a build path or a bare version for a library that
  embeds no library string.
- A row with a library and repo but no kind marks a library that is
  identified but has no recognizer yet, such as libwebp, which embeds no
  version string (roadmap 4.4). Under one prefix, a library has either
  recognizer rows or one such row. Phase 08 has nothing to run for it, and
  4.5 reports it.
- **cpe** and **osv** may be empty until the CVE table (6.1) requires
  them.
- `skip` marks a prefix the maintainer has looked at and isn't tracking,
  so it doesn't come back as a TODO. A `skip` row has every column empty
  except **prefix** and **library**.
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
     recorded but not matched, so a phase can be rerun after a fix. If the
     episode has phase files (finished or `.partial`) but no
     `episode.json`, their inputs can't be checked, and the error names
     them to delete.
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
  packages and libraries, and between phases. The current one finishes, the
  `.partial` file stays, and `scan` exits 130, even when the phase it
  interrupted was the last. The next run stops at pre-flight until the
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
  --library-map data/libraries.csv \
  --episode-dir ~/pypiscan/episodes/smoke-4 \
  --cache-dir ~/pypiscan/cache --count 4
```

- **3.1** ✓ PyPI client and wheel selection, plus
  `fetch <name>==<version> --cache-dir C`: read one release from PyPI's JSON
  API, choose its target wheel, download it into the cache and verify its
  sha256. Tests use recorded responses. Manual check: for five packages, the
  chosen file matches what `uvx pip download` picks with the flags in
  [Conventions](#conventions).
- **3.2** ✓ The package list format and loader, and the smoke list. A package
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
  release exists on PyPI.
- **3.3** ✓ `scan`'s first runnable version: the command-line rules,
  pre-flight checks 1 to 4 without the library map, `episode.json`, and
  the phase runner
  (`.partial` files, one line per package, `skipped` lines, Ctrl-C, exit
  codes, counts on stderr), with phase 01. `episode.json` records both size
  limits from the start, although the zip-member limit is first applied in
  3.4, so episodes from smoke runs stay usable as phases are added. Manual
  check: a smoke run with `--count 4`, its `01-resolve.jsonl`, and a
  second run of the same command that skips phase 01 and exits 0.
- **3.4** ✓ Phases 02 and 03. Phase 02 reuses 3.1's download and skips
  wheels over the wheel size limit as `too_large`. In phase 03, a bad zip or
  malformed ELF becomes an `error` line, and zip members over the
  zip-member size limit are recorded and skipped. Manual check: rerunning
  3.3's smoke episode runs only phases 02 and 03.
- **3.5** ✓ `pypiscan strings <wheel>` and phase 04. `strings` lists, for
  each ELF binary, every printable string that contains a version-like
  token (digit runs separated by dots), with its offset, its ELF section
  name (`null` when the offset maps to none, so `.rodata` strings can be
  told from compiler notes in `.comment`) and a template in which each
  digit run becomes `#`: `deflate 1.3.2 Copyright 1995-2026 …` becomes
  `deflate #.#.# Copyright #-# …`. Offline, like `inspect`. Grouping
  templates across many wheels is `scan`'s library report (3.7). Manual
  check: for lxml 6.1.3, `lxml/etree` lists zlib's `deflate` banner with
  that template, and rerunning the smoke episode runs only phase 04.
- **3.6** ✓ The full package list, `data/packages.csv`. A script outside
  pytest generates it: it walks a top-pypi-packages snapshot in rank order,
  keeps each project whose latest final release has a target wheel, and
  stops at 100. Most top packages are pure Python, so this goes well past
  rank 100. Wheels over the wheel size limit stay on the list; the limit is
  applied when scanning, so raising it doesn't mean regenerating the list.
  The snapshot month and the selection rule go in `data/README.md`.
  Versions are pinned, and refreshing the list is its own pull request.
- **3.7** ✓ Phase 05, `--library-map`, the library map's format and loader
  (pre-flight check 2), the library report, `library-map-todo.csv` and the
  stop for the manual step. The loader accepts a map with only its header
  row, and rejects missing fields, unknown columns, an unknown kind, a row
  whose fields don't fit its kind (a `build_path` row with an
  `identity_file`, or another kind without one) and a prefix that is both
  `skip` and mapped. The report applies the noise filter and the
  200-character template cut. Manual check: a full run of
  `data/packages.csv` with `--count 100`; the PR includes the library
  report's prefixes, ordered by how many wheels carry them.
- **3.8** ✓ The library map's patterns, and the first map. The loader takes
  the columns in [The library map](#the-library-map): it adds **tags** and
  **pattern**, accepts a mapped row with no kind (identified, no
  recognizer) and makes **identity** optional. It rejects a pattern
  without exactly one `{version}` or with any other placeholder than
  `{any}`, a `bare_version` pattern other than `{version}`, an identity
  without **identity_file** or **tags**, a library with both recognizer
  rows and a no-recognizer row under one prefix, rows for one library
  that disagree on **repo**, **tags**, **cpe** or **osv**, and a non-empty
  **tags** without exactly one `{version}` or with any other placeholder,
  so a typo can't make phase 06 match no tags and check nothing. Patterns
  compile to whole-string matchers, with the bare-version shape.
  `data/libraries.csv` gets a row for every prefix in 3.7's report, as the
  maintainer chose them, and `tests/recognizer_examples.tsv` the strings
  each recognizer row must match, taken from the full run's episode, plus
  strings that must not match: libtiff's deprecation message
  (`Since libtiff 4.5.1, …`), `1.3.1.zlib-ng` in libpng16 and `001.000` in
  libharfbuzz. Tests check every recognizer row against its examples.
  Manual check: rerunning 3.7's full episode with the new map writes an
  empty `library-map-todo.csv`, and `scan` exits 0.

Later: a per-wheel time limit, which needs a subprocess per wheel.

### 4. Scan, part 2: recognizers

Adding a library means adding rows to the library map, not code.

- **4.1** Phase 06, upstream clones and tags. Clones or fetches every
  library the map names, and lists the release tags its **tags** matches,
  each with its version; a library whose **tags** matches no tag is an
  `error` line. The loader requires **tags** on every mapped row and
  **identity** empty, and `data/libraries.csv` fills in **tags** for each
  library from its repository's tags and drops the two identities the
  first map had. Upstream repositories are read with the git command, as
  described in [Conventions](#conventions), and
  `scripts/upstream_fixtures.py` (2.2) moves from dulwich to the same git
  module, so dulwich leaves the dependencies. Tests use a small synthetic
  git repository. This item adds the convention's test guard and its ruff
  exception, the one the maintainer has approved; the PR still calls the
  exception out. **← current**
- **4.2** Phase 07, recognizers built from the library map's patterns:
  one line per library listing them, or `skipped` with reason
  `no_recognizer`.
- **4.3** Phase 08, fingerprint with the recognizers and the noise filter.
  Adds `basis` to fingerprint records and bumps their `schema_version`.
  Manual check: compare results against Pillow 12.3.0's
  `.github/dependencies.json`.
- **4.4** *(maintainer input)* The libraries the map marks as identified
  with no recognizer, such as libwebp, brotli, Little CMS, FreeType and
  libpq, which embed no version string: choose a detection method for each
  before implementing it.
- **4.5** Report shared libraries no recognizer identified, including the
  libraries the map marks as having none, so gaps are visible.

### 5. SBOM comparison

- **5.1** Read PEP 770 SBOMs (CycloneDX JSON) into components.
- **5.2** Compare SBOM claims against fingerprint results: coverage and
  agreement statistics.

### 6. CVE data

- **6.1** CVE table format, loader and validation. Each row stores evidence,
  not just conclusions: fix commits, fixed version and release date per
  maintained branch, introduced version (or "unknown"), affected component
  (library code or a bundled tool), disputed status and sources. Seeded with
  CVE-2023-4863. Requires `cpe` and `osv` on the library map's mapped
  rows.
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
  A pattern whose string comes from the library's public header, such as
  OpenSSL's, can't show the library is present outside its own `.libs/`
  file. Much more involved than the shared-library case.
- **Checking patterns at every release tag.** Statically linked libraries
  and time-to-patch need older releases, whose strings can be worded
  differently: before 2.1.0, zlib-ng named and worded its identity string
  differently, and a pattern written from 2.3.3 alone missed it. Where a
  library's string is one C literal, a row's **identity** names it, and
  the pattern is checked against that literal at every release tag,
  allowing for spelling differences between tags and strings (`2.1.0-beta1`
  and `2.1.0.beta1`) and for known exceptions: bzip2's `BZ_VERSION` has
  no date before 1.0.1, and harfbuzz's committed `hb-version.h` still said
  1.7.6 at its 1.7.7 and 1.8.0 tags. The hand-written zlib detector (2.1)
  becomes map rows once they pass its fixtures (2.2), including telling
  zlib from zlib-ng.
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
- Aggregate statistics say which identification bases they include, such
  as library strings only, or all kinds.

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
- `uv run python scripts/top_packages.py`: regenerate `data/packages.csv`
  from the current top-pypi-packages snapshot (see `data/README.md`). Needs
  the network.

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
