# pypiscan

Inventories the compiled C libraries bundled inside PyPI wheels, identifies
their versions from the binaries themselves, measures how far behind
upstream those versions were when each wheel was uploaded, and matches
them against known CVEs.

Status: early development. see the [Roadmap](#roadmap) for
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
- How stale each bundled library was: how far its version lagged
  upstream's releases when the wheel was uploaded (see
  [The staleness report](#the-staleness-report)).
- A curated [CVE table](#the-cve-table) covering high and critical CVEs
  from 2020 onward for those libraries, found through NVD.

Statically linked libraries were out of scope for version 1 and are
its next step (see
[Mini-roadmap: statically linked libraries](#mini-roadmap-statically-linked-libraries)).
Out of scope for version 1, and listed under [Later](#later-tbd):
time-to-patch (how long wheels kept shipping an affected version).

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

Every basis is a signal for deciding whether a CVE might be worth
investigating, not a conclusion. Every version pypiscan reports, in its
records and in every report a person reads, is shown with the basis it
rests on, so a reader can always tell which signal a version came from.

A bare version is the weakest signal. When it is a finding's basis,
another source must confirm the version before the finding is sent: the
package's build scripts, an SBOM in the wheel, or a library string found
by hand.

An ambiguous version (see [Ambiguous versions](#ambiguous-versions))
may be any of the releases that share it, so a finding that rests on
one names them all, and which one shipped is confirmed before it is
sent.

## Sources of truth

- **The wheel's binaries** are what users actually run, and the primary
  measurement.
- **A package's build scripts** show what the maintainers intended (for
  example, Pillow pins its bundled library versions in
  `.github/dependencies.json`). They serve as an answer key for checking
  version detection, and for triage. Disagreements between the two are
  findings.
- **SBOMs in the wheel** are claims about what it bundles, made by the
  tools that built it (see [SBOMs in wheels](#sboms-in-wheels)). They
  are compared with the binaries (roadmap 5.2) and never change what
  the binaries show.
- **The upstream library's git history** is the ground truth for a CVE's
  fixed versions: a release is fixed when its tag contains a fix's
  commits, and a backport is a commit of its own (see
  [The CVE table](#the-cve-table)). The CVE table stores the fix commits,
  so every range can be recomputed.
- **NVD** is used to find candidate CVEs, their severity and links to
  their fix commits. Version 1 uses no other advisory source (see
  "Other advisory sources" under [Later](#later-tbd)). NVD's version
  ranges for C libraries are often wrong and are never used unverified.

## How versions are identified

Identification is best effort. Any string that can say which library a
binary holds, and which version, is used, and every result records the kind
of evidence it rests on. That way a wrong answer can be traced to its cause,
weaker results can be confirmed by hand, and aggregate statistics can say
which kinds they include. A version number means different things depending
on where it comes from, so each match is recorded as one of six kinds,
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
- **Version function machine code**: what an exported function whose job
  is to report the library's version returns, read from the function's
  machine code without running it. In Pillow 12.3.0's libwebp,
  `WebPGetDecoderVersion` is `mov eax, 0x10600; ret`, which is 1.6.0. Only
  a few exact code shapes are read (see
  [Version function machine code](#version-function-machine-code)); any
  other code gives nothing. The function's name ties its result to its
  library, which a bare version lacks, so it ranks above one and counts
  under a prefix that maps to several libraries. It is still a signal, not
  a conclusion: a decoding rule can be wrong for a release it wasn't
  checked against, and a fork can keep the function and change its
  result.
- **Bare version**: a string that is only a version, such as `2.5.4`,
  defined in the library's own source, typically what its version function
  returns. It counts only in a `.libs/` file whose prefix the library map
  ties to that library, since such a file holds one library; anywhere else
  a bare version is ignored. When the prefix maps to several libraries, a
  bare version doesn't choose between them. Nothing around a bare version
  anchors it, so it must be three or more numbers separated by dots. That
  keeps out other libraries' header strings, such as `1.3.1.zlib-ng` in
  libpng, and numbers such as `001.000` in harfbuzz. A bare version is a
  hint, the weakest evidence that sets a version: a finding that rests on
  one needs another source to confirm the version (see
  [How findings are classified](#how-findings-are-classified)).
- **Header string**: a version macro from the library's public header, such
  as `ZLIB_VERSION`. Code that *calls* a library embeds it; for example,
  zlib's `deflateInit()` passes `ZLIB_VERSION` to the library. It shows
  which headers a binary was compiled against, never that the binary
  contains the library.
- **Filename**: the version suffix on a wheel member's name, such as
  `libz-….so.1.3.1`. It isn't part of the binary's contents, and for some
  libraries (libtiff, libwebp) it's an ABI number rather than a release.

The first four kinds show that a binary contains the library, and the
strongest kind present sets its version. A header string alone gives
`compiled_against`. A filename is corroboration only: it never sets a
version and never produces a record on its own.

Some libraries' version functions return a macro from their own public
header, such as OpenSSL's `OPENSSL_VERSION_TEXT` and harfbuzz's
`HB_VERSION_STRING`, so the same string can be a header string in code
that calls the library. In a `.libs/` file whose prefix the library map
ties to that library it is the library's own, and recognizers only run on
such files (phase 08). Phase 10 runs some of them on the other binaries,
where a match is only an unconfirmed candidate (see
[The static discovery report](#the-static-discovery-report)).

An exported symbol's presence and `DT_SONAME` are not version evidence.
What a version function's machine code returns is.

Strings that can't identify a library are dropped before they are used.
Only strings in data sections (`.rodata`, `.data` and `.data.rel.ro`)
count, and known noise is removed: compiler and build notes (`GCC:`,
`annobin`), symbol versions (`@GLIBC_`), the build image's own paths
(`/opt/_internal/`) and object identifiers. A string is an object
identifier when every version-like token in it has six or more
dot-separated parts, such as OpenSSL's
`AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42`. Versions in binaries can
have five (numpy's `OpenBLAS 0.3.34.106.0 …`, which isn't a release; see
"Versions that aren't releases" under [Later](#later-tbd)), and a noise
rule that drops a real version hides it from matching too, so a string
that also holds a token of two to five parts, such as `ANSI X9.62`, is
kept, along with a few five-part spec references and OIDs. The noise list
grows as the library report shows more.
`strings` output and phase 04 keep everything; the filter applies where
strings are used, in the library report (phase 05), in matching (phases
08 and 10) and in the static discovery report.

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
- `relation`: `contains` when a library string, build path, version
  function machine code or bare version matched; `compiled_against` when
  only header strings did.
- `linkage`: where the library was found, by the binary's location:
  `shared_lib` when it was found in a `.libs/` file through that file's
  prefix (phase 08), and `static_lib` when it was found in a binary
  outside `.libs/` (phase 10), such as pyarrow's bzip2 in
  `pyarrow/libarrow.so.2600`, though that file is itself a shared
  library. The `fingerprint` command sets it the same way, by whether the
  binary is in a `.libs/` directory. It is a closed set, and other values
  may come later, such as a library shipped as an executable (ffmpeg);
  every reader fails on a value it doesn't know. A record from before
  `schema_version` 4 has none, and is read as `shared_lib`, since phase 08
  wrote all of them.
- `basis`: for `contains`, the strongest kind present (`library_string`,
  `build_path`, `version_function_machine_code` or `bare_version`): the
  kind that sets the version, or would if its matches agreed. For
  `compiled_against`, `header_string`.
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

### Version function machine code

Some libraries embed no version string but export a function whose only
job is to report the version, such as libwebp's `WebPGetDecoderVersion` or
libpq's `PQlibVersion`. A `version_function_machine_code` row names such a
function and says how its result gives the version. Phase 08 looks the
function up among the defined functions in the file's `.dynsym`, reads its
code from the cached wheel, and accepts only these shapes, optionally after
`endbr64`:

- it returns an integer (`mov eax, imm32; ret`);
- it returns a pointer to a string in the file
  (`lea rax, [rip+disp32]; ret`);
- it stores three integers, the major, minor and patch numbers, through its
  three pointer arguments, then returns.

Each shape is accepted both as an optimizing compiler emits it and as an
unoptimized build does, inside `push rbp; mov rbp, rsp` and `pop rbp;
ret`: Pillow 12.3.0 builds lcms2 and FreeType, and pyzmq 27.2.0 builds
libzmq, without optimization. Any other code gives nothing, so a misread
function is a missed version, not a wrong one.

The row's **pattern** is the function's name, `->`, and how its result
gives the version:

- `bits` and the widths of the version's fields in bits, most significant
  first, with `*` for the top field: `WebPGetDecoderVersion -> bits *.8.8`
  reads 0x10600 as 1.6.0, and `BrotliDecoderVersion -> bits *.12.12` reads
  0x1002000 as 1.2.0.
  It can end with `from`, as `decimal` does: before libwebp 1.0.0,
  `WebPGetDemuxVersion` and `WebPGetMuxVersion` returned the demux and
  mux libraries' own versions (0.3.3 and 0.4.1 in libwebp 0.6.1), so
  their rows end with `from 65536`, which is 1.0.0.
- `decimal` and the fields' widths in decimal digits, the same way, then
  `from` and the smallest value the encoding holds for. A smaller value
  gives nothing: `PQlibVersion -> decimal *.4 from 100000` reads 170011 as
  17.11, and PostgreSQL before 10 encoded its versions differently.
- `out`, for three integers stored through pointer arguments:
  `zmq_version -> out` reads 4, 3 and 5 as 4.3.5.
- `string` and a recognizer pattern that must match the whole string:
  `avifVersion -> string {version}`, and dav1d's
  `dav1d_version -> string {version}-0-g{any}`. In Pillow 12.3.0,
  `avifVersion` points into the tail of an unrelated message,
  `…Section 7.3.11.4.2`, because the linker merged the two, so no string
  in the file is libavif's version on its own. dav1d's string is
  `git describe` output, such as `1.5.3-0-gb546257`; `-0-g` means the build
  was made exactly at a release tag, so a build made between releases
  matches nothing.

Rules for these rows:

- **identity_file** is the upstream source file that defines the function,
  at the release the binary gives.
- Before a row is added, its encoding is checked by hand against the
  library's version macros at every release tag, and the check is recorded
  in the pull request.
  Values two releases share are listed as ambiguous (see
  [Ambiguous versions](#ambiguous-versions)); pre-release tags, such
  as `lcms2.19rc1`, aren't releases and aren't checked.
- The derivative rule for library strings applies: a row is added only
  after checking for derivatives that keep the function and change its
  result, as zlib-ng's `zlibVersion` returns `1.3.1.zlib-ng`.
- Every row is tested against real code. A committed fixture,
  `tests/version_function_examples.tsv`, holds for each row the function's
  bytes from a real wheel (and, for a string, the string it points to),
  the version they must give, and the wheel and member they came from. It
  also holds code that must give nothing, such as FreeType's
  `FT_Library_Version`, which copies the version out of a struct.
- A match's evidence has the function's name and its result as read, such
  as `WebPGetDecoderVersion: 0x10600`, `avifVersion: "1.4.2"` or
  `zmq_version: 4, 3, 5`, and the file offset and section of the
  function's first byte.

### Ambiguous versions

A version is ambiguous when the library's own version macros give two
releases the same value, so a binary from either reads the same.
lcms2's `cmsGetEncodedCMMversion` returns 2190, read as 2.19.0, for
both 2.19 and 2.19.1, and libavif's v0.3.1 tag still says 0.3.0 in
`avif.h`. The every-tag check before a version function row is added
finds them, and each is listed in `data/ambiguous_versions.csv`: the
library, the version as its encoding spells it, and the other release
it may be.

| library | version | ambiguous_with |
|---|---|---|
| `lcms2` | `2.19.0` | `2.19.1` |
| `libavif` | `0.3.0` | `0.3.1` |

The list applies to a library's version whatever its basis, so a bare
version that reads the same is marked too: marking too much costs a
check by hand, and marking too little hides a candidate. Records keep
the version as read. The fingerprint report notes
`ambiguous: may also be 2.19.1`, and 7.1 checks a CVE against the
version and every release it may be, so an ambiguous version can add
a candidate but never hide one. The report reads the list on every
run, so editing it needs no phase file deleted.

## SBOMs in wheels

[PEP 770](https://peps.python.org/pep-0770/) puts a wheel's SBOMs in its
`.dist-info/sboms/` directory. It allows any format, recommends a
standard one in JSON, and allows several files. Every SBOM in the
top-100 scan's wheels was CycloneDX JSON, of three kinds:

- **auditwheel's**, `auditwheel.cdx.json`, which `auditwheel repair`
  writes from version 6.5.0 on, in CycloneDX 1.4. After the wheel
  itself, it has one component for each file auditwheel copied in that
  a distribution package owns, as the build image's package manager
  reports it: the package's name and version, and a purl such as
  `pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9`. A package that owns
  several of the files appears once for each. Libraries built from
  source get no component, and a wheel with no packaged library gets
  no SBOM. A component names neither its library nor its file in the
  wheel; its bom-ref ends with the sha256 of the file's path on the
  build machine.
- **A project's own**, such as Pillow's, generated from its
  `.github/dependencies.json` and embedded unchanged in every wheel of a
  release. Pillow 12.3.0's marks FreeType and other libraries its wheel
  carries `optional`, which CycloneDX 1.7 defines as not installed;
  lists `zlib` 2.3.3, the zlib-ng version it pins, though its binaries
  load the system's zlib (roadmap 2.1); and leaves out libpng, xz and
  brotli, which its wheel carries.
- **A Rust extension's**, written by cargo-cyclonedx: the crates
  compiled in, among them `-sys` crates for C libraries, some with the
  library's version in their build metadata, such as
  `zstd-sys 2.0.16+zstd.1.5.7`.

An SBOM is a claim, and pypiscan treats it as one:

- It never sets or changes a version in fingerprint records. 5.2
  compares the two, and a disagreement is a finding, as one between
  the binaries and the build scripts is.
- A missing SBOM, or a library with no component, shows nothing.
  Wheels repaired before auditwheel 6.5.0 have no SBOM, and a
  project's SBOM can leave libraries out, so a missing component never
  shows an upstream build (level 2 in
  [How findings are classified](#how-findings-are-classified)).
- An auditwheel component marks its file as a distribution package's
  build, whose version is the package's and can carry backported
  fixes (see "Libraries from the build image's packages" under
  [Later](#later-tbd)). The claim rests on which package owns the
  file's path, not on its bytes, so a library a build installed over a
  packaged file would still be claimed.
- A build can change a wheel after auditwheel writes its SBOM:
  numba 0.68.0's deletes `numba.libs/` after repair, so its SBOM
  names a libgomp the wheel doesn't carry.
- A project's SBOM generated from its build scripts isn't a second
  source beside them, and it isn't a list of what one wheel carries.
- `scope` is recorded, never interpreted: cargo-cyclonedx marks build
  and dev dependencies `excluded`, as CycloneDX defines it, but Pillow
  marks libraries its wheel carries `optional`.

`sbom` writes JSON Lines with its own `schema_version`, one record per
file under a top-level `*.dist-info/sboms/` directory of the wheel,
subdirectories included. A wheel with no such file gives no records.

- `wheel`, `path`, `size`, `sha256`: as in `inspect`.
- `format`: `cyclonedx-json` for JSON whose top level is an object with
  `bomFormat` `CycloneDX`, `spdx-json` for one with `spdxVersion`, and
  `other` for anything else. The file's name isn't used.
- `spec_version`: CycloneDX's `specVersion` verbatim, or `null`.
- `tools`: each tool in `metadata.tools`, as its `name` and `version`,
  from either form CycloneDX allows: a list of tools (1.4's form, still
  allowed later, which auditwheel and cargo-cyclonedx write) or an
  object holding `components` and `services` (1.5 on, which Pillow
  writes). Empty when there are none.
- `components`: every component, nested ones included, in document
  order: each one, then those nested in it. Each has `bom-ref`, `type`,
  `name`, `version`, `purl` and `scope` verbatim, `null` when absent,
  and `parent`, the index in this list of the component it is nested
  in, or `null`. A purl is never derived from a bom-ref: Pillow's
  libraries have bom-refs such as `pkg:generic/freetype2` and no purl.
- `subject`: `metadata.component`, with a component's fields except
  `parent`, or `null`.
- `error`: why the file wasn't read in full, or `null`: `too_large` for
  a file over the zip-member size limit (phase 09 only), which isn't
  read, so its `sha256` and `format` are `null`; `not_json`; or
  `wrong_type` and the path of the CycloneDX field whose type is wrong,
  such as `wrong_type: components[3].version`.

Only `cyclonedx-json` files without an `error` have `tools`, `subject`
and `components`. For every other file all three are `null`, so a file
that was only partly read never looks complete.

### Comparing SBOMs with fingerprints

Once phase 09 is finished, every run rewrites `sbom-report.md` in the
episode from phases 05, 08 and 09, as it rewrites the fingerprint
report (roadmap 5.2). Records and the fingerprint report don't change.
Only auditwheel's components are compared: each claims a file, and a
file is what pypiscan measures. Other SBOMs are listed, with their
components counted (see "Comparing project SBOMs" under
[Later](#later-tbd)).

A component is tied to a `.libs/` file by its bom-ref, and only by an
exact match:

- The bom-ref must be the component's purl, `#` and 64 lowercase hex
  digits, in a file whose tools include `auditwheel`. The wheel's own
  component has no such bom-ref and isn't counted.
- For each `.libs/` file in the same wheel, the name auditwheel copied
  it from is rebuilt: the part before the first `.` loses its trailing
  `-` and 8 hex digits, so `libkrb5-fcafa220.so.3.3` was
  `libkrb5.so.3.3`. A file whose name has no such part has no name to
  rebuild.
- That name is joined to each of `/lib64/`, `/usr/lib64/`, `/lib/` and
  `/usr/lib/`, and a path whose sha256 is the bom-ref's hex digits ties
  the component to the file. In psycopg2-binary 2.9.13 and Pillow
  12.3.0, every component matched one file this way, under `/lib64/`.
- A component that matches no file, or more than one, is tied to none
  and listed. The directories are a guess, but a guess can only miss a
  tie, never make a wrong one.

A tied file is compared when the library map ties its prefix to one
library, and that library's `contains` record for the file has a
version. The package's version is cut to its upstream release:
everything from its last `-` is dropped (rpm's release, apk's `-rN`,
a deb revision), and a deb version also loses a leading epoch (`N:`).
A component whose purl isn't `pkg:rpm`, `pkg:deb` or `pkg:apk`, or
that has no version, isn't compared. The two agree when the cut
version equals the fingerprint version, or a release that version may
be (see [Ambiguous versions](#ambiguous-versions)), and differ
otherwise; a difference is checked by hand. Any other tied file isn't
compared, and the report says why: two components are tied to it, its
prefix isn't in the map (`not in map`), its prefix maps to several
libraries, so the package's version could be set against the wrong one,
or the fingerprint report's reason for having no version.

Agreement is two signals saying the same thing, not proof. When the
fingerprint version is a bare version, it is the kind of second source
[How findings are classified](#how-findings-are-classified) asks for.

The report starts with counts, saying they cover auditwheel's SBOMs
only:

- packages scanned in phase 09, with any SBOM and with auditwheel's;
- auditwheel components that name a file, tied and not tied;
- `.libs/` files in scanned packages, tied and not tied;
- tied files that agree or differ, by the fingerprint version's basis,
  and tied files not compared, by reason.

Then, for each package with an SBOM or a `.libs/` file:

- its SBOM files, each with its tools and component count, whether its
  components are compared, or its error;
- each `.libs/` file with the component tied to it (name, version and
  purl) or none, and for a tied file the comparison, with the
  fingerprint version, basis and notes shown as the fingerprint report
  shows them;
- auditwheel components tied to no file, with their bom-refs.

A package that wasn't scanned in phase 09 shows the phase where it
stopped and that phase's reason, as in the fingerprint report.

### The bundled-library atlas

Once phase 09 is finished, every run rewrites `atlas.md` in the episode
from phases 01 to 05 and 09 and the library map, as it rewrites the SBOM
report; phases 03 and 04 only show where a package stopped. Records and
other reports don't change. The atlas is meant to be read outside the
project, so its top says what it covers:

- It lists only shared libraries in a wheel's `.libs/` directory.
  Libraries compiled into extension modules or other libraries, such as
  cryptography's OpenSSL or lxml's zlib, aren't in it (see
  [Findings so far](#findings-so-far)).
- It names what wheels carry, not versions: versions and their basis are
  in `fingerprint-report.md`, and SBOM claims in `sbom-report.md`.
- A build image is shown only where an auditwheel component is tied to
  the file. No image doesn't mean an upstream build.

Then counts:

- packages in the episode, wheels opened in phase 05, and packages
  skipped, by phase and reason;
- wheels with a `.libs/` directory (the rows) and their `.libs/` files;
- libraries by the map's name, and prefixes not in the map with their
  files;
- rows by platform tag;
- rows with an SBOM, by kind, and scanned wheels with an SBOM but no
  `.libs/`, by kind (they are in `sbom-report.md`, not here); a wheel
  with several kinds counts under each, so the kinds can sum to more
  than the wheels;
- rows with a file tied to an auditwheel component, and tied files by
  build image.

Then a table, one row per wheel with a `.libs/` file, by package name:
package, version, platform tag, SBOM, build image, libraries.

- **platform tag** is the wheel filename's platform tag verbatim, such as
  `manylinux_2_17_x86_64.manylinux2014_x86_64`.
- **SBOM** is each SBOM file's kind, distinct kinds joined with `, `: for
  a CycloneDX file without an error, its tools' names joined with `+`
  (`auditwheel`, `cargo-cyclonedx`, or the name a project's file gives),
  or `cyclonedx-json, no tools`; otherwise its format (`spdx-json`,
  `other`) or `error: <error>`. A wheel with no SBOM shows `none`; a
  package whose phase 09 line is an error shows
  `error at 09-sboms: <reason>`.
- **build image** is each distinct image of the wheel's tied components,
  or `—`.
- **libraries**: a prefix the map ties to one library appears under that
  library's name, once per wheel however many prefixes and files it has,
  so OpenBLAS's five prefixes are one library. Any other prefix appears
  as itself, in code font, with a label: `` `libfoo` (not in map) ``,
  `` `libgfortran` (skip) `` for a map row whose library is `skip`, and
  `` `libfreetype` (freetype, bzip2) `` for a prefix the map ties to
  several libraries. Names are plain text and prefixes always in code
  font, so a prefix is never read as a library pypiscan identified. Each
  entry shows in brackets the distinct images of its tied files, such as
  `krb5 [CentOS 7]`. Entries are sorted.

A tied component's build image comes from its purl only. The
distribution is the purl's namespace, displayed as CentOS, AlmaLinux,
Rocky Linux, RHEL, Debian, Ubuntu or Alpine for `centos`, `almalinux`,
`rocky`, `rhel`, `debian`, `ubuntu` or `alpine`, any other namespace
verbatim, and `unknown` with none. The release is known only for
`pkg:rpm` whose version's last `-` part contains `.el` and digits: those
digits, so `1.15.1-55.el7_9` is 7 and the image is `CentOS 7`. Any other
purl shows `<distribution>, release unknown`. A wheel whose components
name different images lists each; none is picked.

Below the table, every package without a row that wasn't opened, with
the phase where it stopped and that phase's reason, as the fingerprint
report shows it, such as `skipped at 02-fetch: too_large`.

## How a scan runs

`scan` runs every package on a committed list through a fixed sequence of
phases, finishing each phase before starting the next. It covers breadth:
the latest release of many packages, and only the shared libraries bundled
in their `<package>.libs/` directories. Statically linked libraries are
the [mini-roadmap](#mini-roadmap-statically-linked-libraries), which
starts with phase 10 and
[the static discovery report](#the-static-discovery-report).
Time-to-patch is [Later](#later-tbd).

A scan runs in two parts with a manual step between them. Part 1 finds the
bundled libraries; the maintainer then says, in the
[library map](#the-library-map), which upstream project each one comes
from and how to recognize it; part 2 clones those projects, builds
recognizers from the map, reads the wheels' SBOMs, lists candidates for
statically linked libraries and matches the versions it finds against
CVEs.
The same command runs both parts: a rerun skips finished phases, so after
the map is edited, `scan` picks up at phase 06.

```
pypiscan scan <package-list> --library-map M --ambiguous-versions A \
  --cve-table T --line-eol L --episode-dir D --cache-dir C --count N \
  [--stop-after NN] [--skip-map-todo] \
  [--wheel-size-limit MB] [--member-size-limit MB]
```

- `--count` is required and takes the first N rows of the list: 1, 2, 5 or
  10 for smoke tests, 100 for a full run. If it is missing, `scan` prints
  its full help to stderr and exits 2. (argparse's `required=True` prints
  only the usage line, so the check is made after parsing.) A value below 1
  is an error and exits 2; a value larger than the list is clamped to its
  length.
- `--library-map` is required and names the committed library map,
  normally `data/libraries.csv`.
- `--ambiguous-versions` is required and names the committed list of
  ambiguous versions, normally `data/ambiguous_versions.csv` (see
  [Ambiguous versions](#ambiguous-versions)).
- `--cve-table` is required and names the committed CVE table, normally
  `data/cves.toml` (see [The CVE table](#the-cve-table)).
- `--line-eol` is required and names the committed list of lines' ends
  of life, normally `data/line_eol.csv` (see
  [Lines' ends of life](#lines-ends-of-life)).
- `--stop-after` is optional and takes a phase's two-digit number, 01 to
  11; any other value exits 2. `scan` runs through phase NN, skipping
  finished phases, writes the reports the finished phases allow, prints
  `stopped after NN-<phase>` to stderr after the counts and exits 0, so a
  manual check needn't wait out phase 11. If phase NN is already
  finished, no phase runs and the reports are rewritten. The manual step
  still stops a run before NN with exit 3. It isn't recorded in
  `episode.json`, so a later run without it carries on from phase NN+1.
- `--skip-map-todo` is optional. The manual step still rewrites
  `library-map-todo.csv` and lists its prefixes, but doesn't stop the run,
  so part 2 runs on the prefixes the map lists, and a `.libs/` file whose
  prefix it doesn't list shows as `not in map` in the reports. Like
  `--stop-after`, it isn't recorded in `episode.json`, so a later run
  without it stops at the manual step again, before any report is
  rewritten. Adding rows to the map afterwards means deleting phase 06's
  file and every later one (pre-flight check 5).
- `--wheel-size-limit` and `--member-size-limit` are optional and set the
  wheel size limit and the zip-member size limit, in MB of 1,000,000
  bytes: 100 and 512 by default. A value below 1 exits 2. Both are
  recorded in `episode.json` and matched by pre-flight check 4, so an
  episode run with raised limits needs them on every rerun.
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
size limit, by the size PyPI reports (100 MB by default), resolves
normally in phase 01, and phase 02 records it as `skipped` with reason
`too_large` without downloading it. Phases 03 and 04 skip zip members
larger than the zip-member size limit, 512 MB uncompressed by default,
since each member is read into memory, and phase 09 doesn't read such a
file.

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
   becomes `libjpeg`. A hash joined with `.`, such as `libz.915b4635`, isn't
   auditwheel's but is cut the same way, so it becomes `libz`. A library
   repaired twice has two hashes, and the first hash in the name cuts. A
   name with no hash is cut at its first `.so`. Then the phase writes the
   library report into the episode, `library-report.md`:
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
exits 3, unless `--skip-map-todo` is given. The maintainer reads the
report and, for each prefix, adds rows to the library map (or marks the prefix `skip`), commits the map, and reruns
`scan`, which goes on to phase 06 once the todo is empty.

Part 2:

6. `06-upstream` (network, per library): clone the repository of every
   library the map names, with a recognizer or not, into the cache, or
   fetch into the existing clone (see [Conventions](#conventions)). The
   clone is needed for fixed versions (phase 11). The line lists the
   tags the library's **tags** matches, each with the version it names,
   its date, the day `git for-each-ref` gives as `%(creatordate:short)`
   (see [The CVE table](#the-cve-table)), and `release`, whether it is a
   release by the map's rule (see [The library map](#the-library-map)),
   which the staleness report and the range verifier (6.3) read. A library whose **tags** matches no tag
   is an `error` line, so a
   wrong repo or a misspelled pattern shows up before phase 11 relies on
   it. A host that can't be reached gives an `error` line too.
7. `07-recognizers` (per library): build a recognizer from each of the
   library's rows that has a kind (see
   [How versions are identified](#how-versions-are-identified)), and list
   them in the library's line. A library with no recognizer gets a
   `skipped` line with reason `no_recognizer`. It doesn't depend on phase
   06, because recognizers come from the map, so a library whose clone was
   skipped or failed still gets them.
8. `08-fingerprint` (per package): run the recognizers on each shared
   library whose prefix maps to them, giving `fingerprint` records with
   linkage `shared_lib`. It
   compiles the recognizers from phase 07's lines, so phase 07's file is the
   record of what ran, and matches them against the library's strings in
   phase 04's records that pass the noise filter, without reading the wheel
   again. Phase 04 lists only strings with a version-like token (digit runs
   joined by dots), so a recognizer whose string has none never matches.
   Version function machine code is the exception: for a file whose prefix
   has such a recognizer, phase 08 reads the file from the wheel at phase
   02's path and decodes the function (see
   [Version function machine code](#version-function-machine-code)).
   Each file it reads must match phase 04's sha256. A missing wheel or
   member, a changed file or an ELF pyelftools can't parse makes the
   package's line `error`, so rerunning phase 08 needs the wheel cache.
   Once phase 08 is finished, every run rewrites `fingerprint-report.md`
   in the episode from phases 05, 07 and 08, as it rewrites
   `library-map-todo.csv`: for each package, every `.libs/` file and each
   library its prefix maps to, with the version and its basis, marking an
   ambiguous version, or why there is none (roadmap 4.5). A file whose
   prefix isn't in the map gets one row, with `—` for the library and the
   reason `not in map`, and the report's first lines count such files and
   their prefixes.
   A package that wasn't scanned shows the phase where it stopped and
   that phase's reason, such as `skipped at 02-fetch: too_large`.
9. `09-sboms` (per package): `sbom` records for the wheel (see
   [SBOMs in wheels](#sboms-in-wheels)), read from the wheel at phase
   02's path once its sha256 matches phase 01's. Files over the
   zip-member size limit aren't read. A missing or changed wheel makes
   the package's line `error`, so rerunning phase 09 needs the wheel
   cache. A wheel with no SBOM gets an `ok` line with no records.
   Once phase 09 is finished, every run rewrites `sbom-report.md` in the
   episode (see
   [Comparing SBOMs with fingerprints](#comparing-sboms-with-fingerprints)),
   and `atlas.md` (see
   [The bundled-library atlas](#the-bundled-library-atlas)).
10. `10-static` (per package): unconfirmed candidates for statically
    linked libraries in the wheel's binaries outside `.libs/`, and
    `fingerprint` records with linkage `static_lib` from those whose map
    row's **static_lib_detection** qualifies them (see
    [The static discovery report](#the-static-discovery-report)). Once
    phase 10 is finished, every run rewrites `static-report.md` in the
    episode.
11. `11-cves` (network, per library): candidate CVEs from NVD, by each
    of the library's CPE names (see
    [Candidates from NVD](#candidates-from-nvd)). It reads neither the
    CVE table nor phase 06's clone: candidates are drafts, and the range
    verifier (6.3) checks the table's fixes in the clone.
12. `12-match` (per package): each library version that falls inside a
    CVE's affected range, with its evidence level. A match is a candidate
    for investigation, not a finding. It reads phase 10's `static_lib`
    records as well as phase 08's.

### The library map

`data/libraries.csv` is curated input, edited by hand and committed like
the package list. One row per prefix, library and way of identifying it:

| prefix | library | repo | tags | not_release | line | kind | pattern | identity_file | identity | static_lib_detection | cpe | osv |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `libtiff` | `libtiff` | `https://gitlab.com/libtiff/libtiff` | `v{version}` | | `single_line` | `library_string` | `LIBTIFF, Version {version}` | `libtiff/tiffvers.h.in` | | | `libtiff:libtiff` | … |
| `libfreetype` | `bzip2` | `https://sourceware.org/git/bzip2.git` | `bzip2-{version}` | | `single_line` | `library_string` | `{version}, {any}-{any}-20{any}` | `bzlib_private.h` | | `pattern` | `bzip:bzip2` | … |
| `libopenjp2` | `openjpeg` | `https://github.com/uclouvain/openjpeg` | `v{version}` | | `single_line` | `build_path` | `{any}/openjpeg-{version}/{any}` | | | | `uclouvain:openjpeg` | … |
| `libopenjp2` | `openjpeg` | `https://github.com/uclouvain/openjpeg` | `v{version}` | | `single_line` | `bare_version` | `{version}` | `src/lib/openjp2/opj_config_private.h.cmake.in` | | | `uclouvain:openjpeg` | … |
| `libwebp` | `libwebp` | `https://chromium.googlesource.com/webm/libwebp` | `v{version}` | | `single_line` | `version_function_machine_code` | `WebPGetDecoderVersion -> bits *.8.8` | `src/dec/vp8_dec.c` | | | `webmproject:libwebp` | … |
| `libfreetype` | `freetype` | `https://gitlab.freedesktop.org/freetype/freetype` | `VER-{version}` | | `single_line` | | | | | | `freetype:freetype` | |
| | `zlib` | `https://github.com/madler/zlib` | `v{version}` | `\d+\.\d+\.\d+\.\d+` | `single_line` | | | | | `detector` | `zlib:zlib` | |
| `libgfortran` | `skip` | | | | | | | | | | | |

- **prefix** is how a file is found, **library** is what it turns out to
  be, and **cpe** and **osv** are how advisories name it. The three
  differ: no advisory says `libz`, and zlib-ng's CVEs name zlib-ng, not
  zlib. **prefix** is empty only on a `detector` row (see
  **static_lib_detection**), which names no `.libs/` file.
- A prefix can map to several libraries (`libz` may be zlib or zlib-ng in
  compat mode, and Pillow's `libfreetype` has bzip2 compiled into it). The
  prefix picks which recognizers to try; the strings and version functions
  in the file decide which one it is.
- **repo** is where the library's source is, and **tags** how its release
  tags are named, with `{version}` where the version is (`v{version}`,
  `openssl-{version}`). **repo** is required on every mapped row, and so
  is **tags** from roadmap 4.1 on: phase 06 clones every library and lists
  its release tags, and the range verifier (6.3) reads them. **tags** is
  one or more patterns separated by single spaces, each with exactly one
  `{version}` and no other placeholder. They are tried in order, and a
  tag takes its version from the first that matches, so it is listed
  once: lcms2 tagged 2.7 `lcms2-2.7`, most releases like `lcms2.19`, and
  2.11 only `2.11`, so its **tags** is
  `lcms2-{version} lcms{version} {version}`, and without the first
  pattern `lcms2-2.7` would list as 2.2.7. Some projects spell
  versions in tags with `_` or `-` (PostgreSQL's `REL_18_6`, OpenLDAP's
  `OPENLDAP_REL_ENG_2_6_15`, FreeType's `VER-2-14-3`), so in **tags**,
  `{version}` also takes `_`, and the version listed for a tag has each `_`
  or `-` between two digits replaced by `.`: `REL_{version}` lists
  `REL_18_6` as 18.6.
- **not_release** is empty, or a Python regular expression for the
  versions **tags** lists that aren't releases: a listed version that it
  matches in full isn't a release, even when it is digits separated by
  dots. libjpeg-turbo tags its betas `x.y.90` and up, such as `3.1.90`,
  so its **not_release** is `\d+\.\d+\.9\d`. The loader rejects one that
  doesn't compile. Phase 06 marks each listed tag a release when its
  version is digits separated by dots and doesn't match **not_release**,
  so a pre-release spelled with letters, such as `lcms2.19rc1`, needs no
  rule.
- **line** says how a library's releases form lines, such as OpenSSL's
  3.0 and 3.5, each kept up with its own releases: a positive integer N,
  so a version's line is its first N numbers (OpenSSL's is 2, so 3.5.8 is
  on line 3.5, and PostgreSQL's is 1), or `single_line`, for a library
  that maintains one line. It is required on every mapped row. It is N
  when, by phase 06's release rule, a release on an older line of N
  numbers is dated after the first release of a newer one, in 2021 or
  later; otherwise `single_line`. When each line reached its end of life
  is in [Lines' ends of life](#lines-ends-of-life).
- Rows for one library agree on **repo**, **tags**, **not_release**,
  **line**, **cpe** and **osv**, and on whether they are `detector` rows.
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
  - A `bare_version` row's pattern is `{version}`, and its prefix maps to
    no other library, since a bare version doesn't choose between them.
  - For `version_function_machine_code`, the pattern and
    **identity_file** are as in
    [Version function machine code](#version-function-machine-code), and
    the prefix may map to other libraries.
  - For `build_path`, **identity_file** and **identity** are empty.
- A library can have several rows, one per way of identifying it. Prefer a
  library string; for a library that embeds none, use a build path,
  version function machine code or a bare version.
- A row with a library and repo but no kind marks a library that is
  identified but has no recognizer, such as FreeType, which embeds no
  version string and has no version function that can be read
  (roadmap 4.4). Under one prefix, a library has either recognizer rows or
  one such row. Phase 08 has nothing to run for it, and 4.5 reports it.
- **static_lib_detection** records the maintainer's judgment, from
  reading upstream source, that a match proves a binary contains the
  library: the string is the library's own and can't be a header string
  (roadmap T.2). It is one of:
  - `pattern`: the row's pattern qualifies, and its matches in binaries
    outside `.libs/` become `static_lib` records (phase 10). Only a
    `library_string` or `build_path` row can have it. bzip2's row does.
  - `detector`: the library's hand-written detector qualifies. The row
    gives phase 06 and the staleness report the library's **repo**,
    **tags**, **not_release**, **line** and **cpe**, and phase 06 clones
    it like any other. It has no **prefix** and no **kind**, and its
    library must be one a hand-written detector finds: zlib's row is the
    only one. zlib's four-part versions, such as 1.3.1.2, whose
    `zlib.h` says `1.3.1.2-audit`, are tags between releases, not
    releases, so its **not_release** is `\d+\.\d+\.\d+\.\d+`.
  - empty: the row's matches never become `static_lib` records, though
    they are still candidates in the static discovery report.

  A `skip` row leaves it empty. Matches in `.libs/` files don't depend
  on it: phase 08 runs every recognizer row.
- **cpe** is how NVD names the library: each vendor and product NVD
  uses for the library's upstream project, joined by `:`, such as
  `webmproject:libwebp`, each in lowercase letters, digits, `_`, `.`,
  `-`, `+` and `~`. Several are separated by single spaces, the one NVD
  uses now first: krb5's is `mit:kerberos_5 mit:kerberos`, the second
  being NVD's name for older releases. A distribution's name for its
  package of the library, such as `redhat:libpng`, isn't listed, nor is
  another project with the same product name: `bzip2_project:bzip2` is
  a Rust crate. A library NVD has no CPE name for has `none`, so a
  value that was forgotten can't pass for one that was checked.
  **cpe** is required on every mapped row. **osv** isn't used in
  version 1 (see "Other advisory sources" under [Later](#later-tbd)).
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

### Lines' ends of life

`data/line_eol.csv` is curated input, edited by hand and committed like
the library map: when each line of a library whose **line** isn't
`single_line` reached, or will reach, its end of life, as the project
states it. Its columns are **library**, **line**, **eol**, an ISO date
or `maintained`, and **source**, a link to the page on the project's own
site that states it. It has a row for every line with a release in 2021
or later whose end of life the project states; a line it leaves out is
never taken for a maintained one. Pre-flight loads it against the map.
The loader rejects an empty field, a library the map doesn't track or
whose **line** is `single_line`, a line that isn't as many numbers as
the library's **line** says, an **eol** that is neither a date nor
`maintained`, and a line listed twice. The staleness report reads it on
every run, so editing it needs no phase file deleted, and it isn't an
episode input.

### The staleness report

A scanner sees `pillow 12.3.0`; the staleness report shows how old the
C libraries inside it were. It is a measurement, not a finding: it
names no CVE, so it isn't a CVE match (see
[Data handling and disclosure](#data-handling-and-disclosure)). It
measures each library twice: against all its releases, and against the
releases on its own line (see [The library map](#the-library-map)),
since a wheel on a maintained line, such as OpenSSL 3.5, has its
security fixes without moving to a newer one.

Once phases 01, 06 and 08 are finished, every run rewrites
`staleness-report.md` in the episode from phases 01, 05, 06 and 08, and
10 once it is finished, as it rewrites the fingerprint report, reading
the library map and [Lines' ends of life](#lines-ends-of-life) too.
Until phase 10 is finished, or while its lines predate `static_lib`
records, the report has no static rows and says why in its counts.
Phase files don't change, apart
from the tag dates and release flags phase 06 records. An episode whose
phase 06 lines predate tag dates or release flags compares no library: the report says to rerun from
phase 06, in its counts and as each library's reason.

Staleness is measured against the newest release that existed when the
wheel was uploaded, never today's: a release upstream made afterwards
doesn't count against the wheel, and a rerun next month gives the same
answer.

- The wheel's upload day is phase 01's upload time, in UTC.
- A release is one of phase 06's tags marked `release`: its version is
  digits separated by dots and isn't matched by the library's
  **not_release** (see [The library map](#the-library-map)). Other
  tags, such as `2.19rc1` and libjpeg-turbo's `3.1.90` beta, aren't
  counted, so a pre-release tag never makes a wheel look behind unless
  the map has no rule for it. Versions are ordered as tuples of
  integers.
- The bundled release is the tag phase 06 lists with the fingerprint
  version, as 7.1 tests versions. An ambiguous version (see
  [Ambiguous versions](#ambiguous-versions)) is read as the newest
  release it may be, so the report can understate staleness, never
  overstate it, and the row says so.
- **Newer releases**: releases with a higher version than the bundled
  one, dated on or before the upload day.
- **Days behind**: from the earliest newer release's date to the upload
  day. A wheel with no newer releases is current, at 0 days.
- **Line**: the bundled release's line, by the library's **line**, or
  `all` for a `single_line` library. **Newest on line at upload** and
  **days behind on line** follow the same rules, counting only releases
  on that line; for a `single_line` library they repeat the values above.
- **Line status** on the upload day: `single line`; `maintained`, when
  the line's **eol** is `maintained` or after the upload day; `EOL` and
  the date, when it is on or before it; or `unknown`, for a line the
  list leaves out. A wheel current on a maintained line has the fixes
  its line gets; one behind on it, or on a line at its end of life,
  doesn't.

For each package, each `.libs/` file and each library its prefix maps
to, the report shows the bundled version with its basis and notes as
the fingerprint report shows them, the newest release at upload with
its date, the number of newer releases and the days behind, then the
line, its status, the newest release on it at upload with its date and
the days behind on it. A row whose
basis is `bare_version` is marked as a hint, as everywhere else. Every
row shows its record's linkage. After the `.libs/` rows come the
package's `static_lib` records from phase 10, one row each, in the same
format, named by the member that holds the library, such as
`lxml/etree.cpython-312-x86_64-linux-gnu.so`. A binary with no record
has no row; its candidates are in the static discovery report. A
package whose phase 10 line isn't `ok` says so in place of its static
rows.

Any other row is listed as not compared, never as current, with the
reason: the fingerprint report's reason for having no version, such
as `matches disagree` for a record whose matches give different
versions, as playwright's two copies of zlib in `driver/node` do;
the reason phase 06 failed the library;
or no release tag for the version, such as OpenBLAS's
`0.3.34.106.0` and grpcio's zlib `1.3.1.1`. Its line columns are `—`. A
prefix marked `skip` is listed as skipped. A file whose prefix isn't in
the map is listed as not compared, `not in map`. A package
that wasn't scanned shows the phase where it stopped and that phase's
reason, as in the fingerprint report.

The report starts with counts: libraries compared, current and behind,
by basis, then current and behind on their line, by basis, and by line
status, and libraries not compared, by reason, so a reader sees how
much of the substrate the numbers cover. Packages not scanned are a
count of packages, given once. The other counts are given once per
linkage present, `shared_lib` first and then `static_lib`, with no
combined total, so the `.libs/` numbers stay comparable with reports
from before static rows. The `static_lib` counts end with the packages
whose phase 10 line isn't `ok`.

Rules:

- **Pre-flight finishes before anything is written.** Any failure is
  printed to stderr and exits 2:
  1. The episode and cache directories are outside any git working tree.
  2. The package list loads (roadmap 3.2), and so do the library map
     (roadmap 3.7), the list of ambiguous versions (roadmap 4.7), the
     CVE table (roadmap 6.1) and the list of lines' ends of life
     (roadmap S.4).
  3. The episode's phase files are a run of finished phases with no gaps
     (01, 02, …), no `.partial` file, and no two files, finished or
     `.partial`, with one number, such as `10-cves.jsonl` beside
     `10-static.jsonl`. Otherwise the error names every file to delete.
  4. If the episode has an `episode.json`, it matches this run's inputs: the
     list file's sha256, the count after clamping, the target and both size
     limits. A smoke run at `--count 2` and another at `--count 10`
     therefore need separate episode directories. The code version is
     recorded but not matched, so a phase can be rerun after a fix. If the
     episode has phase files (finished or `.partial`) but no
     `episode.json`, their inputs can't be checked, and the error names
     them to delete.
  5. The library map is expected to change between parts 1 and 2, so it
     isn't matched from the start. Phase 06 records its sha256 in
     `episode.json`, written whole or not at all like a phase file; if the
     map has changed since, the error names phase 06's file and every later
     one to delete. The field made `episode.json`'s `schema_version` 2; an
     episode from version 1 still passes pre-flight, and phase 06 brings it
     to 2.
- **One line per package, or per library, per phase**, in list or map order:
  `schema_version`, `name` or `library`, `status` (`ok`, `skipped` or
  `error`), `reason`, and the phase's data. Per-binary results are nested
  inside the package's line, in the `inspect`, `strings` and `fingerprint`
  record formats, and per-file results in the `sbom` format. A package
  whose line in the previous per-package phase isn't `ok` gets a
  `skipped` line, never a missing one, whose reason is the phase where
  its line first wasn't `ok` (such as `02-fetch`). Per-library phases
  never skip a library over an earlier line; one that needs an earlier phase's
  result reads that line itself. Every finished phase file has exactly one
  line per package or library. A bad zip or malformed ELF becomes an `error`
  line, not a crash.
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
  01, 02, 06 and 11 use the network, through an HTTP client (or, for 06,
  the git command) that tests replace with recorded responses or a
  synthetic repository.
- When every phase finishes, `scan` exits 0, even if some lines are
  `error`: errors are data. It exits 3 when it stops for the manual step.
  Counts by status go to stderr, and nothing goes to stdout.

### The static discovery report

Phase 08 reads only `.libs/` files. Phase 10 and the static discovery
report show what a wheel's other binaries hold, mostly its extension
modules, so the maintainer can choose which statically linked libraries
to detect (roadmap T.2). This is a measurement, not detection: a
candidate is not a fingerprint record and not a finding. Phase 10 also
writes `static_lib` fingerprint records from the candidates' sources
that the library map qualifies (roadmap T.3); those are detection, as
phase 08's records are.

`10-static` (per package) covers every ELF binary in phase 04 except the
`.libs/` files phase 05 lists. For each binary it lists candidates from
two sources:

- strings that the library map's `library_string` and `build_path`
  recognizers match, compiled from phase 07's lines as phase 08 compiles
  them, among the binary's strings in phase 04's records that pass the
  noise filter;
- the hand-written zlib detector (roadmap 2.1), since zlib has no
  recognizer row, run over the binary's bytes, read from the wheel at
  phase 02's path. Each string of a `contains` result's basis is a candidate, with
  that basis as its kind and its own string's version, so two zlib
  copies in one binary keep both versions. A string the derivative rule
  reattributes, such as zlib's banners beside zlib-ng's own string,
  stays the derivative's with no version. Its `compiled_against`
  results are not candidates.

Each candidate records the library, the version, the kind, the matched
string, its file offset and ELF section, and the map row's pattern, or
none for the zlib detector. Each file phase 10 reads must match phase
04's sha256. A missing wheel or member, a changed file or an ELF
pyelftools can't parse makes the package's line `error`, so rerunning
phase 10 needs the wheel cache. `bare_version` and
`version_function_machine_code` rows don't run here: both rest on a
`.libs/` file, a bare version on its prefix and a version function on
the file's exported symbols.

Beside its candidates, each binary in phase 10's line has a
`fingerprints` list: `fingerprint` records with linkage `static_lib`,
built from the matches of the map rows whose **static_lib_detection** is
`pattern`, and of the zlib detector when the map has a `detector` row
for one of its libraries (see [The library map](#the-library-map)).
They go through the same record builder as phase 08's, so the
derivative rule and the conflict rule apply unchanged: two copies of
zlib in one binary, such as playwright's `driver/node`, give one record
with version `null` and `conflict` `true`, while the candidates keep
both versions. Only `contains` records are written; a header string
alone shows nothing about what a binary holds. The record fields are
those of [How versions are identified](#how-versions-are-identified),
and the line's `schema_version` is 2.

Once phase 10 is finished, every run rewrites `static-report.md` in the
episode from phases 04, 05 and 10, as it rewrites the fingerprint
report, reading the library map and the list of ambiguous versions too.
It reads no wheel, so editing the map or the list needs no phase file
deleted.

The report starts with counts: packages scanned in phase 10, and those
not scanned, by the phase where they stopped; binaries outside
`.libs/`; candidates by library and by kind; candidates marked header
string risk; candidates that became `static_lib` records, those whose
string is in a record's evidence; and distinct templates.

**Binaries by file name.** For each package, the binaries outside
`.libs/`, counted by their file names alone: extension modules, whose
names end in `.cpython-<tag>.so` or `.abi3.so`; shared libraries, other
names starting with `lib` and ending in `.so` or `.so.` and numbers,
such as torch's `torch/lib/libtorch_cpu.so`; and other binaries, such as
executables and other `.so` names. Names alone can miscount: an
extension module with a bare `.so` name counts as another binary.

**Candidates.** For each package, each candidate with its member,
library, version, kind and matched string, labeled "unconfirmed static
candidate", with an ambiguous version marked as the fingerprint report
marks it, and "conflict" when a binary's candidates for one library
give different versions.

- A candidate whose map row's **identity_file** is a header (`.h` or
  `.h.in`), such as OpenSSL's `include/openssl/opensslv.h.in` and
  libtiff's `libtiff/tiffvers.h.in`, is also marked "header string
  risk". A string defined in a public header can be a header string in
  any binary that calls the library, and a header string shows what a
  binary was compiled against, not that it contains the library. The
  mark comes from the map when the report is written.
- A candidate names the library whose row matched. The derivative rule
  (see [How versions are identified](#how-versions-are-identified))
  applies to the `static_lib` records, not here.

A package that wasn't scanned in phase 10 shows the phase where it
stopped and that phase's reason, as in the fingerprint report.

**Templates.** From phase 04: the templates of every string in those
binaries that passes the noise filter, with templates longer than 200
characters cut to 200, as in the library report. They are ranked by how
many wheels carry them, then by how many binaries, then alphabetically,
each with one real example string, its wheel and member, and the
packages carrying it. Every template is listed; review reads from the
top.

## The CVE table

`data/cves.toml` is curated input, edited by hand and committed like the
library map. It lists high and critical CVEs in the libraries the map
tracks, and it is about libraries and their releases, never wheels or
packages: matches against wheels are written only into the episode
(roadmap 7.1; see
[Data handling and disclosure](#data-handling-and-disclosure)).

Version 1 finds CVEs through NVD alone (see "Other advisory sources"
under [Later](#later-tbd)). A CVE is in scope when NVD published it on
or after 2020-01-01 and any CVSS v3.0, v3.1 or v4.0 score on its NVD
record, NVD's own or another source's, is `HIGH` or `CRITICAL`. Every
score is recorded, and one is enough: listing too much costs a check by
hand, and listing too little hides a candidate. Severities that aren't
CVSS scores, such as Chromium's, aren't used.

The table is TOML, read with Python's `tomllib`: a CVE can have several
fixes, each with its own commits, which a CSV row can't hold, and with
one value per line a diff shows what changed. Each CVE and library is
one `[[cve]]` table. The seed, abridged:

```toml
[[cve]]
id = "CVE-2023-4863"
library = "libwebp"
published = 2023-09-12
component = "library"
introduced = "unknown"
duplicates = ["CVE-2023-5129"]
sources = [
  "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
  "https://chromium.googlesource.com/webm/libwebp/+/refs/tags/v1.3.2/NEWS",
]

[[cve.severity]]
source = "nvd@nist.gov"
cvss = "3.1"
score = 8.8
label = "HIGH"

[[cve.fix]]
commits = ["2af26267cdfcb63a88e5c74a85927a12d6ca1d76"]
tag = "v1.3.2"
date = 2023-09-13

[[cve.fix]]
commits = ["902bc9190331343b2017211debcec8d2ab87e17a"]
tag = "v1.4.0"
date = 2024-04-12
```

- **id**: `CVE-`, the year, `-` and four or more digits. A CVE is listed
  once for each library it affects, so **id** and **library** together
  are unique.
- **library**: a library the map tracks, not `skip`, whose **cpe**
  isn't `none`.
- **published**: the day NVD published the CVE, in UTC, from 2020-01-01
  on.
- **component**: `library` when the bug is in the library's own code, or
  `tool` when it is in a program the project ships beside it, with
  **tool** naming the program. A `.libs/` file holds the library, not
  its tools, so 7.1 lists a `tool` CVE without matching it.
- **introduced**: the commit that introduced the bug, or `unknown`,
  which counts every release without a fix as affected.
- **duplicates**: optional. Rejected CVE IDs that NVD calls duplicates of
  this one, such as CVE-2023-5129, so an advisory that names one is tied
  to this row rather than becoming a second row.
- **disputed**: only for a disputed CVE, a table with **reason**, who
  disputes it and why, and **source**, a link to the dispute. A disputed
  CVE stays in the table, marked.
- **sources**: links to what the row rests on, among them the CVE's NVD
  page.
- **severity**: each CVSS score on the NVD record: its **source** as NVD
  names it (`nvd@nist.gov` for NVD's own), the CVSS version, the base
  score and its label.
- **fix**: one for each line of releases the fix reached, such as a
  maintained branch: the **commits** a release must contain to be fixed
  (a backport has its own hashes), the first release **tag** that
  contains them all, and that tag's **date**. A row with no fix has no
  fixed release yet.

The upstream git history is the ground truth: a release is fixed when its
tag contains every commit of one of the row's fixes. CVE-2023-4863 shows
why each line of releases is listed. NVD links libwebp's fix on its main
branch, 902bc91, which no release before 1.4.0 contains; 1.3.2 was fixed
by a backport, 2af2626. A row with only NVD's commit would call 1.3.2
affected. A backport no release tag contains, such as those on libwebp's
older branches, isn't listed.

A fix's tag and date say which release first carried it, a claim the
range verifier (6.3) checks with `git tag --contains` in phase 06's
clone. A tag's date is the day `git for-each-ref` gives as
`%(creatordate:short)`: its tagger date, or its commit's date for a
lightweight tag, in that date's own time zone.

7.1 doesn't order versions. It tests a version by the release tag phase
06 lists for it: the release is affected when its tag contains none of
the row's fixes, unless the row names an introducing commit the tag
doesn't contain. A version phase 06 lists no tag for, such as OpenBLAS's
`0.3.31.dev`, and every version of a library phase 06 couldn't clone
are listed as not compared, never as fixed. An ambiguous version is
tested as every release it may be.

Pre-flight loads the table against the library map. The loader rejects,
naming the CVE, its library and the field:

- a file that isn't TOML, a key it doesn't know at any level, a value of
  the wrong type, or an empty string;
- an **id** or duplicate of the wrong shape, an **id** and **library**
  listed twice, or a duplicate that is also a row's **id**, appears twice
  in one row or is listed for two different CVEs (a CVE in two libraries
  lists its duplicates in both rows);
- a library the map doesn't track, or one whose **cpe** is `none`;
- a **published** day before 2020-01-01;
- a **component** other than `library` or `tool`, a `tool` without
  **tool**, or **tool** on a `library` row;
- an **introduced** that is neither `unknown` nor a commit;
- a **disputed** table without both **reason** and **source**, or whose
  **source** doesn't start with `https://`;
- no **sources**, no NVD page for the CVE among them, a link that
  doesn't start with `https://`, or one listed twice;
- no score labeled `HIGH` or `CRITICAL`; a CVSS version other than
  `3.0`, `3.1` or `4.0`; a label that doesn't fit its score (`NONE` for
  0.0, `LOW` from 0.1 to 3.9, `MEDIUM` from 4.0 to 6.9, `HIGH` from 7.0
  to 8.9, `CRITICAL` from 9.0 to 10.0);
- a fix with no commits, a commit that isn't 40 lowercase hex digits or
  appears twice in the row, counting the introducing commit, or a **tag**
  the library's **tags** doesn't match.

A commit is 40 lowercase hex digits. Whether a fix's tag exists and
contains its commits isn't checked at load time, since tags come from
phase 06's clone: the range verifier (6.3) checks them.

### Candidates from NVD

Phase 11 drafts candidates for the table: for each library, every CVE
that NVD's API returns for one of its CPE names and that NVD published
on or after 2020-01-01. Candidates stay in the episode. The table is
edited by hand (roadmap 6.4), and nothing is copied into it.

A query by CPE finds only CVEs whose NVD record has a product list
naming the library, so no candidates means none were found that way,
never that the library has no CVEs. NVD has no CPE name for libsodium,
and its CVE-2025-69277, which NVD has deferred, has no product list.
Nor has libpq's CVE-2025-1094, which its CNA scored `HIGH` (see "Other
advisory sources" under [Later](#later-tbd)).

For each name in the library's **cpe**, phase 11 asks NVD's CVE API
for `virtualMatchString=cpe:2.3:a:<vendor>:<product>` with
`resultsPerPage=2000`, the most the API allows, and pages with
`startIndex` until it has `totalResults` CVEs. It sends no dates, since
a query's published range can span at most 120 days, and keeps the
CVEs NVD published on or after 2020-01-01, in UTC. It waits 6 seconds
between requests, the pace NVD's documentation sets for clients
without an API key, and sends no key. A library whose **cpe** is
`none` gets a `skipped` line with reason `no_cpe`. A failed request, a
page whose `totalResults` differs from the first page's, fewer distinct
CVEs than `totalResults`, a response that isn't JSON or a field of the
wrong type makes the library's line `error` with no candidates, so a
partial answer never passes for a whole one.

Nothing is dropped for its scores. Each candidate's **scope** comes
from the CVSS v3.0, v3.1 and v4.0 scores NVD lists: `in` when any is
labeled `HIGH` or `CRITICAL`, the table's rule, or is 7.0 or more, so a
label that doesn't fit its score can't hide a candidate; `out` when it
has such scores and none is; and `unscored` when it has none.
NVD no longer scores every CVE, so an unscored candidate is checked by
hand like one in scope; one that is `out` is listed but needn't be.

The library's line has `cpe`, the names queried; `nvd_timestamp`, the
first response's `timestamp`; `total`, each name's `totalResults`
before the date filter; and `candidates`, ordered by `published` and
then `id`, each with:

- `id`, `status` (NVD's `vulnStatus`), `published` and
  `last_modified`, verbatim;
- `cpe`: the library's names whose queries returned it;
- `scope`, as above, and `scores`: each CVSS v3.0, v3.1 and v4.0
  metric as its `source`, `type`, CVSS `version`, `score` and `label`,
  verbatim;
- `kev`: NVD's `cisaExploitAdd`, the day CISA added the CVE to its
  Known Exploited Vulnerabilities catalog, or `null`;
- `description`: NVD's English description;
- `ranges`: every `cpeMatch` entry, from any configuration, whose
  criteria name one of the library's CPE names, with all its fields
  verbatim;
- `affected`: the record's `affected` list as NVD gives it, or `null`;
- `patches`: the URLs of references tagged `Patch`, each once, in
  NVD's order.

Ranges, patch links and `affected` lists are claims, recorded verbatim
and never used unverified: CVE-2023-4863's Patch link is a commit no
release before 1.4.0 contains (see [The CVE table](#the-cve-table)). A
candidate with no range, because no criteria name the library, is kept
and checked by hand. A rejected CVE has no product list, so a query by
CPE never returns it; CVE-2023-5129 is reached only as a
**duplicates** entry.

Phase 11 reads neither the CVE table nor phase 06's clone, so editing
the table needs no phase file deleted. Its candidates are a snapshot of
NVD: to take a new one, delete `11-cves.jsonl` and every later phase
file. A changed **cpe** changes the map, so pre-flight check 5 already
names phase 11's file. Which candidates the table lists is for a
report that reads the table on every run (roadmap 6.3).

## Findings so far

pypiscan's results up to the checkpoint (see [Mini-roadmap:
checkpoint](#mini-roadmap-checkpoint)). Nothing here names a CVE.

### What popular wheels bundle

The top-500 probe took the first 500 projects on the package list (pypi top
downloads, prev 30 days) with a manylinux target wheel, which walked the
list to rank 3252: 2682 of the projects passed over had no target wheel
(none for CPython 3.12 on manylinux x86_64 with glibc 2.28 or older). It
ran part 1 only (`--stop-after 05`), with the 100-row cap lifted by a local
override, not by T.4.
Of the 2682 passed over (C.7), 2573 have only pure-Python wheels and 74
only an sdist. Only 15 are compiled for CPython 3.12 on Linux x86_64 but
miss the target for needing glibc newer than 2.28, among them the pyside6
packages, debugpy and semgrep. Another 10 have no manylinux x86_64 wheel:
some are Windows-only (pywin32, pywinpty), and others, such as psycopg2,
mysqlclient and pycairo, are compiled from their sdists on Linux. The last
10 have no cp312 or `abi3` wheel, mostly because they target other Python
versions (audioop-lts, pyyaml-ft, backports-zoneinfo, typed-ast).

- Phase 01 resolved all 500. Phase 02 fetched 475 and skipped 25 as
  `too_large` (over 100 MB; see C.5). The skipped wheels weren't opened, so
  the counts below cover 475 wheels and are a floor.
- 48 of the 475 have a `.libs/` directory, mostly scientific, media,
  geospatial and database-driver packages.
- Their manylinux tags, the oldest glibc each wheel claims, not the image
  that built it: `manylinux2014` 7 (google-crc32c, ijson, cassandra-driver,
  psycopg2-binary, psycopg-binary, simsimd, tables), `2_17` 3 (the same
  policy as `manylinux2014`), `2_24` 2, `2_26` 3, `2_27` 15, `2_28` 18.
- 22 of the 48 ship an SBOM, of the three kinds in [SBOMs in
  wheels](#sboms-in-wheels). Where auditwheel's names the build image's
  packages, the image shows. In those SBOMs, CentOS 7 packages appear only
  in psycopg2-binary and psycopg-binary: krb5, cyrus-sasl, pcre, keyutils,
  libcom_err and libselinux. psycopg documents this as a deliberate choice
  for its binary packages. AlmaLinux 8 packages appear in many more: the
  opencv packages, pymssql, memray, rdkit, cadquery-ocp, scipy,
  scikit-learn, faiss-cpu and others.
- A bundled package stays as the build image had it on the day of the
  build: opencv's wheels carry `openssl-libs` `1.1.1k-15.el8_6`, and
  pymssql's and memray's carry `1.1.1k-17.el8_6`. Whether the later builds
  include security fixes hasn't been checked.
- The same libraries recur. OpenSSL is the most duplicated: 12 wheels carry
  their own libcrypto, among them psycopg2-binary, psycopg-binary, pymssql,
  pycurl, pygit2, memray, rasterio, netcdf4, connectorx and the opencv
  packages. libgomp is in 9 (scikit-learn, faiss-cpu, xgboost, ctranslate2
  and others), libpng in 9, and libgfortran in 7 (numpy, scipy, scs,
  faiss-cpu and the opencv packages). OpenBLAS is in 7 wheels from 5
  projects, under five file names, and no two projects share a build:
  numpy's `libscipy_openblas64_` (OpenBLAS's name for its 64-bit-integer
  build), scipy's `libscipy_openblas`, faiss-cpu's `libopenblaso-r0` (its
  name for the OpenMP build), scs's `libopenblas-r0`, and `libopenblasp-r0`
  (the pthreads build) in the three opencv packages. ffmpeg's libraries are
  in av and the opencv packages, HDF5 in h5py, netcdf4, rasterio and
  tables, and Kerberos in the database drivers, connectorx and pycurl.
  opencv-python, opencv-python-headless and opencv-contrib-python are
  alternatives, so a count of wheels can count opencv three times:
  libcrypto's 12 wheels are 10 projects.
- The probe found 299 prefixes the library map doesn't list. Of these, only
  libbz2 and libcurl are in five or more wheels.
- The top-100 staleness run (`stale100`, see [The staleness
  report](#the-staleness-report)) compared 27 bundled libraries with their
  upstream releases on each wheel's upload day. On their own release lines,
  22 were current and 5 behind: one by a day, and four that are a CentOS 7
  build image's distribution packages. No `.libs/` prefix appears in more
  than 2 of the 100 wheels.

### Learnings from this measurement

- A version number alone is weak evidence. A distribution's package keeps
  its upstream version while it backports fixes, a maintained release line
  gets fixes that a number behind the newest release hides, and a vendored
  fork has its own numbering. Each breaks "version X, so vulnerable".
- Scanning only `.libs/` misses static linking: pyarrow's bzip2 1.0.8 is
  compiled into `libarrow`, pymupdf's zlib 1.3.2 into `libmupdf`, and
  lxml's and grpcio's zlib into their extension modules (see [Mini-roadmap:
  statically linked libraries](#mini-roadmap-statically-linked-libraries)).
  What `.libs/` shows is less than what wheels carry.
- An SBOM is a claim. numba 0.68.0's names a libgomp its wheel deletes
  after repair, Pillow 12.3.0's marks libraries its wheel carries
  `optional`, and a project's SBOM can leave libraries out (Pillow's omits
  libpng, xz and brotli).
- When working with Claude/Claude Code on a personal "Pro" plan, by far the
  limiting factor is the "weekly" usage limit. So far, human intelligence
  seems to be required and valuable to steer the code/platform/ecosystem
  investigations into useful directions. It helps to have a plan in the
  README, be specific with Claude Code about what to implement, and keep
  implementation sprints very specific and focused.

### Status

CVE matching, 6.3 onward, is paused. Four tries came back thin: the top-100
staleness run found 22 of 27 compared libraries current on their release
lines, the static work found a handful of libraries, and in the top 500
only 48 of 475 wheels bundle shared libraries at all. Those 48 share a
familiar set (OpenSSL, compression and image codecs, compiler runtimes,
ffmpeg, HDF5, Kerberos), and of the 299 prefixes the map doesn't list, only
libbz2 and libcurl are in five or more wheels. At the level of popular
packages, there is too little for matching to find.

## Roadmap

Each item is one pull request (see
[Branches and pull requests](#branches-and-pull-requests)), sized to be
implemented in about 20–30 agent turns and reviewed on a phone. Items marked
*(maintainer input)* need a decision before any code is written. Done items
are marked ✓.

### Mini-roadmap: checkpoint

The CVE and staleness work has come back thin four times (see [Findings so
far](#findings-so-far)). Popular maintainers mostly keep their libraries
current, and a bare version is weak evidence. This mini-roadmap ends the
current direction on a checkpoint: what was found, a pause on CVE matching,
and a few small deliverables other people can use.

- **C.1** ✓ The [Findings so far](#findings-so-far) section, docs only.
- **C.2** ✓ (required for the bundled-library atlas, C.3, and for C.5)
  `scan --skip-map-todo`: the manual step still writes `library-map-todo.csv` and
  lists the prefixes, but the run goes on to phase 06, so `--stop-after 09`
  reaches phase 09 with unmapped prefixes. A `.libs/` file whose prefix
  isn't in the map shows as `not in map` in the fingerprint, SBOM and
  staleness reports, never as missing, and the reports count such files.
  The package list loader's cap goes from 100 rows to 500 (the first half
  of T.4), so the top-500 probe reruns from main. Manual check: rerun
  `top500-p1` with `--skip-map-todo --stop-after 09`; `sbom-report.md`
  lists the 22 SBOM wheels, and in both psycopg wheels krb5 and cyrus-sasl
  still agree. Rerun `stale100` with `--stop-after 09`; its reports don't
  change except for that rename.
- **C.3** ✓ The bundled-library atlas, `atlas.md` (see
  [The bundled-library atlas](#the-bundled-library-atlas)). Manual check:
  rerun `top500-p1` with `--skip-map-todo --stop-after 09`; `atlas.md` has
  48 rows, 22 with an SBOM, and psycopg2-binary's krb5 shows CentOS 7, and
  the other reports don't change. Rerun `stale100` with `--stop-after 09`;
  only `atlas.md` is new.
- **C.4** Now C.9, so the release carries the probe as C.5 to C.8 leave it.
- **C.5** ✓ The large wheels, measured first as T.1 was. A small episode of
  the eight wheels the top-500 probe skipped as `too_large` that aren't
  NVIDIA's own CUDA libraries or model data: torch, tensorflow, vllm,
  onnxruntime-gpu, triton, claude-agent-sdk, chdb-core and vtk, with the
  wheel size limit raised and `--stop-after 10` (past the manual step by
  C.2). It shows how many shared libraries they keep outside `.libs/`, in
  their own package directories, and what static discovery finds in their
  binaries, before any phase is changed to read them. The 16 `nvidia-*`
  wheels, each one proprietary library with no upstream to compare, and
  lingua-language-detector, large for its model data, stay out. `scan`
  gets `--wheel-size-limit` and `--member-size-limit`, the eight are
  `data/large.csv`, at the versions in `top500-p1`'s phase 01, and the
  static discovery report counts each wheel's binaries outside `.libs/`
  by file name. Manual check, with limits that
  cover the largest of the eight (tensorflow, 546 MB):

  ```bash
  uv run python -m pypiscan scan data/large.csv --count 8 \
    --stop-after 10 --wheel-size-limit 1000 --member-size-limit 2048 \
    --library-map data/libraries.csv \
    --ambiguous-versions data/ambiguous_versions.csv \
    --cve-table data/cves.toml --line-eol data/line_eol.csv \
    --episode-dir ~/pypiscan/episodes/large-c5 \
    --cache-dir ~/pypiscan/cache --skip-map-todo
  ```

  Then read the episode's library and static discovery reports for these
  eight only. Results (`large-c5`; no wheel or member was skipped for
  size, and every phase line is `ok` apart from phase 07's three
  libraries without a recognizer):

  | wheel | outside `.libs/` | shared libraries by name | static candidates |
  |---|---|---|---|
  | torch 2.14.1 | 16 | 12 | none |
  | triton 3.8.0 | 25 | 19 | none |
  | claude-agent-sdk 0.2.174 | 1 | 0 | bzip2 1.0.8, libjpeg-turbo 3.2.0 |
  | tensorflow 2.21.0 | 77 | 6 | libjpeg-turbo 2.1.4, zlib 1.3.1 |
  | vtk 9.7.1 | 376 | 222 | libpng 1.6.58, libtiff 4.6.0, zlib 1.3.1 |
  | vllm 0.32.0 | 14 | 0 | openssl 3.5.5 |
  | onnxruntime-gpu 1.31.0 | 5 | 4 | none |
  | chdb-core 26.9.0 | 8 | 7 | krb5 1.22.2, openssl 3.5.8, zstd |

  The eight hold 522 binaries outside `.libs/`, 270 of them shared
  libraries by name, and 19 candidates, 9 of which became `static_lib`
  records. The openssl, libtiff and bzip2 candidates are marked header
  string risk, and chdb-core's three zstd versions (0.11.2+zstd.1.5.2,
  0.13.0 and 0.13.3) look like Rust `zstd` crate versions, not zstd's.
  Phase 10 already reads every one of these binaries, so in-package
  libraries are not invisible: what a phase reading them as `.libs/`
  files would add is the prefix-bound kinds, bare versions and version
  functions, and their names carry no auditwheel hash, so most of the
  270, such as vtk's, would be new prefixes for the map.
- **C.6** ✓ A hash joined with `.`: the prefix cutter also cuts at `.` and 8
  hex digits, so `libz.915b4635` becomes `libz`. Tests use file names, as
  3.7's do. Manual check: rerun `top500-p1` from phase 05. Results: the
  572 `.libs/` files are the same before and after, and exactly 7
  prefixes changed, all in `torchvision.libs`, the one wheel in
  `top500-p1` whose names carry a `.`-joined hash: `libcudart.faf08d9a`,
  `libjpeg.67fb65bd`, `libnvjpeg.36e11081`, `libpng16.1d0d8f4e`,
  `libsharpyuv.64944e6b`, `libwebp.bab959f1` and `libz.915b4635` lose
  their hashes. `library-map-todo.csv` has 5 fewer rows: libjpeg,
  libpng16, libsharpyuv and libwebp now join mapped prefixes and leave
  it, libnvjpeg was already listed, and `libcudart` and `libz` replace
  their hashed forms (zlib's map row has no prefix). No other prefix
  changed.
- **C.7** ✓ Why a project has no target wheel. The 2682 projects the top-500
  walk passed over are passed over by `scripts/top_packages.py`, not by
  phase 01, so the script records each one's reason from its latest final
  release's files: pure Python only, sdist only, Linux wheels needing glibc
  newer than 2.28, no cp312 or `abi3` wheel, or other platforms only. It
  writes them beside the list, with counts, so the compiled projects the
  target rule misses can be counted and named. Manual check: the October
  snapshot's walk to rank 3252 gives reasons summing to 2682. Results
  (snapshot `last_update` 2026-10-01 12:40:51, sha256 `55fee05e…7041`,
  walked on 2026-10-30): the walk stopped at rank 3252 with 2682
  projects without a target, the same as the top-500 walk, and 70 more
  with no final release (67 of them opentelemetry or Azure
  projects). The reasons sum to 2682:

  | reason | projects |
  |---|---|
  | `pure_python` | 2573 |
  | `sdist_only` | 74 |
  | `glibc_newer_than_2_28` | 15 |
  | `other_platforms` | 10 |
  | `no_cp312_or_abi3` | 10 |
  | `other` | 0 |

  - `glibc_newer_than_2_28`: debugpy, caio, semgrep,
    tensorboard-data-server, llguidance, tree-sitter-language-pack,
    ibm-db, onepassword-sdk, pyside6-essentials, shiboken6,
    pyside6-addons, sglang, pyside6, stpyv8 and pyqt6-qt6.
  - `other_platforms`: psycopg2, mysqlclient, sounddevice, pywin32,
    pyzbar, scandir, pycairo, fasttext, pywinpty and gssapi.
  - `no_cp312_or_abi3`: multiprocess, frozendict, pyyaml-ft,
    audioop-lts, numpy-financial, backports-zoneinfo, typed-ast,
    cx-oracle, netifaces and zipfile-deflate64.

  The 500 projects selected are the same names as the top-500 walk's
  list; 80 of them have a newer version than that list pins, since PyPI
  releases moved on, so the list file itself differs.
- **C.8** *(optional)* `pypiscan wheel <file>`: what one wheel bundles, for
  a maintainer to run before a release: its `.libs/` libraries, manylinux
  tag, SBOMs, auditwheel components tied to no file and files with no
  component, and static candidates. Manual check: Pillow 12.3.0 and
  psycopg2-binary 2.9.13 match their episode rows. ← current
- **C.9** A tagged release of the top-500 probe, as a manual case of 8.1:
  the atlas, `library-report.md`, `sbom-report.md`, a short summary and
  `SHA256SUMS`. No code.

### Mini-roadmap: statically linked libraries

The staleness mini-roadmap's full top-100 run compared 27 libraries. On
their own release lines, 22 were current and 5 behind: one by a day, and
four that are a CentOS 7 build image's distribution packages. No
`.libs/` prefix appears in more than 2 of the 100 wheels, so bundled
shared libraries live in about a dozen packages. The larger layer is
code compiled into extension modules, which version 1 doesn't see: zlib
in lxml and grpcio, OpenSSL in cryptography, and the C libraries behind
Rust `-sys` crates. This mini-roadmap comes before a scientific-stack
package list and a top-500 scan. It starts with a measurement, T.1,
which shows how much static code there is before any recognizer is
written for it.

- **T.1** ✓ Phase 10 and the static discovery report, as described in
  [The static discovery report](#the-static-discovery-report). The CVE
  phase becomes 11 and matching 12, so an episode stopped after phase 09
  needs no phase file deleted, and `--stop-after` takes 01 to 11. Tests
  use hand-built phase lines and synthetic wheels. Manual check: rerun
  the full top-100 episode (`stale100`) with `--stop-after 10`; only
  phase 10 runs. The candidates include lxml 6.1.3's zlib 1.3.2 in
  `lxml/etree` and `lxml/objectify`, and grpcio 1.84.0's zlib 1.3.1.1 in
  `grpc/_cython/cygrpc`, 2.1's known answers. Review reads the counts,
  the candidates and about the top 100 templates.
- **T.2** ✓ Which libraries to detect in binaries outside `.libs/`, and
  with which patterns, chosen from T.1's `stale100` report and the
  wheels' SBOM claims (see [SBOMs in wheels](#sboms-in-wheels)), which
  say where to look and never set a version. Only a pattern whose string
  can't be a header string qualifies: a string from a library's public
  header shows what a binary was compiled against, not that it contains
  the library. Two qualify:
  - zlib, by the hand-written detector (roadmap 2.1). Its `deflate` and
    `inflate` banners are literals in `deflate.c` and `inftrees.c`, not
    header strings. It was seen in lxml 6.1.3 (`lxml/etree` and
    `lxml/objectify`: 1.3.2), grpcio 1.84.0 (`cygrpc`: 1.3.1.1) and
    playwright's `driver/node` (1.3.2.1 and 1.3.0.1). It gets no map row
    yet (see "Checking patterns at every release tag" under
    [Later](#later-tbd)).
  - bzip2, by its existing `library_string` row. `bzlib_private.h` is a
    private header, so the string can't be a header string, and the
    report's "header string risk" mark on it is the Later item "Header
    string risk from identity_file alone". It was seen in pyarrow's
    `libarrow.so.2600` (1.0.8), the only match across all binaries
    outside `.libs/`.

  Nothing else qualifies, each for a reason with its own Later entry:
  - OpenSSL: its only versioned string is `OPENSSL_VERSION_TEXT` from
    `include/openssl/opensslv.h.in`, a public header.
  - zstd: `zstd-sys`'s `+zstd.` build metadata appears in no binary.
  - aws-lc, BoringSSL and ring: aws-lc would give the crate's version,
    not aws-lc's; BoringSSL embeds no version string; ring is a Rust
    crate whose status as a C library is open; the OpenSSL-style object
    names show presence only.
  - geos: `capi/geos_c.h.in` is a public header.
- **T.3** ✓ Static records. Every fingerprint record gets a **linkage**,
  where the library was found: `shared_lib` in a `.libs/` file through
  its prefix (all of phase 08's), or `static_lib` in a binary outside
  `.libs/` (see [How versions are identified](#how-versions-are-identified)).
  It is a closed set, and every reader fails on a value it doesn't know.
  Phase 10 writes the `static_lib` records, in a `fingerprints` list
  beside each binary's candidates, through the same record builder, so
  the derivative and conflict rules apply unchanged; no phase is
  renumbered. Fingerprint records' `schema_version` goes to 4 and phase
  10's lines' to 2. The library map gets a **static_lib_detection**
  column, after **identity**: `pattern` on bzip2's row, and `detector`
  on a new zlib row with no prefix, which gives phase 06 and the
  staleness report zlib's repository, tags, release rule, line and CPE
  name. The staleness report reads phase 10 too, lists static rows after
  each package's `.libs/` rows, shows each row's linkage, and counts
  each linkage apart. The static discovery report counts the candidates
  that became records. Tests use hand-built phase lines and synthetic
  wheels. Manual check: rerun `stale100` from phase 06 with
  `--stop-after 10`; lxml 6.1.3's zlib 1.3.2 in `lxml/etree` and
  `lxml/objectify` is compared, grpcio 1.84.0's zlib 1.3.1.1 is not
  compared for lack of a release tag, playwright's `driver/node` gives
  one zlib record with a conflict, pyarrow's bzip2 1.0.8 in
  `libarrow.so.2600` and pymupdf's zlib 1.3.2 in `libmupdf.so.28.2` are
  compared, and the `shared_lib` counts match the earlier report's.
- **T.4** The top 500: the package list loader's 100-row cap (roadmap 3.2)
  is lifted, `scripts/top_packages.py` stops at 500, and a full run scans
  them. *(Paused at the [checkpoint](#mini-roadmap-checkpoint): the top-500
  probe ran part 1 with a local override of the cap. C.2 lifted the cap
  to 500.)*

### Mini-roadmap: staleness of bundled libraries

The CVE work in sections 6 and 7 is paused at 6.3, and the numbered
roadmap below stays as it is. What is binding for now is the cost of
each item in Claude usage, not its size in lines, and the 100-wheel
episodes are costly to run and review. This mini-roadmap goes first. It
asks a smaller question that the latest wheels can answer with the
phases already built: how stale were the libraries bundled in them? No
older releases or Python versions are needed. Time-to-patch and the
CVE lens stay under [Later](#later-tbd).

Its manual checks start from Pillow, the package that bundles the most
libraries the map can version, against its `.github/dependencies.json`,
and review only Pillow's rows and the report's counts, not all 100
packages, to keep reviews short.

- **S.1** ✓ The staleness report, as described in
  [The staleness report](#the-staleness-report): tag dates in phase
  06's lines, which bumps their `schema_version`, and
  `staleness-report.md`. Libraries outside GitHub weren't compared
  until S.2. Tests use a small synthetic git repository and hand-built
  phase lines. Manual check: rerun the full episode from phase 06; for
  Pillow 12.3.0, each library's newest release at upload matches what
  its upstream tags show by hand, and the report's counts.
- **S.2** ✓ Upstreams outside GitHub, once a Later item: phase 06
  clones the eight libraries it skipped with reason `not_github`, so
  the staleness report compares them. Each **tags** pattern is checked
  against the real repository (FreeType's `VER-{version}` had never
  been checked), and every library is cloned from its real upstream
  except PostgreSQL: git.postgresql.org broke off its clone
  (`fetch-pack: invalid index-pack output`), so its row uses the
  official mirror, `github.com/postgres/postgres`. It starts with
  libwebp, which brings Pillow's libwebp rows into the report.
- **S.3** ✓ Tags that aren't releases, once a Later item: **tags** takes
  several patterns, tried in order, so lcms2's `lcms2-2.7` lists as 2.7
  and its bare `2.11` is found, and a new map column, **not_release**,
  holds a regex for versions that aren't releases. Phase 06 marks each
  tag `release`, which bumps its lines' `schema_version`, and the
  staleness report counts only those. libjpeg-turbo's `x.y.90` betas
  stop counting, so Pillow 12.3.0's libjpeg-turbo 3.1.4.1 reads 1 day
  behind 3.2.0, not 96 behind the `3.1.90` beta. The range verifier
  (6.3) reads the same flag. Manual check: rerun a one-package Pillow
  episode from phase 06.
- **S.4** ✓ Maintained release lines, once a Later item: a new map
  column, **line**, says how each library's releases form lines, and
  `data/line_eol.csv` when each line reached its end of life, from the
  project's own site. The staleness report adds each library's line,
  its status on the upload day and its lag on that line, with counts.
  Phase files don't change. psycopg2-binary 2.9.13's OpenSSL 3.5.8
  still reads 343 days behind 4.0.2, but now also shows line 3.5,
  maintained, and its lag behind the newest 3.5 release. Manual check:
  a fresh one-package psycopg2-binary episode.
- **S.5** ✓ `scan --stop-after NN`: stop once phase NN finishes, with
  the reports it allows written, so a manual check that needs only phases
  01 to 09 doesn't wait out phase 10's NVD queries.

### 0. Guardrails

- **0.1** ✓ Working rules in `CLAUDE.md`: never weaken a check (coverage
  threshold, lint rules, type strictness, CI steps) to make it pass, and
  explain the problem in the PR instead; keep non-test changes under about
  500 lines; call out any CI or tool-configuration change in the PR
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
  --ambiguous-versions data/ambiguous_versions.csv \
  --cve-table data/cves.toml --line-eol data/line_eol.csv \
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
  list is a CSV file with columns `name` and `version`, at most 500 rows
  (100 until C.2), in processing order. The loader rejects an empty list, more than 500 rows,
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

Adding a library means adding rows to the library map, not code. 4.6 is
the exception: it adds the code that reads version function machine code,
and after it a library whose version function has one of its shapes is
again only rows.

- **4.1** ✓ Phase 06, upstream clones and tags. Clones or fetches every
  library the map names whose repository is on GitHub (others are `skipped`
  with reason `not_github`), and lists the release tags its **tags** matches,
  each with its version; a library whose **tags** matches no tag is an `error`
  line. The loader requires **tags** on every mapped row and **identity**
  empty, and `data/libraries.csv` fills in **tags** for each library from its
  repository's tags and drops the two identities the first map had. Upstream
  repositories are read with the git command, as described in
  [Conventions](#conventions), and `scripts/upstream_fixtures.py` (2.2) moves
  from dulwich to the same git module, so dulwich leaves the dependencies.
  Tests use a small synthetic git repository. This item adds the convention's
  test guard and its ruff exception, the one the maintainer has approved; the
  PR still calls the exception out.
- **4.2** ✓ Phase 07, recognizers built from the library map's patterns:
  one line per library listing them, or `skipped` with reason
  `no_recognizer`.
- **4.3** ✓ Phase 08, fingerprint with the recognizers and the noise
  filter. Adds `basis` to fingerprint records and bumps their
  `schema_version`. The loader rejects a `bare_version` row whose prefix
  maps to another library. Manual check: compare results against Pillow
  12.3.0's `.github/dependencies.json`.
- **4.4** ✓ *(maintainer input)* A detection method for each library the
  map marked as identified with no recognizer, chosen from upstream source,
  the packages' build scripts and their real wheels (Pillow 12.3.0,
  psycopg2-binary 2.9.13, pyzmq 27.2.0 and shapely 2.2.0). In none of
  their files does a string or a build path give the version.
  - Version function machine code (4.6) for libwebp (`libwebp`,
    `libwebpdemux` and `libwebpmux`), brotli's `libbrotlidec`, libavif,
    libpq and libzmq, and for dav1d, which libavif compiles in as its AV1
    decoder.
  - No method for lcms2, whose encoding gives 2.19 and 2.19.1 the same
    value; FreeType, which has no function that returns its version;
    OpenLDAP, whose version string the compiler drops; libsharpyuv, whose
    function returns its own version (0.4.2 in libwebp 1.6.0), not
    libwebp's; and `libbrotlicommon`, `libssl`, `libgeos` and krb5's
    `libgssapi_krb5`, `libk5crypto` and `libkrb5support`, which have no
    version function either. 4.5 reports them.
- **4.5** ✓ A fingerprint report. Once phase 08 is finished, every run
  rewrites `fingerprint-report.md` in the episode from phases 05, 07 and
  08, as it rewrites `library-map-todo.csv`. It lists every `.libs/` file
  each package carries and, for each library its prefix maps to, the
  version and the basis it rests on, or why there is none: the map gives
  the library no recognizer, or its recognizers matched nothing. A prefix
  marked `skip` is listed as skipped. Signals and gaps are visible side by
  side, and no version is shown without its basis.
- **4.6** ✓ Version function machine code, as described in
  [Version function machine code](#version-function-machine-code): the
  `version_function_machine_code` kind and its pattern forms in the loader,
  the decoder for its code shapes, phase 08 reading those functions from
  the cached wheel, `tests/version_function_examples.tsv` from the real
  wheels, and rows for the libraries 4.4 chose, including dav1d's under
  `libavif`. Fingerprint records' `schema_version` goes to 3. Manual check:
  Pillow 12.3.0, psycopg2-binary 2.9.13 and pyzmq 27.2.0 give the versions
  their build scripts pin: libwebp 1.6.0, brotli 1.2.0, libavif 1.4.2,
  dav1d 1.5.3 (pinned by libavif 1.4.2), libpq 17.11 and libzmq 4.3.5.
- **4.7** ✓ Ambiguous versions, as described in
  [Ambiguous versions](#ambiguous-versions):
  `data/ambiguous_versions.csv`, its loader and `--ambiguous-versions`,
  and the fingerprint report's note. Version function rows for lcms2,
  which the list makes usable, and for xz and harfbuzz, which rank
  above their bare versions. Fingerprint records don't change. Manual
  check: Pillow 12.3.0 gives lcms2 2.19.0, ambiguous with 2.19.1, and
  xz 5.8.3 and harfbuzz 14.2.1 by version function machine code.

### 5. SBOM comparison

- **5.1** ✓ `pypiscan sbom <wheel>` and phase 09, as described in
  [SBOMs in wheels](#sboms-in-wheels): each file in a wheel's
  `.dist-info/sboms/`, its format and tools, and each CycloneDX
  component, kept apart from fingerprint records. CVEs and matching
  move to phases 10 and 11. Manual check: Pillow 12.3.0,
  psycopg2-binary 2.9.13 and cryptography 50.0.2 give the SBOMs the
  top-100 scan found, and lxml 6.1.3 none.
- **5.2** ✓ Compare SBOM claims against fingerprint results, as
  described in
  [Comparing SBOMs with fingerprints](#comparing-sboms-with-fingerprints):
  `sbom-report.md`, auditwheel's components tied to `.libs/` files by
  their bom-refs, their versions compared with fingerprint versions,
  and coverage and agreement counts. Manual check: Pillow, both
  psycopg wheels, scipy, scikit-learn and numba, which have auditwheel
  SBOMs, and numpy, which has `.libs/` files and none; in both psycopg
  wheels, krb5 and cyrus-sasl agree.

### 6. CVE data

- **6.1** ✓ CVE table format, loader and validation, as described in
  [The CVE table](#the-cve-table): `data/cves.toml`, its loader, and
  `--cve-table`, which pre-flight loads. Each row stores evidence, not
  just conclusions: the commits of each fix with the first release tag
  containing them and its date, the introducing commit (or `unknown`),
  the affected component (library code or a bundled tool), disputed
  status, NVD's CVSS scores and sources. Seeded with CVE-2023-4863,
  whose fixes are checked by hand in libwebp's upstream repository. The
  map's **cpe** is required for a library in the table, and filled in
  for libwebp. Manual check: a full episode rerun from phase 06 after
  the map change writes the same reports as before, and a table whose
  fix tag libwebp's **tags** doesn't match stops pre-flight.
- **6.2** ✓ Phase 10 (now 11), candidate CVEs from NVD, as described in
  [Candidates from NVD](#candidates-from-nvd): a query by each of a
  library's CPE names, and every candidate published from 2020-01-01
  on, with its scope, scores, ranges and patch links verbatim. **cpe**
  is required on every mapped row, may hold several names or `none`,
  and is filled in for every library from NVD's CPE dictionary and CVE
  records. Tests use recorded responses. Manual check: a full episode
  rerun from phase 06 after the map change writes the same reports as
  before; phase 10 lists CVE-2023-4863 for libwebp, `in` scope, with
  its Patch link, and gives geos and libsodium `skipped` lines.
- **6.3** Range verifier: given phase 06's clone and a row's fixes and
  introducing commit, compute the release tags that contain them and
  their dates; compare against the table's tags and dates and NVD's
  ranges, and flag disagreements. Tests use a small synthetic git
  repository. A CVE report, rewritten every run from phase 11 and the
  table, shows each candidate and whether the table lists it, as a row
  or a **duplicates** entry, beside the verifier's flags. *(Paused at
  the [checkpoint](#mini-roadmap-checkpoint).)*
- **6.4** *(maintainer input)* Curation review: resolve flagged rows, one
  library per pull request. Corrections to public advisories are submitted
  upstream. A bug in an original library can also be in a fork's code
  (zlib-ng began as a fork of zlib) without any advisory naming the fork;
  that is decided here, by reading the code, not guessed by matching.

### 7. Matching

- **7.1** Phase 12, `match`: compare fingerprints against the CVE table and
  write candidates with their evidence level into the episode, which is
  outside the repository. Each candidate shows the basis of its version,
  and one whose basis is `bare_version` is marked as needing another source
  to confirm it. One whose version is ambiguous is checked against every
  release it may be. Versions are tested by their release tags, as
  described in [The CVE table](#the-cve-table).
- **7.2** Evidence for levels 2 and 3: whether the affected function is
  present in the binary, and which extension modules import functions from
  the bundled library.

### 8. Publishing

- **8.1** Release script: a dated data snapshot plus a `SHA256SUMS` file,
  signed by the maintainer.

### Later (TBD)

- **Header string risk from identity_file alone.** The static
  discovery report marks a candidate as header string risk when its
  row's **identity_file** is a header. bzip2's `bzlib_private.h` is a
  private header no caller includes, so its candidates are marked
  though they can't be header strings. A per-row rule for public
  headers would fix it.
- **Which half of zlib a binary holds.** zlib's deflate and inflate
  banners come from `deflate.c` and `inftrees.c`, and a static link
  pulls in only the objects it uses, so a binary can hold one half.
  Some CVEs affect one half: CVE-2022-37434 is in inflate,
  CVE-2018-25032 in deflate. zlib stays one library, and matching could
  record which halves are present.
- **Rust source paths in the static templates.** In the top-100 run,
  about 90 of the static discovery report's top 100 templates are Rust
  crate source paths (`/rust/deps/…` and `.cargo/registry/…`), one per
  `.rs` file, so they crowd out the C libraries' strings. The paths
  carry crate versions, such as `aws-lc-sys`'s, that are kept for "C
  libraries behind Rust `-sys` crates", so a noise rule would hide
  them; collapsing each path to its crate directory would keep one
  template per crate.
- **OpenSSL in binaries outside `.libs/`.** No non-header string gives
  its version. cryptography's Rust `openssl` crate paths
  (`…/openssl-0.10.81/src/bio.rs`) are the bindings crate, so an
  `{any}/openssl-{version}/{any}` build-path row would misread them as
  OpenSSL 0.10.81. cryptography 50.0.2's SBOM naming OpenSSL 4.0.3 is a
  claim only.
- **C libraries behind Rust `-sys` crates.** In the top-100 run, no
  binary carries `zstd-sys`'s `+zstd.{version}` metadata. `aws-lc-sys`
  paths give the crate's version, which needs a crate-to-release table.
  ring is a crate whose paths give its own version (0.17.14 in
  litellm); its C and assembly derive from BoringSSL, and whether it
  counts as a bundled C library, and under which CPE, is open.
  BoringSSL embeds no version string, so no binary gives its version.
  The OpenSSL-style object names (GOST, `ANSI X9.62`) in 8 wheels show
  presence only.
- **zlib versions that aren't releases.** 1.3.0.1, 1.3.1.1 and 1.3.2.1
  are develop-branch versions, and playwright's node carries Chromium's
  zlib. Neither maps to a release tag for CVE ranges. zlib's map row
  marks four-part versions `not_release` (`\d+\.\d+\.\d+\.\d+`): its
  repository has a `v1.3.1.2` tag, whose `zlib.h` says `1.3.1.2-audit`,
  and which isn't a release on GitHub, so it never makes a wheel look
  behind.
- **Statically linked libraries with no `.libs/` prefix.** Map rows are
  keyed by prefix. A `detector` row (roadmap T.3) covers a library a
  hand-written detector finds, as zlib's does, but a library that would
  be found by a pattern alone and is seen only statically, such as
  aws-lc, still has no row to hang a recognizer on.
- **Several copies of one library in one binary.** playwright's
  `driver/node` carries zlib 1.3.2.1 and 1.3.0.1. Its `static_lib`
  record keeps both copies' banners in its evidence and has version
  `null` and `conflict` `true`, so the staleness report doesn't compare
  it, and `static-report.md` lists both versions as candidates.
  Splitting it into one record per copy needs a rule for pairing each
  `deflate` banner with its `inflate` banner.
- **Libraries compiled into another `.libs/` file.** Linkage is by
  location, so every phase 08 record is `shared_lib`, including
  Pillow's bzip2, which is compiled into `libfreetype`, not a `.libs/`
  file of its own. Telling the two apart needs the library map to say
  which library a `.libs/` file is, not only which libraries it may
  hold.
- **zlib-ng static records have no map row.** The zlib detector's
  derivative rule can give a `static_lib` record for zlib-ng, but
  zlib-ng has no map row, so the staleness report lists it as not
  compared, `not in phase 06`. No wheel in the top-100 run has one. A
  `detector` row for zlib-ng would bring it in.
- **geos's header string outside `.libs/`.** `{version}-CAPI-{any}`
  comes from `capi/geos_c.h.in`, so it can't qualify for static
  detection.
- **Phase files from an older numbering.** A lone `10-cves.jsonl` from
  before T.1 passes pre-flight as phase 10. Checking each file's name
  against its number's phase would catch it.
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
- **Lines before a library changed its numbering.** PostgreSQL's
  **line** is 1, which fits its versions from 10 on; before 10 a line was
  two numbers, such as 9.6, so a 9.x release is put on line 9.
- **Lines with no stated end of life.** krb5, OpenLDAP, xz, aom and
  brotli keep releases on older lines, but S.4 found no end-of-life date
  their projects state, and GEOS's site names none for 3.6 to 3.9, so
  those lines' status is `unknown`.
- **Tags that look like an older line's releases.** By the **line**
  rule, libtiff and zstd would keep older lines: libtiff's v3.5.1 and
  v3.5.2 are dated 2022, on commits of that date carrying 1999's
  releases into the repository, and zstd's v1.4.10, dated 2022 after
  1.5.0, is on commits preparing zstd's copy in the Linux kernel. Both
  are `single_line`, and the staleness report still counts those dates.
- **Time zones in days behind.** A tag's date is in the tag's own time
  zone, while the upload day is in UTC, so a staleness row's days
  behind can be off by one.
- **Staleness through a CVE lens.** On top of the staleness report:
  the high and critical CVEs NVD published between the bundled
  release's date and the wheel's upload day. These name current
  releases, so they follow
  [Data handling and disclosure](#data-handling-and-disclosure), and
  this is where 6.3, 6.4 and 7.1 come back in.
- **Time-to-patch.** How long wheels kept shipping an affected version.
  Needs every release of each affected package, with upload times per file
  (depth, where `scan` is breadth). The clock starts when a fixed library
  release was public (the later of the fixed release and the CVE's
  publication) and stops at the first release whose wheel for that
  platform bundles a fixed version. Wheels still unpatched are counted as
  unfinished, not dropped. A pilot would follow libwebp CVE-2023-4863.
- **One string claimed by two libraries.** A prefix can map to several
  libraries, and phase 08 resolves each library under it on its own. If
  recognizers of two libraries both match one string in a file, each gets
  a `contains` record, and nothing marks the pair for checking. No prefix
  in the current map has recognizers for more than one library, so this
  can't happen yet, but it needs a guard before one does. Two candidates:
  `tests/test_recognizer_examples.py` could require that no recognizer of
  another library under an example's prefix matches the example at all
  (today it checks only that none reads a different version from it), and
  phase 08 could mark records whose evidence shares a string with another
  library's. A derivative that carries the original's strings, such as
  zlib-ng with zlib's banners, is a separate case, under "Checking
  patterns at every release tag".
- **Patterns that don't name their library.** Most library-string
  patterns name the library, but two don't: bzip2's and geos's
  `{version}-CAPI-{any}`. Both strings are the libraries' own; the
  weakness is the pattern. bzip2's was `{version}, {any}`, which any
  string starting with a version and a comma matches: run over every
  binary outside `.libs/` in a `--count 20` episode, it matched seven
  strings in numpy 2.5.4's `mtrand` and `_generator`, such as
  `9, -0.52`. It is now narrowed to `{version}, {any}-{any}-20{any}`,
  which `BZ_VERSION`'s dated form (`1.0.8, 13-Jul-2019`) fits at every
  release from 1.0.1 on; earlier releases have no date and give
  nothing. geos's literal text is still only `-CAPI-`, so in a
  `libgeos_c` file a string with that text and a leading version would
  give a wrong, unflagged geos version. Options: a loader rule that a
  library-string pattern's literal text contains the library's name,
  ignoring case, which every other current pattern meets; or counting
  such patterns only as hints, like bare versions.
- **Versions that aren't releases.** Some builds stamp a library
  with a version no release has. numpy 2.5.4's OpenBLAS says
  `OpenBLAS 0.3.34.106.0`: scipy-openblas builds OpenBLAS at a
  commit and writes its own package version (the tag, the commits
  since it and a build number) into OpenBLAS's `VERSION`, so this is
  OpenBLAS 106 commits after 0.3.34. Compared as a version it falls
  between 0.3.34 and 0.3.35, so 7.1 may flag a CVE whose fix is
  among those 106 commits but won't miss one fixed later.
  openblas-libs records each build's exact commit in
  `openblas_commit.txt`, which 6.3's fix-commit check could use.
  scipy 1.18.1's says `OpenBLAS 0.3.31.dev`, OpenBLAS's own version
  on its development branch between the 0.3.31 and 0.3.32 releases;
  the string doesn't say which commit was built. It shows OpenBLAS's
  own version because openblas-libs began writing its package
  version into `VERSION` only in March 2026, after that build.
- **Libraries from the build image's packages.** auditwheel copies every
  library a wheel's binaries load, including the build image's own
  distribution packages. psycopg2-binary 2.9.13 builds OpenSSL, OpenLDAP
  and libpq from source, but installs krb5 and Cyrus SASL with `yum` on
  its manylinux2014 (CentOS 7) image, so its krb5 1.15.1 and cyrus-sasl
  2.1.26 are CentOS 7's packages. psycopg-binary 3.3.6 carries
  byte-identical copies (the same sha256, under the same auditwheel
  names, such as `libkrb5-fcafa220`). The name alone wouldn't show it:
  auditwheel names a copy by a hash of the original file's contents,
  then patches the copy, and both wheels have a `libssl-8bd944e8` whose
  bytes differ, each naming a different libcrypto. A distribution
  backports security fixes without changing the version, so an
  upstream CVE range can flag a fix the package already has. CentOS 7
  reached end of life in June 2024, so fixes released after that
  weren't backported. Level 2 (see
  [How findings are classified](#how-findings-are-classified)) needs an
  upstream build, so such a library needs a way to be recognized as a
  distribution build. Both wheels' auditwheel SBOMs (see
  [SBOMs in wheels](#sboms-in-wheels)) name the packages, such as
  `krb5-libs` 1.15.1-55.el7_9 and `cyrus-sasl-lib` 2.1.26-24.el7_9. The
  build image's package manager answered that, a stronger signal than a
  debuglink, though wheels repaired before auditwheel 6.5.0 have no
  SBOM. 5.2's report ties each such package to its file. Another
  candidate is a `.gnu_debuglink` section, which RPM's
  debuginfo split adds: psycopg2-binary's krb5 and SASL files have one
  and its libraries built from source don't, though any build that
  splits off debug info adds one.
- **Comparing project SBOMs.** 5.2 compares only auditwheel's
  components. A project's own SBOM names libraries, not files, and in
  its own words (Pillow's `FreeType`, `Little CMS 2`, and `zlib` for
  zlib-ng), so comparing one needs a hand-kept map from its names to
  the library map's. Pillow's is generated from the build scripts
  that are already the answer key, so it adds no independent source.
  Rust extensions' SBOMs name crates compiled in statically, which
  T.2 reads as claims (see
  [Mini-roadmap: statically linked libraries](#mini-roadmap-statically-linked-libraries)).
- **Other advisory sources.** Version 1 finds CVEs through NVD alone, by
  each library's CPE. Since April 15, 2026, NVD enriches first the CVEs
  in CISA's KEV catalog, in software the federal government uses, or in
  critical software, and marks the rest lowest priority, not scheduled
  for immediate enrichment; its unenriched backlog from before March 1,
  2026 is not scheduled either. Enrichment adds severity scores and
  product lists, and a query by CPE finds a CVE only through its product
  list, so a CVE NVD hasn't enriched is missed. libpq's CVE-2025-1094,
  which its CNA scored `HIGH` and NVD has deferred, is one, and libsodium
  and geos have no CPE name at all. NVD also no longer routinely scores
  a CVE its CNA has scored; the scope rule's "any score" covers that.
  NVD's API also carries each record's `affected` list, the vendor and
  product in the CNA's own words (libsodium's CVE-2025-69277 has one),
  which isn't a CPE and which phase 11 records but doesn't search.
  OSV gives git ranges for C libraries, but its record for CVE-2023-4863
  derives them from the same CPE range and patch link NVD has, so there
  it isn't an independent source; it may list CVEs NVD hasn't matched.
  The library map keeps an **osv** column for it. Adding a source means
  deciding how its CVEs, severities and fixes combine with NVD's.

- **Releases outside digits and dots.** A release is digits separated
  by dots, so libjpeg-turbo's `2.0.7-esr` and `2.0.8-esr`, releases of
  its extended-support 2.0 line, aren't counted, and a wheel bundling
  one isn't compared. A per-library rule for releases spelled another
  way would fix it.

- **Repo URLs aren't checked for https.** The loader accepts any
  **repo**, so an ssh URL could hang phase 06 on a host-key or
  passphrase prompt.

- **Wheels with an SBOM but no `.libs/` in the atlas.** The atlas counts
  them by SBOM kind and leaves them to `sbom-report.md`; a row for each
  would show what Rust extensions and projects claim beside what
  auditwheel copied.

- **Build images from more of a purl.** The atlas reads a release only
  from an `.elN` in an rpm version. A purl qualifier, such as a
  `distro` one, or a deb or apk version could name the release of other
  images.

- **Multi-library prefixes in the atlas.** A prefix the map ties to
  several libraries is shown as the prefix with its libraries listed.
  Phase 08's records for the wheel could say which of them the file
  holds.

- **Memory for huge zip members.** Phases 03, 04 and 10 read each member
  whole into memory, so a raised `--member-size-limit` needs that much RAM.

- **Cache disk space for large wheels.** C.5's eight wheels are several GB
  in the cache, and nothing reports or prunes the cache's size.

- **The `nvidia-*` and lingua wheels.** C.5 leaves out the 16 `nvidia-*`
  wheels and lingua-language-detector; nothing measures them yet.

- **The top-500 package list isn't committed.** The probe's list,
  `packages500.csv`, lives outside the repository, beside the episodes;
  in the repository only C.5's eight rows come from it.

- **Rust crate versions as zstd's.** chdb-core 26.9.0's static
  candidates give zstd 0.11.2+zstd.1.5.2, 0.13.0 and 0.13.3, which look
  like the Rust `zstd` crate's versions, not zstd's own.

- **Decimal digits after `.` as a hash.** The prefix cutter (C.6) cuts at
  `.` and 8 hex digits, so 8 decimal digits, such as a date-like version
  in `libfoo.20240101.so`, are cut too. This is accepted for now.

- **`libz` and `libcudart` have no map row.** After C.6, torchvision's
  `libz.915b4635` and `libcudart.faf08d9a` give the prefixes `libz` and
  `libcudart`, which the todo lists. zlib's map row has no prefix, so
  mapping `libz` needs a prefix on it, and `libcudart` needs a row of
  its own. The zlib detector (`detectors/zlib.py`) recognizes file names
  only with a `-` hash, so mapping `libz` should check that it also finds
  torchvision's `libz.915b4635.so.1`.

- **"1 binary" in the static report.** A wheel with one binary outside
  `.libs/` says `1 binary outside`, so a grep for `binaries outside`, as
  C.5's manual step used, misses its line.

- **Shared libraries by ELF header, not name.** The static report counts
  binaries by file name; `DT_SONAME` or the ELF type would count them
  without the name rules' misses.

- **sdist-only projects may be compiled.** C.7 counts a project with no
  wheel as `sdist_only`, but its sdist may build C extensions or bundle C
  libraries, which isn't knowable without building it.

- **No-target reasons from the latest release only.** C.7 reads each
  project's latest final release, so a project whose older releases had a
  target wheel, or that would have one under a different rule, isn't told
  apart.

- **`other` lumps requires_python exclusions.** C.7's `other` covers a
  wheel the tags accept whose Requires-Python excludes 3.12, beside wheel
  names that don't parse.

- **The top-pypi-packages snapshot isn't committed.** `--snapshot` reads
  a local copy, identified only by the sha256 the script prints.

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
- The staleness report names no CVE, so it may be published with package
  names, its bases shown and its not-compared counts included. Once a
  CVE is attached to a stale library, the rules above apply.

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
    80 MB. A host that ignores `--filter` gives a full clone instead, and
    git warns.
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
