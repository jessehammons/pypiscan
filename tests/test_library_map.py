import re
from pathlib import Path

import pytest

from pypiscan.fingerprint_report import libraries_by_prefix
from pypiscan.library_map import (
    AMBIGUOUS_COLUMNS,
    COLUMNS,
    LINE_EOL_COLUMNS,
    LibraryMapError,
    MapRow,
    VersionFunction,
    cpe_names,
    is_release,
    load_ambiguous_versions,
    load_library_map,
    load_line_eol,
    matcher,
    parse_version_function,
    release_line,
    tag_matcher,
)
from pypiscan.scan import recognizers_phase, upstream_libraries

HEADER = ",".join(COLUMNS)
ZLIB = (
    "libz,zlib,https://github.com/madler/zlib,v{version},,single_line,library_string,"
    "deflate {version} Copyright {any},deflate.c,,,none,"
)
OPENJPEG = (
    "libopenjp2,openjpeg,https://github.com/uclouvain/openjpeg,v{version},,single_line,"
    "build_path,{any}/openjpeg-{version}/{any},,,,uclouvain:openjpeg,"
)
BARE = "libfoo,foo,https://example.org/foo,v{version},,single_line,bare_version,{version},version.c,,,none,"
WEBP = "libwebp,libwebp,https://chromium.googlesource.com/webm/libwebp,v{version},,single_line,,,,,,none,"
SKIP = "libgfortran,skip,,,,,,,,,,,"


def write_map(path: Path, *rows: str, header: str = HEADER) -> Path:
    path.write_text(header + "\n" + "".join(f"{row}\n" for row in rows))
    return path


def test_header_only_map_is_valid(tmp_path: Path) -> None:
    assert load_library_map(write_map(tmp_path / "m.csv")) == []


def test_committed_map_loads() -> None:
    path = Path(__file__).parent.parent / "data" / "libraries.csv"
    rows = load_library_map(path)
    assert path.read_text().startswith(HEADER + "\n")
    assert len({row.prefix for row in rows if row.prefix}) == 43


def test_rows_of_every_kind(tmp_path: Path) -> None:
    path = write_map(tmp_path / "m.csv", ZLIB, "", OPENJPEG, BARE, WEBP, SKIP)
    rows = load_library_map(path)
    assert [(row.prefix, row.library, row.kind) for row in rows] == [
        ("libz", "zlib", "library_string"),
        ("libopenjp2", "openjpeg", "build_path"),
        ("libfoo", "foo", "bare_version"),
        ("libwebp", "libwebp", ""),
        ("libgfortran", "skip", ""),
    ]
    assert rows[0] == MapRow(
        prefix="libz",
        library="zlib",
        repo="https://github.com/madler/zlib",
        tags="v{version}",
        kind="library_string",
        pattern="deflate {version} Copyright {any}",
        identity_file="deflate.c",
        identity="",
        cpe="none",
        osv="",
    )
    assert rows[1].cpe == "uclouvain:openjpeg"


def test_a_prefix_can_map_to_several_libraries(tmp_path: Path) -> None:
    ng = (
        "libz,zlib-ng,https://github.com/zlib-ng/zlib-ng,{version},,single_line,library_string,"
        "zlib-ng {version},zbuild.h,,,none,"
    )
    inflate = ZLIB.replace("deflate", "inflate")
    rows = load_library_map(
        write_map(tmp_path / "m.csv", ZLIB, ng, inflate, SKIP, SKIP)
    )
    assert [row.library for row in rows] == ["zlib", "zlib-ng", "zlib", "skip", "skip"]


def test_a_library_can_span_prefixes(tmp_path: Path) -> None:
    other = WEBP.replace("libwebp,", "libwebpmux,", 1)
    path = write_map(tmp_path / "m.csv", WEBP, other)
    assert [row.prefix for row in load_library_map(path)] == ["libwebp", "libwebpmux"]


@pytest.mark.parametrize(
    ("header", "message"),
    [
        (HEADER + ",notes", "header must be"),
        (HEADER.removesuffix(",osv"), "header must be"),
        ("", "header must be"),
    ],
)
def test_rejects_wrong_columns(tmp_path: Path, header: str, message: str) -> None:
    with pytest.raises(LibraryMapError, match=message):
        load_library_map(write_map(tmp_path / "m.csv", header=header))


@pytest.mark.parametrize("cpe", ["webmproject:libwebp", "a_b.c+d~e-0:x"])
def test_accepts_a_cpe_vendor_and_product(tmp_path: Path, cpe: str) -> None:
    path = write_map(
        tmp_path / "m.csv", f"libz,zlib,r,v{{version}},,single_line,,,,,,{cpe},"
    )
    assert [row.cpe for row in load_library_map(path)] == [cpe]


@pytest.mark.parametrize(
    "cpe",
    [
        "libwebp",
        "WebMProject:libwebp",
        ":libwebp",
        "webmproject:",
        "webmproject:libwebp:1.3.2",
        "cpe:2.3:a:webmproject:libwebp",
        "webm project:libwebp",
        "webmproject::libwebp",
    ],
)
def test_rejects_a_cpe_of_the_wrong_shape(tmp_path: Path, cpe: str) -> None:
    path = write_map(
        tmp_path / "m.csv", f"libz,zlib,r,v{{version}},,single_line,,,,,,{cpe},"
    )
    with pytest.raises(LibraryMapError, match=f"{path}:2: cpe '{re.escape(cpe)}'"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("cpe", "names"),
    [
        ("mit:kerberos_5 mit:kerberos", ["mit:kerberos_5", "mit:kerberos"]),
        ("a:a b:b c:c", ["a:a", "b:b", "c:c"]),
        ("none", []),
    ],
)
def test_accepts_several_cpe_names_or_none(
    tmp_path: Path, cpe: str, names: list[str]
) -> None:
    path = write_map(
        tmp_path / "m.csv", f"libz,zlib,r,v{{version}},,single_line,,,,,,{cpe},"
    )
    [row] = load_library_map(path)
    assert (row.cpe, cpe_names(row.cpe)) == (cpe, names)


@pytest.mark.parametrize(
    ("cpe", "message"),
    [
        ("", "cpe is empty; use none for a library NVD has no CPE name for"),
        (
            "mit:kerberos_5  mit:kerberos",
            "cpe 'mit:kerberos_5  mit:kerberos' has an empty name; names are "
            "separated by single spaces",
        ),
        (" mit:kerberos", "cpe ' mit:kerberos' has an empty name"),
        ("mit:kerberos ", "cpe 'mit:kerberos ' has an empty name"),
        ("mit:kerberos\tmit:krb5", "cpe 'mit:kerberos\\tmit:krb5': 'mit:kerberos\\t"),
        ("a:a b:b a:a", "cpe 'a:a b:b a:a' lists a name twice"),
        ("none a:a", "cpe 'none a:a': 'none' isn't none or a vendor and product"),
        ("a:a none", "cpe 'a:a none': 'none' isn't none or a vendor and product"),
        ("None", "cpe 'None': 'None' isn't none or a vendor and product"),
        ("a:a B:b", "cpe 'a:a B:b': 'B:b' isn't"),
    ],
)
def test_rejects_a_bad_list_of_cpe_names(
    tmp_path: Path, cpe: str, message: str
) -> None:
    path = write_map(
        tmp_path / "m.csv", f"libz,zlib,r,v{{version}},,single_line,,,,,,{cpe},"
    )
    with pytest.raises(LibraryMapError) as raised:
        load_library_map(path)
    assert str(raised.value).startswith(f"{path}:2: {message}")


def test_rows_for_one_library_agree_on_every_cpe_name(tmp_path: Path) -> None:
    first = "libz,zlib,r,v{version},,single_line,,,,,,a:a b:b,"
    path = write_map(tmp_path / "m.csv", first, first.replace("libz,", "libz2,"))
    assert len(load_library_map(path)) == 2
    path = write_map(
        tmp_path / "m.csv", first, first.replace("libz,", "libz2,").replace(" b:b", "")
    )
    with pytest.raises(LibraryMapError, match="library 'zlib' has another cpe"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("libz,zlib", "expected 13 fields, got 2"),
        (ZLIB + ",extra", "expected 13 fields, got 14"),
        (",zlib,r,,,,,,,,,none,", "prefix is empty"),
        ("libz,,r,,,,,,,,,none,", "library is empty"),
        ("libz,zlib,,,,,,,,,,none,", "repo, tags is empty"),
        ("libz,zlib,r,,,,,,,,,none,", "tags is empty"),
        (
            "libz,zlib,r,,,single_line,library_string,zlib {version},f,,,none,",
            "tags is empty",
        ),
        (
            "libz,zlib,,v{version},,single_line,build_path,{any}/z-{version}/{any},,,,none,",
            "repo is",
        ),
        (
            "libz,zlib,r,v{version},,single_line,header_string,{version},f,,,none,",
            "unknown kind 'header_string'",
        ),
        (
            "libz,zlib,r,v{version},,single_line,library_string,,f,,,none,",
            "pattern is empty",
        ),
        (
            "libz,zlib,r,v{version},,single_line,,{version},,,,none,",
            "a row with no kind has no pattern",
        ),
        (
            "libz,zlib,r,v{version},,single_line,,,f,,,none,",
            "a row with no kind has no identity_file",
        ),
        (
            "libz,zlib,r,v{version},,single_line,build_path,{version}/{any},f,,,none,",
            "a build_path row has no",
        ),
        (
            "libz,zlib,r,v{version},,single_line,build_path,{version}/{any},,i,,,",
            "identity is",
        ),
        (
            "libz,zlib,r,v{version},,single_line,library_string,"
            "zlib {version},,,,none,",
            "a library_string row needs",
        ),
        (
            "libz,zlib,r,v{version},,single_line,bare_version,{version},,,,none,",
            "a bare_version row needs an",
        ),
        (
            "libz,zlib,r,v{version},,single_line,library_string,zlib {version},f,i,,,",
            "identity is empty in version 1",
        ),
        (
            "libz,zlib,r,v{version},,single_line,library_string,zlib,f,,,none,",
            r"pattern needs exactly one \{version\}",
        ),
        (
            "libz,zlib,r,v{version},,single_line,library_string,"
            "{version} {version},f,,,none,",
            "pattern needs exactly one",
        ),
        (
            "libz,zlib,r,v{version},,single_line,library_string,"
            "{version} {date},f,,,none,",
            r"pattern has an unknown placeholder \{date\}",
        ),
        (
            "libz,zlib,r,v{version},,single_line,bare_version,v{version},f,,,none,",
            "a bare_version pattern is",
        ),
        (
            "libz,skip,,,,,library_string,,,,,,",
            "a skip row has only a prefix and library",
        ),
        ("libz,skip,,,,,,,,,,zlib:zlib,", "a skip row .* but cpe is set"),
        ("libz,skip,r,,,,,,,i,,,o", "a skip row .* but repo is set"),
        ("libz,skip,,,,1,,,,,,,", "a skip row .* but line is set"),
        ("libz,zlib,r,v{version},,,,,,,,none,", "line is empty; use single_line"),
        ("libz,zlib,r,v{version},,0,,,,,,none,", "line '0' isn't a positive integer"),
        ("libz,zlib,r,v{version},,x,,,,,,none,", "line 'x' isn't a positive integer"),
    ],
)
def test_rejects_rows_that_dont_fit(tmp_path: Path, row: str, message: str) -> None:
    path = write_map(tmp_path / "m.csv", BARE, row)
    with pytest.raises(LibraryMapError, match=f"{path}:3: {message}"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("first", "second", "message"),
    [
        (ZLIB, "libz,skip,,,,,,,,,,,", "prefix 'libz' is both skip and mapped"),
        (
            SKIP,
            "libgfortran,gcc,r,v{version},,single_line,,,,,,none,",
            "prefix 'libgfortran' is both skip",
        ),
        (
            WEBP,
            WEBP.replace(
                "v{version},,,,,,,none,",
                "v{version},,bare_version,{version},v.h,single_line,,,none,",
            ),
            "library 'libwebp' under prefix 'libwebp' has a row with no kind",
        ),
        (
            BARE,
            "libfoo,foo,https://example.org/foo,v{version},,single_line,,,,,,none,",
            "library 'foo' under prefix 'libfoo' has a row with no kind",
        ),
        (
            WEBP,
            WEBP,
            "library 'libwebp' under .* no kind, which must be its only row",
        ),
        (
            BARE,
            BARE.replace("libfoo,", "libfoo2,", 1).replace(".org", ".com"),
            "library 'foo' has another repo",
        ),
        (
            ZLIB,
            "libz2,zlib,https://github.com/madler/zlib,{version},,single_line,bare_version,{version},z.h,,,none,",
            "library 'zlib' has another tags",
        ),
        (BARE, BARE[:-7] + ",,foo:foo,OSV", "library 'foo' has another cpe, osv"),
    ],
)
def test_rejects_rows_that_clash(
    tmp_path: Path, first: str, second: str, message: str
) -> None:
    path = write_map(tmp_path / "m.csv", first, OPENJPEG, second)
    with pytest.raises(LibraryMapError, match=rf":4: {message}.*\(see line 2\)"):
        load_library_map(path)


def test_unreadable_map(tmp_path: Path) -> None:
    with pytest.raises(LibraryMapError, match="No such file"):
        load_library_map(tmp_path / "missing.csv")
    path = tmp_path / "binary.csv"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(LibraryMapError, match="codec"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("pattern", "text", "version"),
    [
        ("LIBTIFF, Version {version}", "LIBTIFF, Version 4.7.1", "4.7.1"),
        ("OpenSSL {version} {any}", "OpenSSL 3.5.8 25 Aug 2026", "3.5.8"),
        ("OpenSSL {version} {any}", "OpenSSL 3.5.8 ", "3.5.8"),
        ("x {version}", "x 2.1.0-beta1+g1d92~rc", "2.1.0-beta1+g1d92~rc"),
        ("x {version}", "x 0.3.31.dev", "0.3.31.dev"),
        ("{version}-CAPI-{any}", "3.14.1-CAPI-1.20", "3.14.1"),
        ("{any}/zstd-{version}/{any}", "/p/zstd-1.5.7/lib//x.c", "1.5.7"),
        ("v{version} (build {any})", "v1.2 (build 2026)", "1.2"),
        # Whole strings only, and every other character is literal.
        ("LIBTIFF, Version {version}", "Since LIBTIFF, Version 4.5.1", None),
        ("LIBTIFF, Version {version}", "LIBTIFF, Version 4.5.1, x", None),
        ("v{version} (build {any})", "v1.2 build 2026", None),
        ("a.b {version}", "axb 1.0", None),
        ("x {version}", "x v1.0", None),
        ("x {version}", "x ", None),
        ("OpenSSL {version} {any}", "OpenSSL X9.42 DH implementation", None),
    ],
)
def test_matcher(pattern: str, text: str, version: str | None) -> None:
    match = matcher(pattern, "library_string").fullmatch(text)
    assert (match and match.group(1)) == version


def test_any_matches_across_lines() -> None:
    assert matcher("a {version}{any}", "library_string").fullmatch("a 1.0\nb")


@pytest.mark.parametrize(
    ("text", "version"),
    [
        ("1.6.58", "1.6.58"),
        ("0.3.34.106.0", "0.3.34.106.0"),
        ("14.2.1", "14.2.1"),
        ("001.000", None),
        ("1.3", None),
        ("1.3.1.zlib-ng", None),
        ("2.1.0-beta1", None),
        ("v1.2.3", None),
    ],
)
def test_bare_version_shape(text: str, version: str | None) -> None:
    match = matcher("{version}", "bare_version").fullmatch(text)
    assert (match and match.group(1)) == version
    # The same pattern in another kind takes any version.
    assert matcher("{version}", "build_path").fullmatch("1.3.1.zlib-ng")


@pytest.mark.parametrize("tags", ["v{version}", "bzip2-{version}"])
def test_accepts_tags_with_one_version(tmp_path: Path, tags: str) -> None:
    row = f"libz,zlib,r,{tags},,single_line,,,,,,none,"
    assert load_library_map(write_map(tmp_path / "m.csv", row))[0].tags == tags


@pytest.mark.parametrize(
    ("tags", "message"),
    [
        ("v1.2", r"tags needs exactly one \{version\}"),
        ("{version}-{version}", r"tags needs exactly one \{version\}"),
        ("v{any}", r"tags has an unknown placeholder \{any\}"),
    ],
)
def test_rejects_tags_without_one_version(
    tmp_path: Path, tags: str, message: str
) -> None:
    path = write_map(tmp_path / "m.csv", f"libz,zlib,r,{tags},,single_line,,,,,,none,")
    with pytest.raises(LibraryMapError, match=f"{path}:2: {message}"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("tags", "tag", "version"),
    [
        ("v{version}", "v1.3.2", "1.3.2"),
        ("v{version}", "v2.1.0-beta1", "2.1.0-beta1"),
        ("{version}", "1.0.22-RELEASE", "1.0.22-RELEASE"),
        ("REL_{version}", "REL_18_6", "18.6"),
        ("VER-{version}", "VER-2-14-3", "2.14.3"),
        ("OPENLDAP_REL_ENG_{version}", "OPENLDAP_REL_ENG_2_6_15", "2.6.15"),
        ("krb5-{version}-final", "krb5-1.15.1-final", "1.15.1"),
        ("lcms{version}", "lcms2.17", "2.17"),
        ("v{version}", "1.3.2", None),
        ("v{version}", "vx", None),
        ("krb5-{version}-final", "krb5-1.15.1-beta1", None),
        ("REL_{version}", "REL9_6_STABLE", None),
    ],
)
def test_tag_matcher(tags: str, tag: str, version: str | None) -> None:
    assert tag_matcher(tags)(tag) == version


# libfoo's bare_version row, and another library under the same prefix.
BAR_KIND = (
    "libfoo,bar,https://example.org/bar,v{version},,single_line,library_string,"
    "bar {version},bar.c,,,none,"
)
BAR_NO_KIND = "libfoo,bar,https://example.org/bar,v{version},,single_line,,,,,,none,"


@pytest.mark.parametrize("other", [BAR_KIND, BAR_NO_KIND], ids=["kind", "no-kind"])
@pytest.mark.parametrize("bare_first", [True, False], ids=["bare-first", "bare-last"])
def test_rejects_bare_version_under_a_multi_library_prefix(
    tmp_path: Path, other: str, bare_first: bool
) -> None:
    rows = (BARE, other) if bare_first else (other, BARE)
    path = write_map(tmp_path / "m.csv", *rows)
    first, second = ("foo", "bar") if bare_first else ("bar", "foo")
    message = (
        f"{path}:3: prefix 'libfoo' maps to '{first}' and '{second}', so it "
        "can't have a bare_version row: a bare version doesn't choose between "
        r"libraries \(see line 2\)"
    )
    with pytest.raises(LibraryMapError, match=message):
        load_library_map(path)


def test_bare_version_under_a_single_library_prefix(tmp_path: Path) -> None:
    other_prefix = BAR_KIND.replace("libfoo,", "libbar,", 1)
    lib_string = BARE.replace(
        "bare_version,{version},", "library_string,foo {version},"
    )
    rows = load_library_map(
        write_map(tmp_path / "m.csv", BARE, lib_string, other_prefix)
    )
    assert [(r.prefix, r.library, r.kind) for r in rows] == [
        ("libfoo", "foo", "bare_version"),
        ("libfoo", "foo", "library_string"),
        ("libbar", "bar", "library_string"),
    ]


# version_function_machine_code rows (roadmap 4.6).

FUNCTION = (
    "libwebp,libwebp,r,v{version},,single_line,version_function_machine_code,"
    "{},f.c,,,none,"
)


@pytest.mark.parametrize(
    ("pattern", "parsed"),
    [
        (
            "WebPGetDecoderVersion -> bits *.8.8",
            VersionFunction("WebPGetDecoderVersion", "bits", (8, 8)),
        ),
        ("f -> bits *.12.12", VersionFunction("f", "bits", (12, 12))),
        ("f -> bits *.31", VersionFunction("f", "bits", (31,))),
        (
            "WebPGetDemuxVersion -> bits *.8.8 from 65536",
            VersionFunction("WebPGetDemuxVersion", "bits", (8, 8), 65536),
        ),
        (
            "PQlibVersion -> decimal *.4 from 100000",
            VersionFunction("PQlibVersion", "decimal", (4,), 100000),
        ),
        ("f -> decimal *.2.2 from 0", VersionFunction("f", "decimal", (2, 2), 0)),
        ("zmq_version -> out", VersionFunction("zmq_version", "out")),
        (
            "dav1d_version -> string {version}-0-g{any}",
            VersionFunction("dav1d_version", "string", pattern="{version}-0-g{any}"),
        ),
        (
            "_f2 -> string v {version}",
            VersionFunction("_f2", "string", pattern="v {version}"),
        ),
    ],
)
def test_parse_version_function(pattern: str, parsed: VersionFunction) -> None:
    assert parse_version_function(pattern) == parsed


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("f", "pattern is <function> -> <encoding>"),
        ("f->out", "pattern is <function> -> <encoding>"),
        ("2f -> out", "'2f' isn't a C identifier"),
        ("f.g -> out", "'f.g' isn't a C identifier"),
        (" -> out", "'' isn't a C identifier"),
        ("f -> bits", "widths need a \\* and at least one more field"),
        ("f -> bits *", "widths need a \\* and at least one more field"),
        ("f -> bits 1.8.8", "widths need a \\*"),
        ("f -> bits *.8.*", "widths after the \\* are positive integers"),
        ("f -> bits *.0.8", "widths after the \\* are positive integers"),
        ("f -> bits *.-8", "widths after the \\* are positive integers"),
        ("f -> bits *.8.x", "widths after the \\* are positive integers"),
        ("f -> bits *.16.16", "bits widths after the \\* total more than 31"),
        ("f -> bits *.32", "bits widths after the \\* total more than 31"),
        ("f -> bits *.8.8 from", "from in a bits pattern takes an integer"),
        ("f -> bits *.8.8 from x", "from in a bits pattern takes an integer"),
        ("f -> bits *.8.8 from -1", "from in a bits pattern takes an integer"),
        ("f -> decimal *.4", "a decimal pattern ends with from and an integer"),
        ("f -> decimal *.4 from", "a decimal pattern ends with from and an integer"),
        ("f -> decimal *.4 from -1", "a decimal pattern ends with from and an"),
        ("f -> decimal *.4 from x", "a decimal pattern ends with from and an"),
        ("f -> decimal * from 0", "widths need a \\*"),
        ("f -> out x", "nothing follows out"),
        ("f -> out ", "nothing follows out"),
        ("f -> string", "pattern needs exactly one \\{version\\}"),
        ("f -> string {any}", "pattern needs exactly one \\{version\\}"),
        ("f -> string {version}{version}", "pattern needs exactly one"),
        (
            "f -> string {version} {date}",
            "pattern has an unknown placeholder \\{date\\}",
        ),
        ("f -> hex *.8", "unknown encoding 'hex'"),
    ],
)
def test_rejects_version_function_patterns(
    tmp_path: Path, pattern: str, message: str
) -> None:
    path = write_map(tmp_path / "m.csv", BARE, FUNCTION.replace("{}", pattern))
    with pytest.raises(LibraryMapError, match=f"{path}:3: {message}"):
        load_library_map(path)


def test_version_function_row_needs_an_identity_file(tmp_path: Path) -> None:
    row = FUNCTION.replace("{}", "f -> out").replace(",f.c,", ",,")
    path = write_map(tmp_path / "m.csv", row)
    message = f"{path}:2: a version_function_machine_code row needs an identity_file"
    with pytest.raises(LibraryMapError, match=message):
        load_library_map(path)


def test_version_function_shares_a_prefix(tmp_path: Path) -> None:
    rows = [
        "libavif,libavif,r,v{version},,single_line,version_function_machine_code,"
        "avifVersion -> string {version},src/avif.c,,,none,",
        "libavif,aom,a,v{version},,single_line,library_string,"
        "AOMedia {version},av1.c,,,none,",
        "libavif,dav1d,d,{version},,single_line,version_function_machine_code,"
        "dav1d_version -> string {version}-0-g{any},src/lib.c,,,none,",
        "libavif,yuv,y,{version},,single_line,,,,,,none,",
    ]
    loaded = load_library_map(write_map(tmp_path / "m.csv", *rows))
    assert [(r.library, r.kind) for r in loaded] == [
        ("libavif", "version_function_machine_code"),
        ("aom", "library_string"),
        ("dav1d", "version_function_machine_code"),
        ("yuv", ""),
    ]


# The list of ambiguous versions (README "Ambiguous versions").
AMBIGUOUS_HEADER = ",".join(AMBIGUOUS_COLUMNS)
MAPPED = [
    MapRow("liblcms2", "lcms2", "r", "v{version}", "", "", "", "", "", ""),
    MapRow("libgfortran", "skip", "", "", "", "", "", "", "", ""),
]


def write_list(path: Path, *rows: str, header: str = AMBIGUOUS_HEADER) -> Path:
    return write_map(path, *rows, header=header)


def test_header_only_ambiguous_list_is_valid(tmp_path: Path) -> None:
    assert load_ambiguous_versions(write_list(tmp_path / "a.csv"), MAPPED) == {}


def test_ambiguous_list_keeps_each_version_and_its_releases(tmp_path: Path) -> None:
    rows = ["lcms2,2.19.0,2.19.1", "", "lcms2,1.7.6,1.7.7", "lcms2,1.7.6,1.8.0"]
    path = write_list(tmp_path / "a.csv", *rows)
    assert load_ambiguous_versions(path, MAPPED) == {
        "lcms2": {"2.19.0": ["2.19.1"], "1.7.6": ["1.7.7", "1.8.0"]}
    }


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (["lcms2,2.19.0"], r":2: expected 3 fields, got 2"),
        (["lcms2,2.19.0,2.19.1,x"], r":2: expected 3 fields, got 4"),
        ([",2.19.0,2.19.1"], r":2: library is empty"),
        (["lcms2,,2.19.1"], r":2: version is empty"),
        (["lcms2,2.19.0,"], r":2: ambiguous_with is empty"),
        (["zlib,1.3,1.3.1"], r":2: library 'zlib' isn't mapped"),
        (["skip,1.3,1.3.1"], r":2: library 'skip' isn't mapped"),
        (["lcms2,v2.19,2.19.1"], r":2: 'v2.19' isn't a version"),
        (["lcms2,2.19.0,2.19 rc1"], r":2: '2.19 rc1' isn't a version"),
        (["lcms2,2.19.0,2.19.0"], r":2: version and ambiguous_with are the same"),
        (
            ["lcms2,2.19.0,2.19.1", "lcms2,2.19.0,2.19.1"],
            r":3: lcms2 2.19.0 2.19.1 is listed twice",
        ),
    ],
)
def test_ambiguous_list_rejects(tmp_path: Path, rows: list[str], message: str) -> None:
    path = write_list(tmp_path / "a.csv", *rows)
    with pytest.raises(LibraryMapError, match=rf"^{re.escape(str(path))}{message}"):
        load_ambiguous_versions(path, MAPPED)


@pytest.mark.parametrize(
    "header", ["library,version", "library,version,ambiguous_with,note", "a,b,c"]
)
def test_ambiguous_list_rejects_missing_or_unknown_columns(
    tmp_path: Path, header: str
) -> None:
    path = write_list(tmp_path / "a.csv", header=header)
    with pytest.raises(LibraryMapError, match="header must be"):
        load_ambiguous_versions(path, MAPPED)


def test_committed_ambiguous_list_loads_against_committed_map() -> None:
    data = Path(__file__).parent.parent / "data"
    rows = load_library_map(data / "libraries.csv")
    found = load_ambiguous_versions(data / "ambiguous_versions.csv", rows)
    assert found["lcms2"]["2.19.0"] == ["2.19.1"]
    assert found["libavif"]["0.3.0"] == ["0.3.1"]


# Several tags patterns, and versions that aren't releases (roadmap S.3).


def test_tags_patterns_are_tried_in_order() -> None:
    version = tag_matcher("lcms2-{version} lcms{version} {version}")
    assert version("lcms2-2.7") == "2.7"
    assert version("lcms2.19") == "2.19"
    assert version("2.11") == "2.11"
    assert version("lcm2.16rc1") is None
    # The first pattern that matches wins, even when a later one would too.
    assert tag_matcher("v{version} {version}")("v1.2") == "1.2"
    assert tag_matcher("{version} v{version}")("v1.2") == "1.2"


@pytest.mark.parametrize(
    ("version", "not_release", "release"),
    [
        ("3.1.4.1", r"\d+\.\d+\.9\d", True),
        ("3.1.90", r"\d+\.\d+\.9\d", False),
        ("2.1.91", r"\d+\.\d+\.9\d", False),
        ("3.1.900", r"\d+\.\d+\.9\d", True),
        ("3.1.90", "", True),
        ("2.19rc1", "", False),
        ("2.18rc_1", "", False),
        ("18_BETA1", "", False),
    ],
)
def test_is_release(version: str, not_release: str, release: bool) -> None:
    assert is_release(version, not_release) is release


def test_loads_tags_patterns_and_not_release(tmp_path: Path) -> None:
    row = r"libz,zlib,r,lcms2-{version} {version},\d+\.\d+\.9\d,single_line,,,,,,none,"
    [loaded] = load_library_map(write_map(tmp_path / "m.csv", row))
    assert loaded.tags == "lcms2-{version} {version}"
    assert loaded.not_release == r"\d+\.\d+\.9\d"


@pytest.mark.parametrize(
    ("tags", "not_release", "message"),
    [
        ("v{version}  {version}", "", "tags 'v{version}  {version}' has an empty"),
        ("v{version} v1.2", "", r"tags needs exactly one \{version\}"),
        ("v{version}", "(", "not_release '\\(' isn't a regex"),
    ],
)
def test_rejects_bad_tags_patterns_and_not_release(
    tmp_path: Path, tags: str, not_release: str, message: str
) -> None:
    row = f"libz,zlib,r,{tags},{not_release},single_line,,,,,,none,"
    path = write_map(tmp_path / "m.csv", row)
    with pytest.raises(LibraryMapError, match=f"{path}:2: {message}"):
        load_library_map(path)


def test_rows_for_one_library_agree_on_not_release(tmp_path: Path) -> None:
    first = r"libz,zlib,r,v{version},\d+\.9\d,single_line,,,,,,none,"
    second = first.replace("libz,", "libz2,", 1).replace(r"\d+\.9\d", "")
    path = write_map(tmp_path / "m.csv", first, second)
    with pytest.raises(LibraryMapError, match="has another not_release"):
        load_library_map(path)


def test_rows_for_one_library_agree_on_line(tmp_path: Path) -> None:
    first = "libz,zlib,r,v{version},,2,,,,,,none,"
    second = first.replace("libz,", "libz2,", 1).replace(",2,", ",single_line,")
    path = write_map(tmp_path / "m.csv", first, second)
    with pytest.raises(LibraryMapError, match="another line"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("version", "line", "expected"),
    [
        ("3.5.8", "2", "3.5"),
        ("18.6", "1", "18"),
        ("3.1.4.1", "3", "3.1.4"),
        # A version with fewer components is its own line.
        ("3", "2", "3"),
        ("3.5.8", "single_line", None),
    ],
)
def test_release_line(version: str, line: str, expected: str | None) -> None:
    assert release_line(version, line) == expected


# Lines' ends of life (roadmap S.4).
LINE_EOL_HEADER = ",".join(LINE_EOL_COLUMNS)
LINED = [
    MapRow("libcrypto", "openssl", "r", "v{version}", "", "", "", "", "", "", line="2"),
    MapRow("libpq", "postgresql", "r", "v{version}", "", "", "", "", "", "", line="1"),
    MapRow("libz", "zlib", "r", "v{version}", "", "", "", "", "", ""),
    MapRow("libgfortran", "skip", "", "", "", "", "", "", "", "", line=""),
]
SOURCE = "https://example.org/eol"


def test_line_eol_keeps_each_line(tmp_path: Path) -> None:
    rows = [
        f"openssl,3.0,2026-09-07,{SOURCE}",
        f"openssl,3.5,maintained,{SOURCE}",
        "",
        f"postgresql,13,2025-11-13,{SOURCE}",
    ]
    path = write_map(tmp_path / "e.csv", *rows, header=LINE_EOL_HEADER)
    assert load_line_eol(path, LINED) == {
        "openssl": {"3.0": "2026-09-07", "3.5": "maintained"},
        "postgresql": {"13": "2025-11-13"},
    }
    empty = write_map(tmp_path / "f.csv", header=LINE_EOL_HEADER)
    assert load_line_eol(empty, LINED) == {}


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (["openssl,3.0,maintained"], r":2: expected 4 fields, got 3"),
        ([f",3.0,maintained,{SOURCE}"], r":2: library is empty"),
        ([f"openssl,,maintained,{SOURCE}"], r":2: line is empty"),
        ([f"openssl,3.0,,{SOURCE}"], r":2: eol is empty"),
        (["openssl,3.0,maintained,"], r":2: source is empty"),
        ([f"curl,8.0,maintained,{SOURCE}"], r":2: library 'curl' isn't mapped"),
        ([f"skip,1.0,maintained,{SOURCE}"], r":2: library 'skip' isn't mapped"),
        ([f"zlib,1.3,maintained,{SOURCE}"], r":2: library 'zlib' has a single line"),
        ([f"openssl,3,maintained,{SOURCE}"], r":2: line '3' isn't 2 numbers"),
        ([f"openssl,3.5.8,maintained,{SOURCE}"], r":2: line '3.5.8' isn't 2"),
        ([f"openssl,3.x,maintained,{SOURCE}"], r":2: line '3.x' isn't 2"),
        ([f"postgresql,17.0,maintained,{SOURCE}"], r":2: line '17.0' isn't 1"),
        ([f"openssl,3.0,2026-9-7,{SOURCE}"], r":2: eol '2026-9-7' isn't an ISO date"),
        ([f"openssl,3.0,2026-02-30,{SOURCE}"], r":2: eol '2026-02-30' isn't"),
        ([f"openssl,3.0,supported,{SOURCE}"], r":2: eol 'supported' isn't"),
        (
            [f"openssl,3.0,maintained,{SOURCE}", f"openssl,3.0,2026-09-07,{SOURCE}"],
            r":3: openssl 3.0 is listed twice",
        ),
    ],
)
def test_line_eol_rejects(tmp_path: Path, rows: list[str], message: str) -> None:
    path = write_map(tmp_path / "e.csv", *rows, header=LINE_EOL_HEADER)
    with pytest.raises(LibraryMapError, match=rf"^{re.escape(str(path))}{message}"):
        load_line_eol(path, LINED)


def test_line_eol_rejects_wrong_columns(tmp_path: Path) -> None:
    path = write_map(tmp_path / "e.csv", header="library,line,eol")
    with pytest.raises(LibraryMapError, match="header must be"):
        load_line_eol(path, LINED)


def test_committed_line_eol_loads_against_committed_map() -> None:
    data = Path(__file__).parent.parent / "data"
    rows = load_library_map(data / "libraries.csv")
    found = load_line_eol(data / "line_eol.csv", rows)
    assert found["openssl"]["3.5"] == "2030-04-08"
    lines = {row.library: row.line for row in rows}
    assert (lines["openssl"], lines["postgresql"], lines["libpng"]) == (
        "2",
        "1",
        "single_line",
    )


# static_lib_detection (roadmap T.3).
DETECTOR = (
    ",zlib,https://github.com/madler/zlib,v{version},,single_line,,,,,detector,none,"
)
OPENJPEG_PATTERN = OPENJPEG.replace(",,,,uclouvain", ",,,pattern,uclouvain")


def test_detector_and_pattern_rows(tmp_path: Path) -> None:
    rows = load_library_map(write_map(tmp_path / "m.csv", OPENJPEG_PATTERN, DETECTOR))
    assert [(r.prefix, r.library, r.static_lib_detection) for r in rows] == [
        ("libopenjp2", "openjpeg", "pattern"),
        ("", "zlib", "detector"),
    ]
    # The empty prefix names no `.libs/` file.
    assert libraries_by_prefix(rows) == {"libopenjp2": ["openjpeg"]}
    # Phase 06 clones a detector row's library; phase 07 has nothing to build.
    zlib = upstream_libraries(rows)[1]
    assert (zlib.name, zlib.repo) == ("zlib", "https://github.com/madler/zlib")
    assert recognizers_phase(rows).run(zlib, {}).reason == "no_recognizer"


def test_committed_map_has_a_zlib_detector_row() -> None:
    rows = load_library_map(Path(__file__).parent.parent / "data" / "libraries.csv")
    detection = {(r.library, r.kind): r.static_lib_detection for r in rows}
    assert detection[("zlib", "")] == "detector"
    assert detection[("bzip2", "library_string")] == "pattern"
    assert [r.library for r in rows if r.static_lib_detection] == ["bzip2", "zlib"]


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (
            BARE.replace(",version.c,,,", ",version.c,,pattern,"),
            "a pattern row is a library_string or build_path row",
        ),
        (
            WEBP.replace(",,,,,,none,", ",,,,,pattern,none,"),
            "a pattern row is a library_string or build_path row",
        ),
        (
            "libwebp,libwebp,r,v{version},,single_line,version_function_machine_code,"
            "WebPGetDecoderVersion -> bits *.8.8,f.c,,pattern,none,",
            "a pattern row is a library_string or build_path row",
        ),
        (
            OPENJPEG.replace(",,,,uclouvain", ",,,yes,uclouvain"),
            "unknown static_lib_detection 'yes'; expected pattern, detector or empty",
        ),
        ("libz" + DETECTOR, "a detector row has no prefix and no kind"),
        (
            DETECTOR.replace(
                ",,,,,detector", ",library_string,z {version},z.c,,detector"
            ),
            "a detector row has no prefix and no kind",
        ),
        (
            DETECTOR.replace(",zlib,", ",foo,"),
            "library 'foo' has no hand-written detector",
        ),
        (
            DETECTOR.replace(",detector,", ",,"),
            "prefix is empty, which only a detector row can be",
        ),
        (
            ",zlib,https://github.com/madler/zlib,v{version},,single_line,"
            "library_string,z {version},z.c,,pattern,none,",
            "prefix is empty, which only a detector row can be",
        ),
        ("libz,skip,,,,,,,,,detector,,", "a skip row .* but static_lib_detection"),
    ],
)
def test_rejects_static_lib_detection_that_doesnt_fit(
    tmp_path: Path, row: str, message: str
) -> None:
    path = write_map(tmp_path / "m.csv", BARE, row)
    with pytest.raises(LibraryMapError, match=f"{path}:3: {message}"):
        load_library_map(path)


def test_rows_for_one_library_agree_on_detector(tmp_path: Path) -> None:
    path = write_map(tmp_path / "m.csv", DETECTOR, ZLIB)
    message = r":3: library 'zlib' has another static_lib_detection \(detector or not\)"
    with pytest.raises(LibraryMapError, match=message):
        load_library_map(path)
    # A pattern row and a row with none can be the same library's.
    pattern = ZLIB.replace(",deflate.c,,,", ",deflate.c,,pattern,")
    second = ZLIB.replace("libz,", "libz2,", 1)
    assert len(load_library_map(write_map(tmp_path / "m.csv", pattern, second))) == 2
