from pathlib import Path

import pytest

from pypiscan.library_map import (
    COLUMNS,
    LibraryMapError,
    MapRow,
    load_library_map,
    matcher,
)

HEADER = ",".join(COLUMNS)
ZLIB = (
    "libz,zlib,https://github.com/madler/zlib,v{version},library_string,"
    "deflate {version} Copyright {any},deflate.c,deflate_copyright,,"
)
OPENJPEG = "libopenjp2,openjpeg,https://github.com/uclouvain/openjpeg,,build_path,{any}/openjpeg-{version}/{any},,,uclouvain:openjpeg,"
BARE = "libfoo,foo,https://example.org/foo,,bare_version,{version},version.c,,,"
WEBP = "libwebp,libwebp,https://chromium.googlesource.com/webm/libwebp,,,,,,,"
SKIP = "libgfortran,skip,,,,,,,,"


def write_map(path: Path, *rows: str, header: str = HEADER) -> Path:
    path.write_text(header + "\n" + "".join(f"{row}\n" for row in rows))
    return path


def test_header_only_map_is_valid(tmp_path: Path) -> None:
    assert load_library_map(write_map(tmp_path / "m.csv")) == []


def test_committed_map_loads() -> None:
    path = Path(__file__).parent.parent / "data" / "libraries.csv"
    rows = load_library_map(path)
    assert path.read_text().startswith(HEADER + "\n")
    assert len({row.prefix for row in rows}) == 43


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
        identity="deflate_copyright",
        cpe="",
        osv="",
    )
    assert rows[1].cpe == "uclouvain:openjpeg"


def test_a_prefix_can_map_to_several_libraries(tmp_path: Path) -> None:
    ng = (
        "libz,zlib-ng,https://github.com/zlib-ng/zlib-ng,,library_string,"
        "zlib-ng {version},zbuild.h,,,"
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


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("libz,zlib", "expected 10 fields, got 2"),
        (ZLIB + ",extra", "expected 10 fields, got 11"),
        (",zlib,r,,,,,,,", "prefix is empty"),
        ("libz,,r,,,,,,,", "library is empty"),
        ("libz,zlib,,,,,,,,", "repo is empty"),
        ("libz,zlib,,,build_path,{any}/zlib-{version}/{any},,,,", "repo is empty"),
        ("libz,zlib,r,,header_string,{version},f,,,", "unknown kind 'header_string'"),
        ("libz,zlib,r,,library_string,,f,,,", "pattern is empty"),
        ("libz,zlib,r,,,{version},,,,", "a row with no kind has no pattern"),
        ("libz,zlib,r,v{version},,,f,i,,", "a row with no kind has no identity_file"),
        ("libz,zlib,r,,build_path,{version}/{any},f,,,", "a build_path row has no"),
        ("libz,zlib,r,v{version},build_path,{version}/{any},,i,,", "a build_path"),
        (
            "libz,zlib,r,,library_string,zlib {version},,,,",
            "a library_string row needs",
        ),
        ("libz,zlib,r,,bare_version,{version},,,,", "a bare_version row needs an"),
        (
            "libz,zlib,r,,library_string,zlib {version},f,i,,",
            "a row with an identity needs tags",
        ),
        (
            "libz,zlib,r,,library_string,zlib,f,,,",
            r"pattern needs exactly one \{version\}",
        ),
        (
            "libz,zlib,r,,library_string,{version} {version},f,,,",
            "pattern needs exactly one",
        ),
        (
            "libz,zlib,r,,library_string,{version} {date},f,,,",
            r"pattern has an unknown placeholder \{date\}",
        ),
        ("libz,zlib,r,,bare_version,v{version},f,,,", "a bare_version pattern is"),
        ("libz,skip,,,library_string,,,,,", "a skip row has only a prefix and library"),
        ("libz,skip,,,,,,,zlib:zlib,", "a skip row .* but cpe is set"),
        ("libz,skip,r,,,,,i,,o", "a skip row .* but repo is set"),
    ],
)
def test_rejects_rows_that_dont_fit(tmp_path: Path, row: str, message: str) -> None:
    path = write_map(tmp_path / "m.csv", BARE, row)
    with pytest.raises(LibraryMapError, match=f"{path}:3: {message}"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("first", "second", "message"),
    [
        (ZLIB, "libz,skip,,,,,,,,", "prefix 'libz' is both skip and mapped"),
        (SKIP, "libgfortran,gcc,r,,,,,,,", "prefix 'libgfortran' is both skip"),
        (
            WEBP,
            WEBP.replace(",,,,,,,", ",,bare_version,{version},v.h,,,"),
            "library 'libwebp' under prefix 'libwebp' has a row with no kind",
        ),
        (
            BARE,
            "libfoo,foo,https://example.org/foo,,,,,,,",
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
            "libz2,zlib,https://github.com/madler/zlib,,bare_version,{version},z.h,,,",
            "library 'zlib' has another tags",
        ),
        (BARE, BARE[:-3] + ",,foo:foo,OSV", "library 'foo' has another cpe, osv"),
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
    row = f"libz,zlib,r,{tags},,,,,,"
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
    path = write_map(tmp_path / "m.csv", f"libz,zlib,r,{tags},,,,,,")
    with pytest.raises(LibraryMapError, match=f"{path}:2: {message}"):
        load_library_map(path)
