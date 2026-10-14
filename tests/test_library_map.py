from pathlib import Path

import pytest

from pypiscan.library_map import (
    COLUMNS,
    LibraryMapError,
    MapRow,
    load_library_map,
)

HEADER = ",".join(COLUMNS)
ZLIB = "libz,zlib,library_string,https://github.com/madler/zlib,deflate.c,deflate_copyright,,"
OPENJPEG = "libopenjp2,openjpeg,build_path,https://github.com/uclouvain/openjpeg,,openjpeg-,uclouvain:openjpeg,"
BARE = "libfoo,foo,bare_version,https://example.org/foo,version.c,FOO_VERSION,,"
SKIP = "libgfortran,skip,,,,,,"


def write_map(path: Path, *rows: str, header: str = HEADER) -> Path:
    path.write_text(header + "\n" + "".join(f"{row}\n" for row in rows))
    return path


def test_header_only_map_is_valid(tmp_path: Path) -> None:
    assert load_library_map(write_map(tmp_path / "m.csv")) == []


def test_committed_map_loads() -> None:
    path = Path(__file__).parent.parent / "data" / "libraries.csv"
    assert path.read_text() == HEADER + "\n"
    assert load_library_map(path) == []


def test_rows_of_every_kind(tmp_path: Path) -> None:
    path = write_map(tmp_path / "m.csv", ZLIB, "", OPENJPEG, BARE, SKIP)
    rows = load_library_map(path)
    assert [(row.prefix, row.library, row.kind) for row in rows] == [
        ("libz", "zlib", "library_string"),
        ("libopenjp2", "openjpeg", "build_path"),
        ("libfoo", "foo", "bare_version"),
        ("libgfortran", "skip", ""),
    ]
    assert rows[0] == MapRow(
        prefix="libz",
        library="zlib",
        kind="library_string",
        repo="https://github.com/madler/zlib",
        identity_file="deflate.c",
        identity="deflate_copyright",
        cpe="",
        osv="",
    )
    assert rows[1].cpe == "uclouvain:openjpeg"


def test_a_prefix_can_map_to_several_libraries(tmp_path: Path) -> None:
    ng = "libz,zlib-ng,library_string,https://github.com/zlib-ng/zlib-ng,zbuild.h,x,,"
    rows = load_library_map(write_map(tmp_path / "m.csv", ZLIB, ng, SKIP, SKIP))
    assert [row.library for row in rows] == ["zlib", "zlib-ng", "skip", "skip"]


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
        ("libz,zlib", "expected 8 fields, got 2"),
        (ZLIB + ",extra", "expected 8 fields, got 9"),
        (",zlib" + ZLIB.removeprefix("libz,zlib"), "prefix is empty"),
        ("libz,,library_string,r,f,i,,", "library is empty"),
        ("libz,zlib,,r,f,i,,", "kind is empty"),
        ("libz,zlib,library_string,,f,i,,", "repo is empty"),
        ("libz,zlib,build_path,,,i,,", "repo is empty"),
        ("libz,zlib,library_string,r,f,,,", "identity is empty"),
        ("libz,zlib,header_string,r,f,i,,", "unknown kind 'header_string'"),
        ("libz,zlib,build_path,r,f,zlib-,,", "a build_path row has no identity_file"),
        ("libz,zlib,library_string,r,,i,,", "a library_string row needs an identity"),
        ("libz,zlib,bare_version,r,,i,,", "a bare_version row needs an identity"),
        ("libz,skip,library_string,,,,,", "a skip row has only a prefix, but kind"),
        ("libz,skip,,,,,zlib:zlib,", "a skip row has only a prefix, but cpe"),
        (
            "libz,skip,,r,,i,,o",
            "a skip row has only a prefix, but repo, identity, osv is set",
        ),
    ],
)
def test_rejects_rows_that_dont_fit(tmp_path: Path, row: str, message: str) -> None:
    path = write_map(tmp_path / "m.csv", BARE, row)
    with pytest.raises(LibraryMapError, match=f"{path}:3: {message}"):
        load_library_map(path)


@pytest.mark.parametrize(
    ("first", "second"),
    [(ZLIB, "libz,skip,,,,,,"), (SKIP, "libgfortran,gfortran,build_path,r,,gcc-,,")],
)
def test_rejects_a_prefix_both_skip_and_mapped(
    tmp_path: Path, first: str, second: str
) -> None:
    path = write_map(tmp_path / "m.csv", first, BARE, second)
    with pytest.raises(
        LibraryMapError,
        match=r":4: prefix '\w+' is both skip and mapped \(see line 2\)",
    ):
        load_library_map(path)


def test_unreadable_map(tmp_path: Path) -> None:
    with pytest.raises(LibraryMapError, match="No such file"):
        load_library_map(tmp_path / "missing.csv")
    path = tmp_path / "binary.csv"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(LibraryMapError, match="codec"):
        load_library_map(path)
