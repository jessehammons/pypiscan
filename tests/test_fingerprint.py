import hashlib
import json
import re
import zipfile
from pathlib import Path

import pytest

from elf_builder import build_elf
from pypiscan.cli import main
from pypiscan.detectors import DETECTORS
from pypiscan.fingerprint import (
    SCHEMA_VERSION,
    Detector,
    Pattern,
    fingerprint_binary,
    fingerprint_wheel,
)
from pypiscan.wheel_inspect import WheelError


def deflate(version: str, year: str = "2026") -> bytes:
    return (
        f" deflate {version} Copyright 1995-{year} Jean-loup Gailly and Mark Adler \0"
    ).encode()


def inflate(version: str, year: str = "2026") -> bytes:
    return f" inflate {version} Copyright 1995-{year} Mark Adler \0".encode()


ZLIB_132 = b"\0" + deflate("1.3.2") + b"\0\0" + inflate("1.3.2")
# zlib-ng 2.3.3 carries classic zlib 1.3.1's banners unchanged.
ZLIB_NG_233 = (
    b"\0" + deflate("1.3.1", "2024") + inflate("1.3.1", "2024") + b"\0 zlib-ng 2.3.3\0"
)


def scan(data: bytes, path: str = "pkg/_ext.so") -> list[dict[str, object]]:
    return [dict(r) for r in fingerprint_binary(DETECTORS, "x.whl", path, data)]


def one(data: bytes, path: str = "pkg/_ext.so") -> dict[str, object]:
    (record,) = scan(data, path)
    return record


def texts(record: dict[str, object]) -> list[tuple[object, ...]]:
    evidence = record["evidence"]
    assert isinstance(evidence, list)
    return [(e["kind"], e["text"], e["section"]) for e in evidence]


def test_classic_zlib_contains() -> None:
    elf = build_elf(None, rodata=ZLIB_132)
    record = one(elf)

    assert record == {
        "schema_version": SCHEMA_VERSION,
        "wheel": "x.whl",
        "path": "pkg/_ext.so",
        "sha256": hashlib.sha256(elf).hexdigest(),
        "library": "zlib",
        "relation": "contains",
        "basis": "library_string",
        "version": "1.3.2",
        "conflict": False,
        "evidence": [
            {
                "kind": "library_string",
                "text": deflate("1.3.2").rstrip(b"\0").decode(),
                "offset": elf.index(b" deflate "),
                "section": ".rodata",
            },
            {
                "kind": "library_string",
                "text": inflate("1.3.2").rstrip(b"\0").decode(),
                "offset": elf.index(b" inflate "),
                "section": ".rodata",
            },
        ],
    }


def test_schema_version_is_3() -> None:
    # 2 added basis; 3 added the version_function_machine_code kind.
    assert SCHEMA_VERSION == 3


def test_four_part_version_kept_exactly() -> None:
    record = one(build_elf(None, rodata=b"\0" + deflate("1.3.1.1", "2024")))

    assert (record["library"], record["version"]) == ("zlib", "1.3.1.1")


def test_banner_after_printable_data_still_matches() -> None:
    # In grpcio's cygrpc the deflate banner follows a table byte 0x2d ("-").
    record = one(build_elf(None, rodata=b"\x01Z-" + deflate("1.3.1.1", "2024")))

    assert record["version"] == "1.3.1.1"


def test_banner_must_end_at_nul() -> None:
    assert scan(build_elf(None, rodata=deflate("1.3.2")[:-1] + b"x\0")) == []


def test_zlib_ng_is_never_reported_as_zlib() -> None:
    record = one(build_elf(None, rodata=ZLIB_NG_233))

    assert (record["library"], record["relation"], record["basis"]) == (
        "zlib-ng",
        "contains",
        "library_string",
    )
    assert (record["version"], record["conflict"]) == ("2.3.3", False)
    assert [kind for kind, _, _ in texts(record)] == ["library_string"] * 3


@pytest.mark.parametrize(
    ("banner_version", "year", "identity", "expected"),
    [
        # 2.0.0-2.0.6: banners say 1.2.11.f, and zlibng_string has a suffix.
        ("1.2.11.f", "2016", b" zlib-ng 2.0.6 forked from zlib", "2.0.6"),
        # 2.0.7: classic 1.2.11's version string with a 2022 copyright year.
        ("1.2.11", "2022", b" zlib-ng 2.0.7 forked from zlib", "2.0.7"),
        # 2.1 betas put the beta tag in the version itself.
        ("1.2.13", "2022", b" zlib-ng 2.1.0.beta1", "2.1.0.beta1"),
    ],
    ids=["2.0.6", "2.0.7", "2.1.0-beta1"],
)
def test_zlib_ng_identity_string_across_releases(
    banner_version: str, year: str, identity: bytes, expected: str
) -> None:
    banners = deflate(banner_version, year) + inflate(banner_version, year)
    record = one(build_elf(None, rodata=b"\0" + banners + identity + b"\0"))

    assert (record["library"], record["version"]) == ("zlib-ng", expected)
    assert record["conflict"] is False
    assert ("library_string", identity.decode(), ".rodata") in texts(record)


def test_zlib_ng_compat_library_with_filename() -> None:
    rodata = ZLIB_NG_233 + b"1.3.1.zlib-ng\0"
    path = "pkg.libs/libz-0123abcd.so.1.3.1.zlib-ng"
    record = one(build_elf([], rodata=rodata), path)

    assert (record["library"], record["version"]) == ("zlib-ng", "2.3.3")
    assert texts(record)[-2:] == [
        ("header_string", "1.3.1.zlib-ng", ".rodata"),
        ("filename", "libz-0123abcd.so.1.3.1.zlib-ng", None),
    ]


def test_zlib_ng_native_filename() -> None:
    record = one(build_elf([], rodata=ZLIB_NG_233), "pkg.libs/libz-ng.so.2.3.3")

    assert texts(record)[-1] == ("filename", "libz-ng.so.2.3.3", None)


def test_header_string_only_is_compiled_against() -> None:
    rodata = b"\0tempfile\x001.3.1.zlib-ng\0write\0"
    record = one(build_elf(["libz.so.1"], rodata=rodata))

    assert record["library"] == "zlib-ng"
    assert (record["relation"], record["basis"]) == (
        "compiled_against",
        "header_string",
    )
    assert (record["version"], record["conflict"]) == ("1.3.1.zlib-ng", False)


def test_header_strings_that_disagree_give_no_version() -> None:
    rodata = b"\x001.3.1.zlib-ng\x001.3.0.zlib-ng\0"
    record = one(build_elf(None, rodata=rodata))

    assert (record["relation"], record["version"]) == ("compiled_against", None)


def test_header_string_must_be_a_whole_string() -> None:
    assert scan(build_elf(None, rodata=b"\0v1.3.1.zlib-ng\0")) == []


def test_library_strings_that_disagree_conflict() -> None:
    rodata = b"\0" + deflate("1.3.1") + inflate("1.3.2")
    record = one(build_elf(None, rodata=rodata))

    assert (record["version"], record["conflict"]) == (None, True)


@pytest.mark.parametrize(
    ("rodata", "path"),
    [
        pytest.param(b"", "pkg.libs/libz-0123abcd.so.1.3.1", id="filename-only"),
        pytest.param(b"\x001.3.2\0", "pkg/_ext.so", id="bare-version"),
        pytest.param(b"\0zlib\0deflate\0", "pkg/_ext.so", id="no-banner"),
    ],
)
def test_no_record_without_library_or_header_strings(rodata: bytes, path: str) -> None:
    assert scan(build_elf([], rodata=rodata), path) == []


def test_filename_corroborates_but_never_sets_version() -> None:
    record = one(build_elf([], rodata=ZLIB_132), "pkg.libs/libz-0123abcd.so.1.2.13")

    assert record["version"] == "1.3.2"
    assert texts(record)[-1] == ("filename", "libz-0123abcd.so.1.2.13", None)


@pytest.mark.parametrize(
    "elf",
    [
        pytest.param(build_elf(None, trailer=ZLIB_132), id="outside-sections"),
        pytest.param(
            build_elf(None, section_headers=False, rodata=ZLIB_132),
            id="no-section-headers",
        ),
        pytest.param(b"\x7fELF" + b"\xff" * 64 + ZLIB_132, id="unparseable-elf"),
    ],
)
def test_unmapped_offsets_have_no_section(elf: bytes) -> None:
    record = one(elf)

    assert record["version"] == "1.3.2"
    assert {section for _, _, section in texts(record)} == {None}


def test_scanner_runs_any_detector() -> None:
    detector = Detector(
        patterns=(
            Pattern(
                "libfoo",
                "library_string",
                re.compile(rb"libfoo version (?P<version>[0-9.]+)\x00"),
                "test",
            ),
        )
    )
    elf = build_elf(None, rodata=b"\0libfoo version 4.5\0" + ZLIB_132)

    records = fingerprint_binary((detector, *DETECTORS), "x.whl", "a.so", elf)

    assert [(r["library"], r["version"]) for r in records] == [
        ("libfoo", "4.5"),
        ("zlib", "1.3.2"),
    ]


def build_wheel(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_fingerprint_wheel_reports_each_binary(tmp_path: Path) -> None:
    whl = build_wheel(
        tmp_path / "lxmlish-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        {
            "lxmlish/etree.so": build_elf(["libc.so.6"], rodata=ZLIB_132),
            "lxmlish/objectify.so": build_elf(["libc.so.6"], rodata=ZLIB_132),
            "lxmlish/sax.so": build_elf(["libc.so.6"]),
            "lxmlish/__init__.py": ZLIB_132,
        },
    )

    records = fingerprint_wheel(whl, DETECTORS)

    assert [(r["path"], r["library"], r["version"]) for r in records] == [
        ("lxmlish/etree.so", "zlib", "1.3.2"),
        ("lxmlish/objectify.so", "zlib", "1.3.2"),
    ]
    assert {r["wheel"] for r in records} == {whl.name}


def test_fingerprint_wheel_errors(tmp_path: Path) -> None:
    with pytest.raises(WheelError, match="no such file"):
        fingerprint_wheel(tmp_path / "missing.whl", DETECTORS)


def test_cli_prints_json_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    whl = build_wheel(tmp_path / "w.whl", {"w/_z.so": build_elf([], rodata=ZLIB_132)})

    assert main(["fingerprint", str(whl)]) == 0

    out, err = capsys.readouterr()
    assert [json.loads(line) for line in out.splitlines()] == fingerprint_wheel(
        whl, DETECTORS
    )
    assert err == ""


def test_cli_error_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip")

    assert main(["fingerprint", str(bogus)]) == 1

    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("pypiscan fingerprint: error: ")
