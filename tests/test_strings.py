import hashlib
import json
from pathlib import Path

import pytest

from elf_builder import build_elf
from pypiscan.cli import main
from pypiscan.wheel_inspect import WheelError
from pypiscan.wheel_strings import (
    SCHEMA_VERSION,
    binary_strings,
    strings_wheel,
    template,
)
from test_inspect import build_wheel

BANNER = " deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly and Mark Adler "


def texts(data: bytes) -> list[str]:
    return [record["text"] for record in binary_strings(data)]


def test_template_replaces_every_digit_run() -> None:
    assert template(BANNER) == (
        " deflate #.#.# Copyright #-# Jean-loup Gailly and Mark Adler "
    )
    assert template("zlib 1.3.1.1-motley v2") == "zlib #.#.#.#-motley v#"


@pytest.mark.parametrize(
    ("text", "listed"),
    [
        ("1.2", True),
        ("libz.so.1.3.1", True),
        ("GCC: (GNU) 12.2.1 20221121", True),
        ("version 12", False),
        ("1. 2", False),
        ("v1.", False),
        (".5", False),
        ("1995-2026", False),
        ("no digits.here", False),
    ],
)
def test_listed_only_with_a_version_token(text: str, listed: bool) -> None:
    assert texts(b"\0" + text.encode() + b"\0") == ([text] if listed else [])


def test_strings_are_kept_exactly_and_end_at_any_non_printable_byte() -> None:
    data = (
        b"\x01\t lead 1.0 trail \t\n"  # tab is printable, newline is not
        + b"a 2.0\x7fb 3.0\x80c 4.0\xff"
        + b"end 5.0"  # ends with the data
    )
    assert binary_strings(data) == [
        {
            "offset": 1,
            "section": None,
            "text": "\t lead 1.0 trail \t",
            "template": "\t lead #.# trail \t",
        },
        {"offset": 20, "section": None, "text": "a 2.0", "template": "a #.#"},
        {"offset": 26, "section": None, "text": "b 3.0", "template": "b #.#"},
        {"offset": 32, "section": None, "text": "c 4.0", "template": "c #.#"},
        {"offset": 38, "section": None, "text": "end 5.0", "template": "end #.#"},
    ]


def test_records_section_or_null() -> None:
    elf = build_elf(
        ["libc.so.6"],
        rodata=b"\0" + BANNER.encode() + b"\0",
        trailer=b"\0outside 9.9\0",
    )
    records = binary_strings(elf)
    by_text = {r["text"]: r for r in records}
    banner = by_text[BANNER]
    assert banner["section"] == ".rodata"
    assert banner["template"] == template(BANNER)
    assert elf[banner["offset"] :].startswith(BANNER.encode())
    assert by_text["outside 9.9"]["section"] is None
    assert [r["offset"] for r in records] == sorted(r["offset"] for r in records)


def test_strings_wheel_has_one_record_per_elf_binary(tmp_path: Path) -> None:
    etree = build_elf(["libc.so.6"], rodata=b"\0" + BANNER.encode() + b"\0")
    plain = build_elf(["libc.so.6"])
    wheel = build_wheel(
        tmp_path / "foo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        {
            "foo/etree.so": etree,
            "foo/plain.so": plain,
            "foo/__init__.py": BANNER.encode(),
        },
    )
    records = strings_wheel(wheel)
    assert [(r["path"], r["sha256"]) for r in records] == [
        ("foo/etree.so", hashlib.sha256(etree).hexdigest()),
        ("foo/plain.so", hashlib.sha256(plain).hexdigest()),
    ]
    assert {r["schema_version"] for r in records} == {SCHEMA_VERSION}
    assert {r["wheel"] for r in records} == {wheel.name}
    assert [s["text"] for s in records[0]["strings"]] == [BANNER]
    assert records[1]["strings"] == []


def test_strings_wheel_errors(tmp_path: Path) -> None:
    with pytest.raises(WheelError, match="no such file"):
        strings_wheel(tmp_path / "missing.whl")


def test_cli_prints_json_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rodata = b"\0" + BANNER.encode() + b"\0"
    wheel = build_wheel(tmp_path / "w.whl", {"w/_z.so": build_elf([], rodata=rodata)})

    assert main(["strings", str(wheel)]) == 0

    out, err = capsys.readouterr()
    assert [json.loads(line) for line in out.splitlines()] == strings_wheel(wheel)
    assert err == ""


def test_cli_error_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip")

    assert main(["strings", str(bogus)]) == 1

    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("pypiscan strings: error: ")
