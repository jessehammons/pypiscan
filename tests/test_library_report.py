import csv
from pathlib import Path

import pytest

from pypiscan.library_map import COLUMNS
from pypiscan.library_report import (
    TEMPLATE_LIMIT,
    libraries,
    prefix,
    report,
    todo,
    write_todo,
)
from pypiscan.noise import NOISE, TOKEN, only_oids, usable
from pypiscan.wheel_strings import VERSION_TOKEN, StringRecord, template


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("pillow.libs/libjpeg-1a2b3c4d.so.62.4.0", "libjpeg"),
        ("numpy.libs/libscipy_openblas64_-6bb31eeb.so", "libscipy_openblas64_"),
        ("x.libs/libgfortran-040039e1.so.5.0.0", "libgfortran"),
        # A library repaired twice has two hashes; the first one cuts.
        ("numpy.libs/libgfortran-83c28eba-468e71e5.so.5.0.0", "libgfortran"),
        ("x.libs/libquadmath-2284e583-a9307bba.so.0.0.0", "libquadmath"),
        # A hash is followed by the extension or another hash.
        ("x.libs/libfoo-1a2b3c4dx.so", "libfoo-1a2b3c4dx"),
        # No hash: cut at the first ".so".
        ("x.libs/libssl.so.3", "libssl"),
        ("x.libs/libfoo-1A2B3C4D.so", "libfoo-1A2B3C4D"),
        ("x.libs/libfoo-1a2b3c4.so.1", "libfoo-1a2b3c4"),
        ("x.libs/sub/libbar.so", "libbar"),
        # Nothing to cut.
        ("x.libs/libbaz", "libbaz"),
        ("x.libs/.so.1", ".so.1"),
    ],
)
def test_prefix(path: str, expected: str) -> None:
    assert prefix(path) == expected


def test_libraries_lists_only_libs_dir_records() -> None:
    records: list[dict[str, object]] = [
        {"path": "foo.libs/libz-0a1b2c3d.so.1.3.1", "in_libs_dir": True},
        {"path": "foo/_speedups.so", "in_libs_dir": False},
    ]
    assert libraries(records) == [
        {"path": "foo.libs/libz-0a1b2c3d.so.1.3.1", "prefix": "libz"}
    ]


def string(text: str, section: str | None = ".rodata") -> StringRecord:
    return {"offset": 0, "section": section, "text": text, "template": template(text)}


@pytest.mark.parametrize("section", [".rodata", ".data", ".data.rel.ro"])
def test_strings_in_data_sections_are_usable(section: str) -> None:
    assert usable(string("libpng version 1.6.58", section))


@pytest.mark.parametrize("section", [".comment", ".dynstr", None])
def test_strings_outside_data_sections_are_not(section: str | None) -> None:
    assert not usable(string("libpng version 1.6.58", section))


@pytest.mark.parametrize(
    "text",
    [
        "GCC: (GNU) 14.2.1 20250110",
        "annobin gcc 14.2.1",
        "memcpy@GLIBC_2.14",
        "/opt/_internal/cpython-3.12.9/include/python3.12",
    ],
)
def test_noise_is_not_usable(text: str) -> None:
    assert not usable(string(text))


def test_every_noise_pattern_is_tested() -> None:
    assert len(NOISE) == 4


@pytest.mark.parametrize(
    "text",
    [
        "1.2.840.10045.2.1",
        "2.16.840.1.101.3.4.1.42",
        "AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42",
        "1.2.3.4.5.6",
    ],
)
def test_strings_with_only_object_identifiers_are_noise(text: str) -> None:
    assert only_oids(text)
    assert not usable(string(text))


@pytest.mark.parametrize(
    "text",
    [
        "OpenSSL 3.5.8 25 Aug 2026",
        "zlib 1.3.1.1",
        "127.0.0.1",
        "ANSI X9.62",
        "id-ecPublicKey 1.2.840.10045.2.1 in OpenSSL 3.5.8",
        # Five parts can be a release version, so they're kept.
        "1.2.3.4.5",
        "OpenBLAS 0.3.34.106.0  USE64BITINT DYNAMIC_ARCH NO_AFFINITY",
    ],
)
def test_strings_with_a_release_like_token_are_kept(text: str) -> None:
    assert not only_oids(text)
    assert usable(string(text))


def test_a_string_with_no_token_is_not_an_oid() -> None:
    # strings never lists one, but the rule shouldn't depend on that.
    assert not only_oids("no version here")


def test_oid_token_matches_the_strings_token() -> None:
    assert TOKEN.pattern == VERSION_TOKEN.pattern.decode()


def strings_line(files: dict[str, list[StringRecord]]) -> dict[str, object]:
    return {
        "status": "ok",
        "records": [
            {"path": path, "strings": strings} for path, strings in files.items()
        ],
    }


def libraries_line(*paths: str) -> dict[str, object]:
    return {
        "status": "ok",
        "libraries": [{"path": path, "prefix": prefix(path)} for path in paths],
    }


PNG_A = "a.libs/libpng16-11111111.so.16.50.0"
PNG_B = "b.libs/libpng16-22222222.so.16.58.0"
JPEG_B = "b.libs/libjpeg-33333333.so.62.4.0"
JPEG_B2 = "b.libs/libjpeg-44444444.so.8.3.2"


def lines() -> dict[str, dict[str, dict[str, object]]]:
    return {
        "a": {
            "04-strings": strings_line(
                {
                    PNG_A: [
                        string("libpng version 1.6.50"),
                        string("GCC: (GNU) 14.2.1", ".comment"),
                        string("annobin 1.2", ".rodata"),
                    ],
                    "a/ext.so": [string("deflate 1.3.1 Copyright")],
                }
            ),
            "05-libraries": libraries_line(PNG_A),
        },
        "b": {
            "04-strings": strings_line(
                {
                    PNG_B: [
                        string("libpng version 1.6.58"),
                        string("1.6.58"),
                        string("AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42"),
                        string("libpng version 1.6.58"),
                    ],
                    JPEG_B: [],
                    JPEG_B2: [string("x `y` 1.0")],
                }
            ),
            "05-libraries": libraries_line(PNG_B, JPEG_B, JPEG_B2),
        },
        "c": {
            "04-strings": {"status": "ok", "records": []},
            "05-libraries": libraries_line(),
        },
        "d": {"05-libraries": {"status": "skipped", "reason": "02-fetch"}},
    }


def test_report() -> None:
    text = report(["a", "b", "c", "d"], lines())
    assert text == "\n".join(
        [
            "# Library report",
            "",
            "4 packages scanned, 2 with `.libs/` shared libraries, 2 prefixes, "
            "ordered by how many wheels carry them.",
            "",
            "Templates use only strings in data sections that pass the noise "
            "filter, cut to 200 characters, with one real example each. Every "
            "template is listed, ranked by how many wheels carry it, ties "
            "alphabetical.",
            "",
            "## Prefixes",
            "",
            "1. ` libpng16 `: 2 wheels, 2 files",
            "2. ` libjpeg `: 1 wheel, 2 files",
            "",
            "## 1. ` libpng16 `: 2 templates",
            "",
            "2 wheels, 2 files: a, b",
            "",
            "1. 2 wheels: ` libpng version #.#.# `",
            "   - e.g. ` libpng version 1.6.50 `",
            "2. 1 wheel: ` #.#.# `",
            "   - e.g. ` 1.6.58 `",
            "",
            "## 2. ` libjpeg `: 1 template",
            "",
            "1 wheel, 2 files: b",
            "",
            "1. 1 wheel: `` x `y` #.# ``",
            "   - e.g. `` x `y` 1.0 ``",
            "",
        ]
    )


def test_report_prefix_with_no_usable_strings() -> None:
    data = {
        "a": {
            "04-strings": strings_line({}),
            "05-libraries": libraries_line("a.libs/libfoo.so"),
        }
    }
    text = report(["a"], data)
    assert "1 package scanned, 1 with `.libs/` shared libraries, 1 prefix," in text
    assert text.endswith(
        "## 1. ` libfoo `: 0 templates\n\n1 wheel, 1 file: a\n\nNo usable strings.\n"
    )


def test_report_ties_order_by_files_then_name() -> None:
    data = {
        "a": {
            "04-strings": strings_line({}),
            "05-libraries": libraries_line(
                "a.libs/libzz.so",
                "a.libs/libyy.so",
                "a.libs/libxx.so",
                "a.libs/libxx.so.2",
            ),
        }
    }
    text = report(["a"], data)
    assert (
        "1. ` libxx `: 1 wheel, 2 files\n2. ` libyy `: 1 wheel, 1 file\n3. ` libzz `"
        in text
    )


def test_report_lists_every_template_cut_to_200_characters() -> None:
    long = "1.0 " + "x" * 300
    many = [string(f"{'a' * n} 1.0") for n in range(1, 25)]
    data = {
        "a": {
            "04-strings": strings_line({"a.libs/libfoo.so": [string(long), *many]}),
            "05-libraries": libraries_line("a.libs/libfoo.so"),
        }
    }
    text = report(["a"], data)
    assert "## 1. ` libfoo `: 25 templates\n" in text
    assert "Top " not in text
    assert text.count("   - e.g. ") == 25
    # The last template ranked, with ties alphabetical, is still listed.
    assert f"25. 1 wheel: ` {'a' * 24} #.# `\n" in text
    assert f"` {template(long)[:TEMPLATE_LIMIT]} `\n" in text
    assert f"` {long[:TEMPLATE_LIMIT]} `\n" in text
    assert "x" * 201 not in text


def test_todo_lists_unmapped_prefixes_in_report_order(tmp_path: Path) -> None:
    only_05 = {
        name: {"05-libraries": line["05-libraries"]} for name, line in lines().items()
    }
    assert todo(["a", "b", "c", "d"], only_05, set()) == ["libpng16", "libjpeg"]
    assert todo(["a", "b", "c", "d"], only_05, {"libpng16"}) == ["libjpeg"]
    path = tmp_path / "todo.csv"
    write_todo(path, ["libpng16", "libjpeg"])
    with path.open(newline="") as f:
        rows = list(csv.reader(f))
    assert rows == [COLUMNS, ["libpng16", *[""] * 12], ["libjpeg", *[""] * 12]]
    write_todo(path, [])
    assert path.read_text() == ",".join(COLUMNS) + "\n"
