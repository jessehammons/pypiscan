"""Phase 08 on hand-built phase 04, 05 and 07 lines: no ELF or wheel.

The recognizers come from phase 07 lines that ``recognizers_phase`` builds
from the committed library map, and the strings from
``recognizer_examples.tsv`` (see README "How versions are identified").
"""

import io
import json
from pathlib import Path
from typing import cast

from pypiscan.library_map import load_library_map
from pypiscan.package_list import Package
from pypiscan.scan import (
    Line,
    Result,
    Stop,
    fingerprint_phase,
    recognizers_phase,
    run_phases,
    upstream_libraries,
)
from pypiscan.wheel_strings import template

ROOT = Path(__file__).parent.parent
ROWS = load_library_map(ROOT / "data/libraries.csv")


def phase_07_lines() -> list[Line]:
    """Phase 07's lines for the committed map, as the phase writes them."""
    phase = recognizers_phase(ROWS)
    lines: list[Line] = []
    for library in upstream_libraries(ROWS):
        result = phase.run(library, {})
        lines.append(
            {
                "library": library.name,
                "status": result.status,
                "reason": result.reason,
                **result.data,
            }
        )
    return lines


MAP_LINES = phase_07_lines()


def string(text: str, offset: int, section: str | None = ".rodata") -> Line:
    return {
        "offset": offset,
        "section": section,
        "text": text,
        "template": template(text),
    }


def file(prefix: str, *strings: Line) -> tuple[str, str, list[Line]]:
    return f"pkg.libs/{prefix}-1a2b3c4d.so.1", prefix, list(strings)


def earlier(*files: tuple[str, str, list[Line]]) -> dict[str, Line]:
    return {
        "04-strings": {
            "status": "ok",
            "wheel": "pkg.whl",
            "records": [
                {"path": path, "sha256": f"sha-{prefix}", "strings": strings}
                for path, prefix, strings in files
            ],
        },
        "05-libraries": {
            "status": "ok",
            "libraries": [
                {"path": path, "prefix": prefix} for path, prefix, _ in files
            ],
        },
    }


def run(*files: tuple[str, str, list[Line]], lines: list[Line] = MAP_LINES) -> Result:
    phase = fingerprint_phase(lines)
    assert phase.name == "08-fingerprint" and phase.skip_not_ok
    return phase.run(Package("pkg", "1"), earlier(*files))


def records(*files: tuple[str, str, list[Line]], **kw: list[Line]) -> list[Line]:
    result = run(*files, **kw)
    assert result.status == "ok" and result.data["wheel"] == "pkg.whl"
    return cast(list[Line], result.data["records"])


def summary(record: Line) -> tuple[object, ...]:
    return (record["library"], record["version"], record["basis"], record["conflict"])


def test_library_string_and_bare_version_agree() -> None:
    lib = string("libpng version 1.6.58", 100)
    bare = string("1.6.58", 40)
    [record] = records(file("libpng16", lib, bare))
    assert record == {
        "schema_version": 2,
        "wheel": "pkg.whl",
        "path": "pkg.libs/libpng16-1a2b3c4d.so.1",
        "sha256": "sha-libpng16",
        "library": "libpng",
        "relation": "contains",
        "basis": "library_string",
        "version": "1.6.58",
        "conflict": False,
        # In offset order.
        "evidence": [
            {
                "kind": "bare_version",
                "text": "1.6.58",
                "offset": 40,
                "section": ".rodata",
            },
            {
                "kind": "library_string",
                "text": "libpng version 1.6.58",
                "offset": 100,
                "section": ".rodata",
            },
        ],
    }


def test_weaker_kind_that_disagrees_is_a_conflict() -> None:
    lib = string("libpng version 1.6.58", 100)
    [record] = records(file("libpng16", lib, string("1.6.57", 200)))
    assert summary(record) == ("libpng", "1.6.58", "library_string", True)


def test_bare_version_alone_sets_the_version() -> None:
    [record] = records(file("libpng16", string("1.6.58", 40)))
    assert summary(record) == ("libpng", "1.6.58", "bare_version", False)


def test_build_path_outranks_bare_version() -> None:
    path = string("/project/build/openjpeg-2.5.4/src/lib/openjp2/t1.c", 10)
    [record] = records(file("libopenjp2", path, string("2.5.4", 90)))
    assert summary(record) == ("openjpeg", "2.5.4", "build_path", False)
    assert record["relation"] == "contains"


def test_strongest_kind_that_disagrees_gives_no_version() -> None:
    a = string("/project/build/zstd-1.5.7/lib//dictBuilder/divsufsort.c", 10)
    b = string("/project/build/zstd-1.5.6/lib/common/xxhash.c", 90)
    [record] = records(file("libzstd", a, b))
    assert summary(record) == ("zstd", None, "build_path", True)


def test_bare_version_under_a_multi_library_prefix_is_never_used() -> None:
    bzip2 = string("1.0.8, 13-Jul-2019", 10)
    [record] = records(file("libfreetype", bzip2, string("2.14.3", 90)))
    assert summary(record) == ("bzip2", "1.0.8", "library_string", False)
    assert len(cast(list[Line], record["evidence"])) == 1
    assert records(file("libfreetype", string("2.14.3", 90))) == []

    aom = string("AOMedia Project AV1 Encoder 3.14.1", 10)
    [record] = records(file("libavif", aom, string("1.4.2", 90)))
    assert summary(record) == ("aom", "3.14.1", "library_string", False)
    assert records(file("libavif", string("1.4.2", 90))) == []


def test_noise_filter_applies() -> None:
    for section in (".comment", None):
        lib = string("libpng version 1.6.58", 10, section)
        assert records(file("libpng16", lib)) == []
    # The bare pattern matches an object identifier; the noise filter drops it.
    assert records(file("liblzma", string("2.16.840.1.101.3.4.1.42", 10))) == []
    [record] = records(file("liblzma", string("5.8.3", 10)))
    assert summary(record) == ("xz", "5.8.3", "bare_version", False)


def test_recognizers_run_only_under_their_prefix() -> None:
    openssl = string("OpenSSL 3.5.8 25 Aug 2026", 10)
    assert records(file("libssl", openssl)) == []
    [record] = records(file("libcrypto", openssl))
    assert summary(record) == ("openssl", "3.5.8", "library_string", False)
    # Skip and no-recognizer prefixes give nothing.
    assert records(file("libgfortran", string("1.6.58", 10))) == []
    assert records(file("libwebp", string("1.6.58", 10))) == []


def test_package_with_no_libs_files_is_ok_with_no_records() -> None:
    assert run() == Result("ok", None, {"wheel": "pkg.whl", "records": []})


def test_records_follow_phase_05_order() -> None:
    lzma = file("liblzma", string("5.8.3", 10))
    png = file("libpng16", string("libpng version 1.6.58", 10))
    found = records(lzma, png)
    assert [r["library"] for r in found] == ["xz", "libpng"]


def ok_line(library: str, *entries: tuple[str, str, str]) -> Line:
    return {
        "library": library,
        "status": "ok",
        "reason": None,
        "recognizers": [
            {"prefix": p, "kind": k, "pattern": pattern, "identity_file": "f.c"}
            for p, k, pattern in entries
        ],
    }


def test_phase_07_lines_are_the_source() -> None:
    # A pattern that differs from the map's is the one that runs.
    lines = [ok_line("libpng", ("libpng16", "library_string", "PNG {version}"))]
    assert (
        records(file("libpng16", string("libpng version 1.6.58", 10)), lines=lines)
        == []
    )
    [record] = records(file("libpng16", string("PNG 1.6.58", 10)), lines=lines)
    assert summary(record) == ("libpng", "1.6.58", "library_string", False)

    # A skipped line contributes nothing, even with recognizers in it.
    skipped = {**lines[0], "status": "skipped", "reason": "no_recognizer"}
    assert records(file("libpng16", string("PNG 1.6.58", 10)), lines=[skipped]) == []


def test_one_file_with_recognizers_from_several_lines() -> None:
    lines = [
        ok_line("beta", ("libx", "library_string", "Beta {version}")),
        ok_line("alpha", ("libx", "library_string", "Alpha {version}")),
    ]
    x = file("libx", string("Alpha 1.0", 10), string("Beta 2.0", 90))
    found = records(x, lines=lines)
    # Phase 07's line order, not the strings' order.
    assert [summary(r) for r in found] == [
        ("beta", "2.0", "library_string", False),
        ("alpha", "1.0", "library_string", False),
    ]


def write(path: Path, lines: list[Line]) -> None:
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))


def test_skip_rule_uses_the_previous_per_package_phase(tmp_path: Path) -> None:
    """A package skipped at 02-fetch keeps that reason in phase 08; one whose
    05 line is ok runs whatever phase 07's lines say."""
    names = ["01-resolve", "02-fetch", "03-inspect", "04-strings", "05-libraries"]
    a = earlier(file("libpng16", string("libpng version 1.6.58", 10)))
    for number, name in enumerate(names):
        a_line: Line = {"name": "a", "status": "ok", "reason": None}
        b_line: Line = {"name": "b", "status": "skipped", "reason": "02-fetch"}
        if name in a:
            a_line |= a[name]
        if number == 0:
            b_line = {"name": "b", "status": "ok", "reason": None}
        elif number == 1:
            b_line["reason"] = "too_large"
        write(tmp_path / f"{name}.jsonl", [a_line, b_line])
    # Every phase 07 line is skipped or error, except libpng's.
    lines = [
        {"library": "x", "status": "error", "reason": "boom"},
        *[line for line in MAP_LINES if line["library"] == "libpng"],
    ]
    err = io.StringIO()
    packages = [Package("a", "1"), Package("b", "2")]
    phases = [fingerprint_phase(lines)]
    assert run_phases(tmp_path, packages, phases, Stop(), err, finished=names) == 0
    assert err.getvalue() == "08-fingerprint: 1 ok, 1 skipped, 0 error\n"
    text = (tmp_path / "08-fingerprint.jsonl").read_text().splitlines()
    a_line, b_line = (json.loads(line) for line in text)
    assert (b_line["status"], b_line["reason"]) == ("skipped", "02-fetch")
    [record] = cast(list[Line], a_line["records"])
    assert summary(record) == ("libpng", "1.6.58", "library_string", False)
