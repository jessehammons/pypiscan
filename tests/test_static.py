"""Phase 10 and the static discovery report (roadmap T.1), and phase 10's
static_lib records (roadmap T.3).

Wheels are built in ``tmp_path`` from ``elf_builder.build_elf`` images, and
phase 04's lines come from ``strings_wheel`` over them, as phase 04 writes
them. The recognizers come from phase 07 lines built from the committed
library map.
"""

import hashlib
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import cast

from elf_builder import build_elf
from pypiscan.library_map import MapRow, load_library_map
from pypiscan.library_report import prefix
from pypiscan.package_list import Package
from pypiscan.scan import (
    STATIC_SCHEMA_VERSION,
    Line,
    Result,
    recognizers_phase,
    static_phase,
    upstream_libraries,
)
from pypiscan.static_report import report
from pypiscan.wheel_strings import strings_wheel

ROOT = Path(__file__).parent.parent
ROWS = load_library_map(ROOT / "data/libraries.csv")
AMBIGUOUS = {"zlib": {"1.3.2": ["1.3.2.1"]}}

DEFLATE = b" deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly and Mark Adler \0"
INFLATE = b" inflate 1.3.2 Copyright 1995-2026 Mark Adler \0"
OPENSSL = b"\0OpenSSL 3.5.8 25 Aug 2026\0"
OPENBLAS = b"\0OpenBLAS 0.3.31.dev DYNAMIC_ARCH NO_AFFINITY \0"
BZIP2 = b"\x001.0.8, 13-Jul-2019\0"


def phase_07_lines() -> list[Line]:
    phase = recognizers_phase(ROWS)
    lines: list[Line] = []
    for library in upstream_libraries(ROWS):
        result = phase.run(library, {})
        lines.append({"library": library.name, "status": result.status, **result.data})
    return lines


MAP_LINES = phase_07_lines()


def wheel(tmp_path: Path, members: dict[str, bytes], name: str = "pkg.whl") -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        for member, data in members.items():
            zf.writestr(member, data)
    return path


def earlier(path: Path) -> dict[str, Line]:
    """Phases 02, 04 and 05's lines for the wheel at ``path``."""
    records = strings_wheel(path)
    libs = [r["path"] for r in records if ".libs/" in r["path"]]
    return {
        "02-fetch": {"status": "ok", "path": str(path)},
        "04-strings": {
            "status": "ok",
            "wheel": path.name,
            "records": cast(list[object], records),
        },
        "05-libraries": {
            "status": "ok",
            "libraries": [{"path": p, "prefix": prefix(p)} for p in libs],
        },
    }


def run(lines: dict[str, Line], rows: list[MapRow] = ROWS) -> Result:
    phase = static_phase(MAP_LINES, rows)
    assert phase.name == "10-static" and phase.skip_not_ok
    assert phase.schema_version == STATIC_SCHEMA_VERSION == 2
    return phase.run(Package("pkg", "1"), lines)


def candidates(result: Result) -> dict[str, list[Line]]:
    assert result.status == "ok", result.reason
    binaries = cast(list[Line], result.data["binaries"])
    return {str(b["path"]): cast(list[Line], b["candidates"]) for b in binaries}


def test_zlib_banners_give_two_candidates(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE)
    found = candidates(run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext}))))
    [deflate, inflate] = found["pkg/_ext.so"]
    assert deflate == {
        "library": "zlib",
        "version": "1.3.2",
        "kind": "library_string",
        "text": DEFLATE.decode().rstrip("\0"),
        "offset": deflate["offset"],
        "section": ".rodata",
        "pattern": None,
    }
    assert (inflate["library"], inflate["version"]) == ("zlib", "1.3.2")
    assert inflate["text"] == INFLATE.decode().rstrip("\0")
    assert cast(int, deflate["offset"]) < cast(int, inflate["offset"])


def test_disagreeing_zlib_copies_keep_their_own_versions(tmp_path: Path) -> None:
    # Two zlib copies in one binary, as in playwright's node: each banner
    # gives its own version, and the report notes the conflict.
    old = (
        b" deflate 1.3.0.1 Copyright 1995-2023 Jean-loup Gailly and Mark Adler \0"
        b" inflate 1.3.0.1 Copyright 1995-2023 Mark Adler \0"
    )
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + old)
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": ext}))
    result = run(lines)
    found = candidates(result)["pkg/_ext.so"]
    assert [(c["library"], c["version"]) for c in found] == [
        ("zlib", "1.3.2"),
        ("zlib", "1.3.2"),
        ("zlib", "1.3.0.1"),
        ("zlib", "1.3.0.1"),
    ]
    static = {"pkg": {"status": "ok", "reason": None, **result.data}}
    phases = {"04-strings": {"pkg": lines["04-strings"]}}
    text = report([Package("pkg", "1")], phases, static, ROWS, AMBIGUOUS)
    assert text.count("| unconfirmed static candidate; conflict |") == 2
    assert (
        text.count(
            "| unconfirmed static candidate; conflict; ambiguous: may also be 1.3.2.1 |"
        )
        == 2
    )


def test_banners_in_zlib_ng_stay_zlib_ng_with_no_version(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + b" zlib-ng 2.3.3\0")
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": ext}))
    result = run(lines)
    found = candidates(result)["pkg/_ext.so"]
    assert [(c["library"], c["version"]) for c in found] == [
        ("zlib-ng", None),
        ("zlib-ng", None),
        ("zlib-ng", "2.3.3"),
    ]
    static = {"pkg": {"status": "ok", "reason": None, **result.data}}
    phases = {"04-strings": {"pkg": lines["04-strings"]}}
    text = report([Package("pkg", "1")], phases, static, ROWS, {})
    assert "| pkg/_ext.so | zlib-ng | — | library_string |" in text
    assert "conflict" not in text


def test_compiled_against_gives_no_candidate(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\x002.3.3.zlib-ng\0")
    found = candidates(run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext}))))
    assert found == {"pkg/_ext.so": []}


def test_map_recognizers_run_once_under_any_prefix(tmp_path: Path) -> None:
    # OpenBLAS's pattern is listed under two prefixes but runs once, and
    # OpenSSL's runs outside libcrypto.
    ext = build_elf(None, rodata=OPENBLAS + OPENSSL)
    found = candidates(run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext}))))
    [openblas, openssl] = found["pkg/_ext.so"]
    assert (openblas["library"], openblas["version"]) == ("openblas", "0.3.31.dev")
    assert openblas["pattern"] == "OpenBLAS {version} {any}"
    assert (openssl["library"], openssl["version"], openssl["kind"]) == (
        "openssl",
        "3.5.8",
        "library_string",
    )
    assert openssl["pattern"] == "OpenSSL {version} {any}"


def test_libs_files_are_excluded_and_every_binary_listed(tmp_path: Path) -> None:
    members = {
        "pkg/_plain.so": build_elf(None),
        "pkg.libs/libz-1a2b3c4d.so.1": build_elf(None, rodata=b"\0" + DEFLATE),
        "pkg/_ext.so": build_elf(None, rodata=b"\0" + DEFLATE),
    }
    found = candidates(run(earlier(wheel(tmp_path, members))))
    assert list(found) == ["pkg/_plain.so", "pkg/_ext.so"]
    assert found["pkg/_plain.so"] == []
    assert len(found["pkg/_ext.so"]) == 1


def test_changed_missing_or_unparseable_member_is_an_error(tmp_path: Path) -> None:
    good = build_elf(None, rodata=b"\0" + DEFLATE)
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": good}))
    wheel(tmp_path, {"pkg/_ext.so": good + b"\0"})
    result = run(lines)
    assert result.status == "error"
    assert result.reason == "pkg/_ext.so's sha256 differs from phase 04's"

    wheel(tmp_path, {"pkg/other.so": good})
    assert run(lines).reason == "pkg/_ext.so is missing from pkg.whl"

    (tmp_path / "pkg.whl").unlink()
    assert run(lines).reason == f"wheel {tmp_path / 'pkg.whl'} is missing"

    # Section headers that point past the end of the file.
    broken = bytearray(good)
    broken[0x28:0x30] = (10**6).to_bytes(8, "little")
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": bytes(broken)}))
    result = run(lines)
    assert result.status == "error"
    assert str(result.reason).startswith("pkg/_ext.so: pyelftools can't parse it")


def test_report(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + OPENSSL)
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": ext, "pkg/b.so": ext}))
    line = {"status": "ok", "reason": None, **run(lines).data}
    other = earlier(wheel(tmp_path, {"o/_o.so": ext}, "other.whl"))
    other_line = {"status": "ok", "reason": None, **run(other).data}
    packages = [Package("pkg", "1"), Package("other", "2"), Package("gone", "3")]
    phases = {
        "01-resolve": {"gone": {"status": "skipped", "reason": "no_target"}},
        "02-fetch": {},
        "04-strings": {"pkg": lines["04-strings"], "other": other["04-strings"]},
    }
    static = {
        "pkg": line,
        "other": other_line,
        "gone": {"status": "skipped", "reason": "01-resolve"},
    }
    text = report(packages, phases, static, ROWS, AMBIGUOUS)
    assert "- 2 packages scanned in phase 10 of 3; not scanned, by the phase " in text
    assert "stopped: 01-resolve 1\n" in text
    assert "- 3 binaries outside `.libs/`\n" in text
    assert "- 9 candidates: by library, openssl 3, zlib 6; by kind, " in text
    assert "- 3 candidates marked header string risk\n" in text
    assert "- 3 distinct templates\n" in text
    assert (
        "| pkg/_ext.so | openssl | 3.5.8 | library_string | "
        "` OpenSSL 3.5.8 25 Aug 2026 ` | "
        "unconfirmed static candidate; header string risk |"
    ) in text
    assert (
        "| pkg/_ext.so | zlib | 1.3.2 | library_string | "
        f"` {DEFLATE.decode().rstrip(chr(0))} ` | "
        "unconfirmed static candidate; ambiguous: may also be 1.3.2.1 |"
    ) in text
    assert "skipped at 01-resolve: no_target" in text
    # Ranked by wheels, then binaries, then alphabetically.
    templates = text.split("## Templates")[1]
    assert "1. 2 wheels, 3 binaries: `  deflate #.#.# Copyright" in templates
    assert "2. 2 wheels, 3 binaries: `  inflate #.#.#" in templates
    assert "3. 2 wheels, 3 binaries: ` OpenSSL #.#.# # Aug # `" in templates
    assert "in `pkg.whl` `pkg/_ext.so`\n   - pkg, other" in templates


def test_report_counts_a_phase_10_error_and_no_candidates(tmp_path: Path) -> None:
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": build_elf(None)}))
    static = {
        "pkg": {"status": "ok", "reason": None, **run(lines).data},
        "bad": {"status": "error", "reason": "pkg/x.so is missing from b.whl"},
    }
    packages = [Package("pkg", "1"), Package("bad", "1")]
    phases = {"04-strings": {"pkg": lines["04-strings"]}}
    text = report(packages, phases, static, ROWS, {})
    assert "stopped: 10-static 1\n" in text
    assert "- 0 candidates: by library, none; by kind, none\n" in text
    assert "No candidates." in text
    assert "error at 10-static: pkg/x.so is missing from b.whl" in text


# static_lib records (roadmap T.3).


def fingerprints(result: Result) -> dict[str, list[Line]]:
    assert result.status == "ok", result.reason
    binaries = cast(list[Line], result.data["binaries"])
    return {str(b["path"]): cast(list[Line], b["fingerprints"]) for b in binaries}


def summary(record: Line) -> tuple[object, ...]:
    return (
        record["library"],
        record["linkage"],
        record["relation"],
        record["basis"],
        record["version"],
        record["conflict"],
        len(cast(list[Line], record["evidence"])),
    )


def test_pattern_row_gives_a_static_lib_record(tmp_path: Path) -> None:
    # bzip2's row is pattern; OpenSSL's isn't, so it stays a candidate.
    ext = build_elf(None, rodata=BZIP2 + OPENSSL)
    result = run(earlier(wheel(tmp_path, {"pkg/libarrow.so.2600": ext})))
    assert len(candidates(result)["pkg/libarrow.so.2600"]) == 2
    [record] = fingerprints(result)["pkg/libarrow.so.2600"]
    [evidence] = cast(list[Line], record["evidence"])
    assert {k: v for k, v in record.items() if k != "evidence"} == {
        "schema_version": 4,
        "wheel": "pkg.whl",
        "path": "pkg/libarrow.so.2600",
        "sha256": hashlib.sha256(ext).hexdigest(),
        "library": "bzip2",
        "relation": "contains",
        "linkage": "static_lib",
        "basis": "library_string",
        "version": "1.0.8",
        "conflict": False,
    }
    assert evidence == {
        "kind": "library_string",
        "text": "1.0.8, 13-Jul-2019",
        "offset": ext.index(BZIP2) + 1,
        "section": ".rodata",
    }


def test_zlib_detector_gives_one_record_per_binary(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE)
    result = run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext})))
    assert [summary(r) for r in fingerprints(result)["pkg/_ext.so"]] == [
        ("zlib", "static_lib", "contains", "library_string", "1.3.2", False, 2)
    ]


def test_two_zlib_copies_give_one_conflicting_record(tmp_path: Path) -> None:
    # playwright's node: the record has no version, and the candidates keep
    # both.
    old = (
        b" deflate 1.3.0.1 Copyright 1995-2023 Jean-loup Gailly and Mark Adler \0"
        b" inflate 1.3.0.1 Copyright 1995-2023 Mark Adler \0"
    )
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + old)
    result = run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext})))
    assert [summary(r) for r in fingerprints(result)["pkg/_ext.so"]] == [
        ("zlib", "static_lib", "contains", "library_string", None, True, 4)
    ]
    assert len(candidates(result)["pkg/_ext.so"]) == 4


def test_derivative_rule_applies_to_static_records(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + b" zlib-ng 2.3.3\0")
    result = run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext})))
    assert [summary(r) for r in fingerprints(result)["pkg/_ext.so"]] == [
        ("zlib-ng", "static_lib", "contains", "library_string", "2.3.3", False, 3)
    ]


def test_compiled_against_gives_no_record(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\x002.3.3.zlib-ng\0")
    result = run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext})))
    assert fingerprints(result) == {"pkg/_ext.so": []}


def test_no_records_without_static_lib_detection(tmp_path: Path) -> None:
    # With no detector row for zlib and no pattern row, only candidates.
    rows = [replace(r, static_lib_detection="") for r in ROWS if r.prefix]
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + BZIP2)
    result = run(earlier(wheel(tmp_path, {"pkg/_ext.so": ext})), rows)
    assert len(candidates(result)["pkg/_ext.so"]) == 3
    assert fingerprints(result) == {"pkg/_ext.so": []}


def test_libs_files_get_no_static_records(tmp_path: Path) -> None:
    members = {
        "pkg.libs/libz-1a2b3c4d.so.1": build_elf(None, rodata=b"\0" + DEFLATE),
        "pkg/_ext.so": build_elf(None, rodata=b"\0" + DEFLATE),
    }
    assert list(fingerprints(run(earlier(wheel(tmp_path, members))))) == ["pkg/_ext.so"]


def test_report_counts_candidates_that_became_records(tmp_path: Path) -> None:
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE + OPENSSL + BZIP2)
    lines = earlier(wheel(tmp_path, {"pkg/_ext.so": ext}))
    static = {"pkg": {"status": "ok", "reason": None, **run(lines).data}}
    phases = {"04-strings": {"pkg": lines["04-strings"]}}
    text = report([Package("pkg", "1")], phases, static, ROWS, {})
    assert "- 4 candidates: by library, bzip2 1, openssl 1, zlib 2;" in text
    assert "- 3 candidates that became static_lib records\n" in text
    # A line from before T.3 has no records.
    del cast(list[Line], static["pkg"]["binaries"])[0]["fingerprints"]
    text = report([Package("pkg", "1")], phases, static, ROWS, {})
    assert "- 0 candidates that became static_lib records\n" in text


def test_report_counts_binaries_by_file_name(tmp_path: Path) -> None:
    plain = build_elf(None)
    members = {
        "pkg/lib/libtorch_cpu.so": plain,
        "pkg/lib/libgomp.so.1": plain,
        "pkg/_C.cpython-312-x86_64-linux-gnu.so": plain,
        "pkg/_rust.abi3.so": plain,
        "pkg/lib_ext.cpython-312-x86_64-linux-gnu.so": plain,
        "pkg/bin/protoc": plain,
        "pkg/_pywrap.so": plain,
        "pkg.libs/libz-1a2b3c4d.so.1": plain,
    }
    lines = earlier(wheel(tmp_path, members))
    static = {"pkg": {"status": "ok", "reason": None, **run(lines).data}}
    phases = {"04-strings": {"pkg": lines["04-strings"]}}
    text = report([Package("pkg", "1")], phases, static, ROWS, AMBIGUOUS)
    assert "`pkg.whl`: 7 binaries outside `.libs/`\n" in text
    assert (
        "By file name: 2 shared libraries, 3 extension modules, 2 other binaries\n"
    ) in text
