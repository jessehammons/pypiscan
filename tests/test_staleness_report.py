"""The staleness report on hand-built phase 01, 05, 06 and 08 lines and map
rows."""

from datetime import date
from typing import cast

from pypiscan.library_map import MapRow
from pypiscan.package_list import Package
from pypiscan.scan import Line
from pypiscan.staleness_report import INTRO, report, staleness, upload_day


def row(prefix: str, library: str, kind: str = "") -> MapRow:
    pattern = "{version}" if kind == "bare_version" else "x {version}" if kind else ""
    return MapRow(
        prefix=prefix,
        library=library,
        repo="" if library == "skip" else "https://github.com/x/y",
        tags="" if library == "skip" else "v{version}",
        kind=kind,
        pattern=pattern,
        identity_file="f.c" if kind else "",
        identity="",
        cpe="",
        osv="",
    )


ROWS = [
    row("libcur", "cur", "library_string"),
    row("libold", "old", "build_path"),
    row("libamb", "lcms", "version_function_machine_code"),
    row("libhint", "hint", "bare_version"),
    row("libgh", "remote", "library_string"),
    row("liberr", "broken", "library_string"),
    row("libblas", "blas", "library_string"),
    row("libnone", "nover", "library_string"),
    row("libfree", "free"),
    row("libgfortran", "skip"),
]
AMBIGUOUS = {"lcms": {"2.19.0": ["2.19.1"]}}


def ok_06(library: str, *tags: tuple[str, str]) -> Line:
    return {
        "schema_version": 2,
        "library": library,
        "status": "ok",
        "reason": None,
        "tags": [{"tag": f"v{v}", "version": v, "date": d} for v, d in tags],
    }


PHASE_06: dict[str, Line] = {
    str(line["library"]): line
    for line in [
        # A release dated after the upload day, and a pre-release before it,
        # don't count.
        ok_06("cur", ("1.2.0", "2025-01-01"), ("1.3.0rc1", "2025-03-01"),
              ("1.3.0", "2025-06-15")),
        # Versions order as integers: 2.0.10 is newer than 2.0.9. A release
        # on the upload day counts.
        ok_06("old", ("2.0.9", "2024-01-01"), ("2.0.10", "2024-02-01"),
              ("2.1.0", "2025-06-14"), ("3.0.0", "2025-07-01")),
        ok_06("lcms", ("2.19.0", "2025-01-01"), ("2.19.1", "2025-02-01"),
              ("2.20", "2025-03-01")),
        ok_06("hint", ("1.0.0", "2025-01-01")),
        {"schema_version": 2, "library": "remote", "status": "skipped",
         "reason": "not_github"},
        {"schema_version": 2, "library": "broken", "status": "error",
         "reason": "git fetch failed: gone"},
        ok_06("blas", ("0.3.34", "2025-01-01"), ("0.3.35", "2025-02-01")),
        ok_06("nover", ("1.0", "2025-01-01")),
        ok_06("free", ("2.14.3", "2025-01-01")),
    ]
}  # fmt: skip


def path(prefix: str) -> str:
    return f"a.libs/{prefix}-1a2b3c4d.so.1"


def record(prefix: str, library: str, version: str | None, basis: str) -> Line:
    return {
        "path": path(prefix),
        "library": library,
        "relation": "contains",
        "version": version,
        "basis": basis,
        "conflict": False,
    }


PREFIXES = [
    "libcur", "libold", "libamb", "libhint", "libgh", "liberr", "libblas",
    "libnone", "libfree", "libgfortran",
]  # fmt: skip
PACKAGES = [Package("pkg", "1.0"), Package("gone", "2.0")]
PART_1: dict[str, dict[str, Line]] = {
    # 01:00 at +03:00 is the day before in UTC.
    "01-resolve": {
        "pkg": {"status": "ok", "upload_time": "2025-06-15T01:00:00+03:00"},
        "gone": {"status": "ok", "upload_time": "2025-06-15T01:00:00Z"},
    },
    "02-fetch": {
        "pkg": {"status": "ok", "reason": None},
        "gone": {"status": "skipped", "reason": "too_large"},
    },
    "05-libraries": {
        "pkg": {
            "status": "ok",
            "libraries": [{"path": path(p), "prefix": p} for p in PREFIXES],
        },
        "gone": {"status": "skipped", "reason": "02-fetch"},
    },
}
PHASE_08: dict[str, Line] = {
    "pkg": {
        "status": "ok",
        "reason": None,
        "wheel": "pkg-1.0.whl",
        "records": [
            record("libcur", "cur", "1.2.0", "library_string"),
            record("libold", "old", "2.0.9", "build_path"),
            record("libamb", "lcms", "2.19.0", "version_function_machine_code"),
            record("libhint", "hint", "1.0.0", "bare_version"),
            record("libgh", "remote", "1.0", "library_string"),
            record("liberr", "broken", "1.0", "library_string"),
            record("libblas", "blas", "0.3.34.106.0", "library_string"),
        ],
    },
    "gone": {"status": "skipped", "reason": "02-fetch"},
}


def text(phase_06: dict[str, Line] = PHASE_06) -> str:
    return report(PACKAGES, PART_1, phase_06, PHASE_08, ROWS, AMBIGUOUS)


def table_row(prefix: str, library: str, *cells: str) -> str:
    return f"| {prefix}-1a2b3c4d.so.1 | {library} | " + " | ".join(cells) + " |"


def test_report_covers_every_case() -> None:
    out = text()
    assert out.startswith(INTRO)
    assert "## pkg 1.0\n\n`pkg-1.0.whl`, uploaded 2025-06-14\n" in out
    lib = "version_function_machine_code"
    expected = [
        table_row("libcur", "cur", "1.2.0", "library_string", "",
                  "1.2.0 (2025-01-01)", "0", "0"),
        # From 2.0.10's date, 2024-02-01, to 2025-06-14.
        table_row("libold", "old", "2.0.9", "build_path", "",
                  "2.1.0 (2025-06-14)", "2", "499"),
        table_row("libamb", "lcms", "2.19.0", lib,
                  "ambiguous: may also be 2.19.1; read as 2.19.1",
                  "2.20 (2025-03-01)", "1", "105"),
        table_row("libhint", "hint", "1.0.0", "bare_version",
                  "hint; needs another source", "1.0.0 (2025-01-01)", "0", "0"),
        table_row("libgh", "remote", "1.0", "library_string", "",
                  "not compared: not_github", "—", "—"),
        table_row("liberr", "broken", "1.0", "library_string", "",
                  "not compared: phase 06 error", "—", "—"),
        table_row("libblas", "blas", "0.3.34.106.0", "library_string", "",
                  "not compared: no release tag for the version", "—", "—"),
        table_row("libnone", "nover", "—", "—", "not detected",
                  "not compared: not detected", "—", "—"),
        table_row("libfree", "free", "—", "—", "no recognizer",
                  "not compared: no recognizer", "—", "—"),
        table_row("libgfortran", "skip", "—", "—", "not tracked",
                  "skipped", "—", "—"),
    ]  # fmt: skip
    for each in expected:
        assert each in out
    assert "## gone 2.0\n\nskipped at 02-fetch: too_large\n" in out


def test_report_starts_with_counts() -> None:
    counts = (
        "## Counts\n\n"
        "- Compared: current 2 (bare_version 1, library_string 1); behind 2 "
        "(build_path 1, version_function_machine_code 1). By basis.\n"
        "- Not compared: 5 (no recognizer 1, no release tag for the version 1, "
        "not detected 1, not_github 1, phase 06 error 1). By reason.\n"
        "- Files whose prefix is marked skip: 1.\n"
        "- Packages not scanned: 1.\n"
    )
    assert text().startswith(f"{INTRO}\n{counts}")


def test_old_phase_06_lines_are_never_compared() -> None:
    """An episode from before tag dates says to rerun from phase 06, and
    treats none of the libraries it covers as current."""
    # A schema 1 line, as phase 06 wrote it before tag dates: no "date".
    cur: Line = {
        "schema_version": 1,
        "library": "cur",
        "status": "ok",
        "reason": None,
        "tags": [{"tag": "v1.2.0", "version": "1.2.0"}],
    }
    old = {**PHASE_06, "cur": cur}
    out = text(old)
    rerun = "- Phase 06's lines predate tag dates, so their libraries aren't "
    assert f"## Counts\n\n{rerun}compared: rerun from phase 06.\n" in out
    assert "- Compared: current 1 (bare_version 1); behind 2" in out
    assert table_row("libcur", "cur", "1.2.0", "library_string", "",
                     "not compared: rerun from phase 06", "—", "—") in out  # fmt: skip
    assert "predate" not in text()


def test_ambiguous_version_without_its_own_tag() -> None:
    """lcms2's encoding gives 2.19.0, but its tags spell 2.19: the release it
    may also be, 2.19.1, is the one compared."""
    upstream = ok_06("lcms", ("2.19", "2025-01-01"), ("2.19.1", "2025-02-01"))
    result = staleness("2.19.0", ["2.19.1"], upstream, date(2025, 6, 1))
    assert result == ("read as 2.19.1", "2.19.1 (2025-02-01)", "0", "0")
    assert staleness("2.19.0", [], upstream, date(2025, 6, 1)) == (
        "no release tag for the version"
    )


def test_upload_day_is_in_utc() -> None:
    assert upload_day({"upload_time": "2025-06-14T22:30:00-03:00"}) == date(2025, 6, 15)
    assert upload_day({"upload_time": "2025-06-14T22:30:00.123456Z"}) == date(
        2025, 6, 14
    )


def test_a_tag_spelled_twice_keeps_its_earliest_date() -> None:
    upstream = ok_06("x", ("1.1", "2025-03-01"), ("1.0", "2025-01-01"))
    again = {"tag": "x-1.1", "version": "1.1", "date": "2025-02-01"}
    upstream["tags"] = [*cast(list[Line], upstream["tags"]), again]
    assert staleness("1.0", [], upstream, date(2025, 6, 1)) == (
        "",
        "1.1 (2025-02-01)",
        "1",
        "120",
    )


def test_a_later_spelling_of_a_tag_keeps_the_earlier_date() -> None:
    upstream = ok_06("x", ("1.1", "2025-02-01"), ("1.0", "2025-01-01"))
    again = {"tag": "x-1.1", "version": "1.1", "date": "2025-03-01"}
    upstream["tags"] = [*cast(list[Line], upstream["tags"]), again]
    result = staleness("1.0", [], upstream, date(2025, 6, 1))
    assert result == ("", "1.1 (2025-02-01)", "1", "120")


def test_a_package_without_libs_and_a_library_missing_from_phase_06() -> None:
    part_1 = {
        "01-resolve": {"pkg": PART_1["01-resolve"]["pkg"]},
        "05-libraries": {
            "pkg": {"status": "ok", "libraries": [{"path": path("libcur"),
                                                   "prefix": "libcur"}]},
            "bare": {"status": "ok", "libraries": []},
        },
    }  # fmt: skip
    part_1["01-resolve"]["bare"] = PART_1["01-resolve"]["pkg"]
    phase_08 = {
        "pkg": PHASE_08["pkg"],
        "bare": {"status": "ok", "wheel": "bare.whl", "records": []},
    }
    packages = [Package("pkg", "1.0"), Package("bare", "1.0")]
    out = report(packages, part_1, {}, phase_08, ROWS, {})
    assert "not compared: not in phase 06" in out
    assert "## bare 1.0\n\n`bare.whl`, uploaded 2025-06-14\n\nNo .libs/ files." in out
