"""The fingerprint report on hand-built phase 05, 07 and 08 lines and map rows."""

from pypiscan.fingerprint_report import INTRO, report
from pypiscan.library_map import MapRow
from pypiscan.package_list import Package
from pypiscan.scan import Line


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
    row("liba", "alpha", "library_string"),
    row("libb", "beta", "build_path"),
    row("libc", "gamma", "bare_version"),
    row("libd", "delta", "library_string"),
    row("libe", "eps", "library_string"),
    row("libf", "phi", "bare_version"),
    row("libg", "webp"),
    row("libh", "eta", "library_string"),
    row("libgfortran", "skip"),
    row("libmulti", "free"),
    row("libmulti", "bz", "library_string"),
    row("libk5", "krb"),
    row("libkrb", "krb", "library_string"),
]


def ok_07(library: str, *prefixes: str) -> Line:
    return {
        "library": library,
        "status": "ok",
        "reason": None,
        "recognizers": [
            {"prefix": p, "kind": "library_string", "pattern": "x {version}"}
            for p in prefixes
        ],
    }


def skipped_07(library: str) -> Line:
    return {"library": library, "status": "skipped", "reason": "no_recognizer"}


PHASE_07: dict[str, Line] = {
    str(line["library"]): line
    for line in [
        ok_07("alpha", "liba"),
        ok_07("beta", "libb"),
        ok_07("gamma", "libc"),
        ok_07("delta", "libd"),
        ok_07("eps", "libe"),
        ok_07("phi", "libf"),
        skipped_07("webp"),
        ok_07("eta", "libh"),
        skipped_07("free"),
        ok_07("bz", "libmulti"),
        ok_07("krb", "libkrb"),
    ]
}


def path(prefix: str) -> str:
    return f"a.libs/{prefix}-1a2b3c4d.so.1"


def record(
    prefix: str,
    library: str,
    version: str | None,
    basis: str,
    conflict: bool = False,
) -> Line:
    return {
        "path": path(prefix),
        "library": library,
        "version": version,
        "basis": basis,
        "conflict": conflict,
    }


PREFIXES = [
    "liba", "libb", "libc", "libd", "libe", "libf", "libg", "libh",
    "libgfortran", "libmulti", "libk5",
]  # fmt: skip
PHASE_05: dict[str, Line] = {
    "a": {"name": "a", "status": "ok", "libraries": [
        {"path": path(p), "prefix": p} for p in PREFIXES
    ]},
    "b": {"name": "b", "status": "skipped", "reason": "02-fetch"},
    "c": {"name": "c", "status": "error", "reason": "bad zip"},
    "d": {"name": "d", "status": "ok", "libraries": []},
}  # fmt: skip
PHASE_08: dict[str, Line] = {
    "a": {
        "name": "a",
        "status": "ok",
        "reason": None,
        "wheel": "a-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        "records": [
            record("liba", "alpha", "1.2.3", "library_string"),
            record("libb", "beta", "2.5.4", "build_path"),
            record("libc", "gamma", "5.8.3", "bare_version"),
            record("libd", "delta", None, "library_string", conflict=True),
            record("libe", "eps", "1|0", "library_string", conflict=True),
            record("libf", "phi", "3.0.0", "bare_version", conflict=True),
            record("libmulti", "bz", "1.0.8", "library_string"),
        ],
    },
    "b": {"name": "b", "status": "skipped", "reason": "02-fetch"},
    "c": {"name": "c", "status": "skipped", "reason": "03-inspect"},
    "d": {
        "name": "d",
        "status": "ok",
        "reason": None,
        "wheel": "d-2.0-py3-none-manylinux_2_28_x86_64.whl",
        "records": [],
    },
}
PACKAGES = [Package("a", "1.0"), Package("b", "2.0"), Package("c", "3.0")]
PACKAGES.append(Package("d", "2.0"))

EXPECTED = (
    INTRO
    + """
## a 1.0

`a-1.0-cp312-cp312-manylinux_2_28_x86_64.whl`

| file | library | version | basis | note |
|---|---|---|---|---|
| liba-1a2b3c4d.so.1 | alpha | 1.2.3 | library_string |  |
| libb-1a2b3c4d.so.1 | beta | 2.5.4 | build_path |  |
| libc-1a2b3c4d.so.1 | gamma | 5.8.3 | bare_version | needs another source |
| libd-1a2b3c4d.so.1 | delta | — | — | matches disagree |
| libe-1a2b3c4d.so.1 | eps | 1\\|0 | library_string | conflict |
| libf-1a2b3c4d.so.1 | phi | 3.0.0 | bare_version | conflict; needs another source |
| libg-1a2b3c4d.so.1 | webp | — | — | no recognizer |
| libh-1a2b3c4d.so.1 | eta | — | — | not detected |
| libgfortran-1a2b3c4d.so.1 | skip | — | — | not tracked |
| libmulti-1a2b3c4d.so.1 | free | — | — | no recognizer |
| libmulti-1a2b3c4d.so.1 | bz | 1.0.8 | library_string |  |
| libk5-1a2b3c4d.so.1 | krb | — | — | no recognizer |

## b 2.0

skipped: 02-fetch

## c 3.0

skipped: 03-inspect

## d 2.0

`d-2.0-py3-none-manylinux_2_28_x86_64.whl`

No .libs/ files.
"""
)


def test_report_covers_every_case() -> None:
    assert report(PACKAGES, PHASE_05, PHASE_07, PHASE_08, ROWS, {}) == EXPECTED


def test_intro_is_verbatim() -> None:
    assert INTRO == (
        "Every version below is a signal for deciding whether a CVE might be worth\n"
        "investigating, not a conclusion. Its basis says which signal it rests on;\n"
        'see "How versions are identified" in the README.\n'
    )


def test_error_line_shows_status_and_reason() -> None:
    error: Line = {"name": "c", "status": "error", "reason": "bad zip"}
    text = report([Package("c", "3.0")], {}, {}, {"c": error}, [], {})
    assert text == INTRO + "\n## c 3.0\n\nerror: bad zip\n"


def test_a_version_never_shows_without_its_basis() -> None:
    for line in EXPECTED.splitlines():
        if line.startswith("| ") and not line.startswith("| file"):
            cells = [c.strip() for c in line.strip("|").split(" | ")]
            assert (cells[2] == "—") == (cells[3] == "—"), line


AMBIGUOUS = {"lcms": {"2.19.0": ["2.19.1"]}, "hb": {"1.7.6": ["1.7.7", "1.8.0"]}}
VF = "version_function_machine_code"


def test_ambiguous_versions_are_noted() -> None:
    rows = [
        row("liblcms", "lcms", VF),
        row("libhb", "hb", "bare_version"),
        row("libnull", "lcms", VF),
        row("libother", "other", VF),
    ]
    prefixes = ["liblcms", "libhb", "libnull", "libother"]
    phase_05: dict[str, Line] = {
        "a": {
            "status": "ok",
            "libraries": [{"path": path(p), "prefix": p} for p in prefixes],
        }
    }
    phase_07: dict[str, Line] = {
        "lcms": ok_07("lcms", "liblcms", "libnull"),
        "hb": ok_07("hb", "libhb"),
        "other": ok_07("other", "libother"),
    }
    records = [
        record("liblcms", "lcms", "2.19.0", VF),
        record("libhb", "hb", "1.7.6", "bare_version"),
        # A null version is never ambiguous, nor another library's version.
        record("libnull", "lcms", None, VF, conflict=True),
        record("libother", "other", "2.19.0", VF),
    ]
    phase_08: dict[str, Line] = {
        "a": {"status": "ok", "wheel": "a.whl", "records": records}
    }
    text = report([Package("a", "1.0")], phase_05, phase_07, phase_08, rows, AMBIGUOUS)
    table = [line for line in text.splitlines() if line.startswith("| lib")]
    assert table == [
        f"| liblcms-1a2b3c4d.so.1 | lcms | 2.19.0 | {VF} | "
        "ambiguous: may also be 2.19.1 |",
        "| libhb-1a2b3c4d.so.1 | hb | 1.7.6 | bare_version | "
        "needs another source; ambiguous: may also be 1.7.7 or 1.8.0 |",
        "| libnull-1a2b3c4d.so.1 | lcms | — | — | matches disagree |",
        f"| libother-1a2b3c4d.so.1 | other | 2.19.0 | {VF} |  |",
    ]
