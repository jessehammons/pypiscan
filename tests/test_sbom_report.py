"""The SBOM report on hand-built phase 01 to 09 lines, SBOM records and map
rows."""

import hashlib
import re
from collections import Counter

import pytest

from pypiscan.package_list import Package
from pypiscan.sbom_report import (
    INTRO,
    LIBRARY_DIRS,
    compare,
    file_components,
    file_digest,
    original_name,
    report,
    tie,
    upstream_version,
)
from pypiscan.scan import Line
from test_fingerprint_report import by_phase, ok_until_05, row, stopped


def digest(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()


def component(
    name: str, version: str | None, purl: str, path: str | None = None
) -> Line:
    """A component whose bom-ref names ``path`` the way auditwheel's does."""
    ref = purl if path is None else f"{purl}#{digest(path)}"
    return {
        "bom-ref": ref,
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "scope": None,
        "parent": None,
    }


def rpm(name: str, version: str) -> str:
    return f"pkg:rpm/centos/{name}@{version}?arch=x86_64"


def sbom(
    path: str,
    components: list[Line],
    tool: str = "auditwheel",
    error: str | None = None,
) -> Line:
    read = error is None
    return {
        "path": path,
        "format": "cyclonedx-json" if read else None,
        "tools": [{"name": tool, "version": "6.8.2"}] if read else None,
        "components": components if read else None,
        "error": error,
    }


# original_name and the paths a file may come from.


@pytest.mark.parametrize(
    ("file_name", "original"),
    [
        ("libkrb5-fcafa220.so.3.3", "libkrb5.so.3.3"),
        ("libfoo-aaaaaaaa-bbbbbbbb.so.1", "libfoo-aaaaaaaa.so.1"),
        ("libfoo.so.1", None),
        ("libfoo-AAAAAAAA.so", None),
        ("libfoo-aaaaaaaa", None),
        ("libfoo-aaaaaaaa1.so", None),
        ("libfoo-aaaaaaa.so", None),
    ],
)
def test_original_name(file_name: str, original: str | None) -> None:
    assert original_name(file_name) == original


# Tying.

KRB5 = rpm("krb5-libs", "1.15.1-55.el7_9")
PATHS = ["a.libs/libkrb5-fcafa220.so.3.3", "a.libs/libz-12345678.so.1"]


@pytest.mark.parametrize("directory", LIBRARY_DIRS)
def test_a_match_under_each_directory(directory: str) -> None:
    krb5 = component("krb5-libs", "1", KRB5, f"{directory}libkrb5.so.3.3")
    tied, untied = tie([krb5], PATHS)
    assert tied == {PATHS[0]: [krb5], PATHS[1]: []}
    assert untied == []


def test_no_match_is_untied() -> None:
    krb5 = component("krb5-libs", "1", KRB5, "/opt/lib/libkrb5.so.3.3")
    assert tie([krb5], PATHS) == ({PATHS[0]: [], PATHS[1]: []}, [krb5])


def test_a_component_matching_two_files_is_untied() -> None:
    paths = ["a.libs/libz-12345678.so.1", "a.libs/libz-87654321.so.1"]
    libz = component("zlib", "1", rpm("zlib", "1.2.7-21"), "/lib64/libz.so.1")
    assert tie([libz], paths) == ({p: [] for p in paths}, [libz])


def test_two_components_tied_to_one_file_are_kept() -> None:
    one = component("krb5-libs", "1", KRB5, "/lib64/libkrb5.so.3.3")
    two = component("other", "1", rpm("other", "1-1"), "/usr/lib/libkrb5.so.3.3")
    tied, untied = tie([one, two], PATHS)
    assert (tied[PATHS[0]], untied) == ([one, two], [])
    outcome = compare([one, two], ["krb5"], None, True, {})
    assert outcome == ("not compared", "several components")


def test_a_bom_ref_names_a_file_only_with_its_own_purl() -> None:
    path = "/lib64/libkrb5.so.3.3"
    good = component("krb5-libs", "1", KRB5, path)
    assert file_digest(good) == digest(path)
    other_purl = {**good, "bom-ref": f"{rpm('krb5', '1-1')}#{digest(path)}"}
    upper = {**good, "bom-ref": f"{KRB5}#{digest(path).upper()}"}
    short = {**good, "bom-ref": f"{KRB5}#{digest(path)[:63]}"}
    no_purl = {**good, "purl": None}
    for bad in (other_purl, upper, short, no_purl):
        assert file_digest(bad) is None
        assert file_components([sbom("s.json", [bad])]) == []


def test_only_auditwheels_files_name_files() -> None:
    krb5 = component("krb5-libs", "1", KRB5, "/lib64/libkrb5.so.3.3")
    wheel = component("a", "1.0", "pkg:pypi/a@1.0")
    assert file_components([sbom("s.json", [wheel, krb5])]) == [krb5]
    assert file_components([sbom("s.json", [krb5], tool="cargo-cyclonedx")]) == []
    assert file_components([sbom("s.json", [krb5], tool="auditwheel2")]) == []
    assert file_components([sbom("s.json", [], error="not_json")]) == []
    spdx = {**sbom("s.json", [krb5]), "format": "spdx-json"}
    assert file_components([spdx]) == []


# upstream_version.


@pytest.mark.parametrize(
    ("purl", "version", "upstream"),
    [
        ("pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9", "1.15.1-55.el7_9", "1.15.1"),
        ("pkg:rpm/x/y", "2", "2"),
        ("pkg:deb/debian/x", "1:2.3-4ubuntu1", "2.3"),
        ("pkg:deb/debian/x", "2.3", "2.3"),
        ("pkg:deb/debian/x", "1.2-3-4", "1.2-3"),
        ("pkg:deb/debian/x", "1:2.3", "2.3"),
        ("pkg:rpm/x/y", "1:2.3-4", "1:2.3"),
        ("pkg:apk/alpine/x", "1.2.4-r2", "1.2.4"),
        ("pkg:pypi/x@1.0", "1.0-1", None),
        ("pkg:generic/freetype2", "2.14.3", None),
        ("pkg:rpm/x/y", None, None),
        (None, "1.0", None),
    ],
)
def test_upstream_version(
    purl: str | None, version: str | None, upstream: str | None
) -> None:
    assert upstream_version(purl, version) == upstream


# Comparing.


def fingerprint(version: str | None, basis: str = "library_string") -> Line:
    return {"version": version, "basis": basis, "conflict": False}


SASL = [component("cyrus-sasl-lib", "2.1.26-24.el7_9", rpm("c", "2.1.26-24"), "/x")]
AMBIGUOUS = {"lcms2": {"2.19.0": ["2.19.1"]}}


@pytest.mark.parametrize(
    ("libraries", "record", "recognized", "outcome"),
    [
        (["sasl"], fingerprint("2.1.26", "bare_version"), True, "agrees"),
        (["sasl"], fingerprint("2.1.26.0"), True, "differs"),
        (["lcms2"], fingerprint("2.19.0"), True, "differs"),
        (["sasl", "other"], fingerprint("2.1.26"), True, "several libraries"),
        ([], None, False, "not mapped"),
        (["skip"], None, False, "not tracked"),
        (["sasl"], None, False, "no recognizer"),
        (["sasl"], None, True, "not detected"),
        (["sasl"], fingerprint(None), True, "matches disagree"),
    ],
)
def test_compare(
    libraries: list[str], record: Line | None, recognized: bool, outcome: str
) -> None:
    result = compare(SASL, libraries, record, recognized, AMBIGUOUS)
    if outcome in ("agrees", "differs"):
        assert result == (outcome, record and record["basis"])
    else:
        assert result == ("not compared", outcome)


def test_agreement_through_an_ambiguous_release() -> None:
    lcms = [component("lcms2", "2.19.1-1.el8", rpm("lcms2", "2.19.1-1"), "/x")]
    record = fingerprint("2.19.0", "version_function_machine_code")
    result = compare(lcms, ["lcms2"], record, True, AMBIGUOUS)
    assert result == ("agrees", "version_function_machine_code")
    assert compare(lcms, ["lcms2"], record, True, {})[0] == "differs"


def test_no_distribution_version() -> None:
    for purl, version in [("pkg:generic/sasl", "2.1.26"), (rpm("c", "2"), None)]:
        sasl = [component("cyrus-sasl", version, purl, "/x")]
        result = compare(sasl, ["sasl"], fingerprint("2.1.26"), True, {})
        assert result == ("not compared", "no distribution version")


# The report.

ROWS = [
    row("libkrb5", "krb5", "library_string"),
    row("libgssapi_krb5", "krb5"),
    row("libsasl2", "cyrus-sasl", "bare_version"),
    row("liblcms2", "lcms2", "library_string"),
    row("libpq", "libpq", "library_string"),
    row("libXau", "skip"),
    row("libmulti", "free"),
    row("libmulti", "bz", "library_string"),
    row("libfreetype", "freetype"),
    row("libgfortran", "skip"),
]


def libs(package: str, *names: str) -> list[dict[str, str]]:
    return [{"path": f"{package}.libs/{n}", "prefix": n.split("-")[0]} for n in names]


A_FILES = libs(
    "a",
    "libkrb5-fcafa220.so.3.3",
    "libsasl2-aaaaaaaa.so.3.0.0",
    "libgssapi_krb5-bbbbbbbb.so.2.2",
    "libXau-cccccccc.so.6.0.0",
    "libpq-dddddddd.so.5.17",
    "liblcms2-eeeeeeee.so.2",
    "libmulti-ffffffff.so.1",
)
A_COMPONENTS = [
    component("a", "1.0", "pkg:pypi/a@1.0"),
    component("krb5-libs", "1.15.1-55.el7_9", KRB5, "/lib64/libkrb5.so.3.3"),
    component(
        "cyrus-sasl-lib",
        "2.1.26.0-24.el7_9",
        rpm("cyrus-sasl-lib", "2.1.26.0-24.el7_9"),
        "/usr/lib64/libsasl2.so.3.0.0",
    ),
    component("krb5-libs", "1.15.1-55.el7_9", KRB5, "/lib64/libgssapi_krb5.so.2.2"),
    component(
        "libXau", "1.0.9-3.el8", rpm("libXau", "1.0.9-3.el8"), "/lib64/libXau.so.6.0.0"
    ),
    component("lcms2", "2.19.1-1.el8", rpm("lcms2", "2.19.1-1"), "/lib/liblcms2.so.2"),
    component(
        "bzip2-libs", "1.0.8-1", rpm("bzip2-libs", "1.0.8-1"), "/lib64/libmulti.so.1"
    ),
    component("libfoo", "1.0-1", rpm("libfoo", "1.0-1"), "/opt/lib/libfoo.so.1"),
]


def contains(
    package: str, name: str, library: str, version: str | None, basis: str
) -> Line:
    return {
        "path": f"{package}.libs/{name}",
        "library": library,
        "relation": "contains",
        "version": version,
        "basis": basis,
        "conflict": False,
    }


def ok(name: str, wheel: str, records: list[Line]) -> Line:
    return {
        "name": name,
        "status": "ok",
        "reason": None,
        "wheel": wheel,
        "records": records,
    }


def skipped(name: str, reason: str) -> Line:
    return {"name": name, "status": "skipped", "reason": reason}


BY_PACKAGE = {
    "a": ok_until_05("a", A_FILES),
    "p": ok_until_05("p", libs("p", "libfreetype-11111111.so.6")),
    "n": ok_until_05("n", libs("n", "libgfortran-22222222.so.5")),
    "q": ok_until_05("q", []),
    "b": stopped("b", "02-fetch", "skipped", "too_large"),
    "e": ok_until_05("e", libs("e", "libz-33333333.so.1")),
}
PHASE_08 = {
    "a": ok(
        "a",
        "a.whl",
        [
            contains(
                "a", "libkrb5-fcafa220.so.3.3", "krb5", "1.15.1", "library_string"
            ),
            contains(
                "a",
                "libsasl2-aaaaaaaa.so.3.0.0",
                "cyrus-sasl",
                "2.1.26",
                "bare_version",
            ),
            contains("a", "libpq-dddddddd.so.5.17", "libpq", "17.11", "library_string"),
            contains(
                "a", "liblcms2-eeeeeeee.so.2", "lcms2", "2.19.0", "library_string"
            ),
            contains("a", "libmulti-ffffffff.so.1", "bz", "1.0.8", "library_string"),
        ],
    ),
    "p": ok("p", "p.whl", []),
    "n": ok("n", "n.whl", []),
    "q": ok("q", "q.whl", []),
    "b": skipped("b", "02-fetch"),
    "e": {"name": "e", "status": "error", "reason": "bad ELF"},
}
FREETYPE = component(
    "freetype", "2.14.3", rpm("freetype", "2.14.3-1"), "/lib64/libfreetype.so.6"
)
PHASE_09 = {
    "a": ok(
        "a", "a.whl", [sbom("a-1.0.dist-info/sboms/auditwheel.cdx.json", A_COMPONENTS)]
    ),
    "p": ok(
        "p",
        "p.whl",
        [
            sbom(
                "p-1.0.dist-info/sboms/p.cdx.json", [FREETYPE], tool="generate-sbom.py"
            ),
            sbom("p-1.0.dist-info/sboms/bad.json", [], error="not_json"),
            {**sbom("p-1.0.dist-info/sboms/x.spdx.json", []), "format": "spdx-json"},
        ],
    ),
    "n": ok("n", "n.whl", []),
    "q": ok("q", "q.whl", []),
    "b": skipped("b", "02-fetch"),
    "e": skipped("e", "08-fingerprint"),
}
PACKAGES = [Package(name, "1.0") for name in BY_PACKAGE]


def full_report() -> str:
    return report(
        PACKAGES,
        by_phase(BY_PACKAGE),
        PHASE_08,
        PHASE_09,
        ROWS,
        {"lcms2": {"2.19.0": ["2.19.1"]}},
    )


A_REF = f"{rpm('libfoo', '1.0-1')}#{digest('/opt/lib/libfoo.so.1')}"


def md(*cells: str) -> str:
    return "| " + " | ".join(cells) + " |"


FILES = "| file | component | library | version | basis | note | comparison |"
SASL_PURL = rpm("cyrus-sasl-lib", "2.1.26.0-24.el7_9")
NOT_TRACKED = ("skip", "—", "—", "not tracked")
EXPECTED = "\n".join(
    [
        INTRO,
        "## Counts",
        "",
        "- Packages scanned in phase 09: 4; with any SBOM: 2; "
        "with an auditwheel SBOM: 1.",
        "- auditwheel components that name a file: tied 6, not tied 1.",
        "- `.libs/` files in scanned packages: tied 6, not tied 3.",
        "- Tied files that agree: 2 (library_string 2).",
        "- Tied files that differ: 1 (bare_version 1).",
        "- Tied files not compared: 3 "
        "(no recognizer 1, not tracked 1, several libraries 1).",
        "",
        "## a 1.0",
        "",
        "`a.whl`",
        "",
        "- `a-1.0.dist-info/sboms/auditwheel.cdx.json`: "
        "tools auditwheel 6.8.2; 8 components; compared",
        "",
        FILES,
        "|---|---|---|---|---|---|---|",
        md(
            "libkrb5-fcafa220.so.3.3",
            f"krb5-libs 1.15.1-55.el7_9 ({KRB5})",
            *("krb5", "1.15.1", "library_string", "", "agrees"),
        ),
        md(
            "libsasl2-aaaaaaaa.so.3.0.0",
            f"cyrus-sasl-lib 2.1.26.0-24.el7_9 ({SASL_PURL})",
            *("cyrus-sasl", "2.1.26", "bare_version", "needs another source"),
            "differs",
        ),
        md(
            "libgssapi_krb5-bbbbbbbb.so.2.2",
            f"krb5-libs 1.15.1-55.el7_9 ({KRB5})",
            *("krb5", "—", "—", "no recognizer", "not compared: no recognizer"),
        ),
        md(
            "libXau-cccccccc.so.6.0.0",
            f"libXau 1.0.9-3.el8 ({rpm('libXau', '1.0.9-3.el8')})",
            *NOT_TRACKED,
            "not compared: not tracked",
        ),
        md("libpq-dddddddd.so.5.17", "—", "libpq", "17.11", "library_string", "", "—"),
        md(
            "liblcms2-eeeeeeee.so.2",
            f"lcms2 2.19.1-1.el8 ({rpm('lcms2', '2.19.1-1')})",
            *("lcms2", "2.19.0", "library_string", "ambiguous: may also be 2.19.1"),
            "agrees",
        ),
        md(
            "libmulti-ffffffff.so.1",
            f"bzip2-libs 1.0.8-1 ({rpm('bzip2-libs', '1.0.8-1')})",
            *("free", "—", "—", "no recognizer", "not compared: several libraries"),
        ),
        md("", "", "bz", "1.0.8", "library_string", "", ""),
        "",
        "auditwheel components tied to no file:",
        "",
        "| name | version | purl | bom-ref |",
        "|---|---|---|---|",
        md("libfoo", "1.0-1", rpm("libfoo", "1.0-1"), A_REF),
        "",
        "## p 1.0",
        "",
        "`p.whl`",
        "",
        "- `p-1.0.dist-info/sboms/p.cdx.json`: "
        "tools generate-sbom.py 6.8.2; 1 component; listed, not compared",
        "- `p-1.0.dist-info/sboms/bad.json`: error: not_json",
        "- `p-1.0.dist-info/sboms/x.spdx.json`: spdx-json; listed, not compared",
        "",
        FILES,
        "|---|---|---|---|---|---|---|",
        md(
            "libfreetype-11111111.so.6", "—", "freetype", "—", "—", "no recognizer", "—"
        ),
        "",
        "## n 1.0",
        "",
        "`n.whl`",
        "",
        "No SBOM files.",
        "",
        FILES,
        "|---|---|---|---|---|---|---|",
        md("libgfortran-22222222.so.5", "—", *NOT_TRACKED, "—"),
        "",
        "## b 1.0",
        "",
        "skipped at 02-fetch: too_large",
        "",
        "## e 1.0",
        "",
        "error at 08-fingerprint: bad ELF",
        "",
    ]
)


def test_report() -> None:
    assert full_report() == EXPECTED


def cells_of(line: str) -> list[str]:
    return [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]


def shown_counts(text: str) -> Counter[str]:
    """The counts the report's sections show, keyed as ``counts_text`` puts
    them."""
    shown: Counter[str] = Counter()
    for section in text.split("\n## ")[2:]:
        lines = section.splitlines()
        if not lines[2].startswith("`"):
            continue  # Stopped before phase 09 finished.
        sbom_lines = [x for x in lines if x.startswith("- `")]
        shown["scanned"] += 1
        shown["with an SBOM"] += bool(sbom_lines)
        shown["with auditwheel"] += any(x.endswith("; compared") for x in sbom_lines)
        table = "files"
        for line in lines:
            if line.startswith("| name |"):
                table = "untied"
            if not line.startswith("| ") or line.startswith(("| file |", "| name |")):
                continue
            cells = cells_of(line)
            if table == "untied":
                shown["components not tied"] += 1
            elif cells[0] and cells[1] == "—":
                shown["files not tied"] += 1
            elif cells[0]:
                shown["files tied"] += 1
                shown["components tied"] += len(cells[1].split("; "))
                comparison = cells[6]
                if comparison in ("agrees", "differs"):
                    comparison += f": {cells[4]}"
                shown[comparison] += 1
    return shown


def counts_text(shown: Counter[str]) -> str:
    def split(outcome: str) -> str:
        parts = sorted(
            (key.removeprefix(f"{outcome}: "), n)
            for key, n in shown.items()
            if key.startswith(f"{outcome}: ")
        )
        total = sum(n for _, n in parts)
        return f"{total} ({', '.join(f'{k} {n}' for k, n in parts)})" if parts else "0"

    return (
        f"- Packages scanned in phase 09: {shown['scanned']}; with any SBOM: "
        f"{shown['with an SBOM']}; with an auditwheel SBOM: "
        f"{shown['with auditwheel']}.\n"
        f"- auditwheel components that name a file: tied "
        f"{shown['components tied']}, not tied {shown['components not tied']}.\n"
        f"- `.libs/` files in scanned packages: tied {shown['files tied']}, "
        f"not tied {shown['files not tied']}.\n"
        f"- Tied files that agree: {split('agrees')}.\n"
        f"- Tied files that differ: {split('differs')}.\n"
        f"- Tied files not compared: {split('not compared')}.\n"
    )


def test_counts_equal_what_the_sections_show() -> None:
    text = full_report()
    shown = shown_counts(text)
    # q was scanned, but has no SBOM or .libs/ file, so it has no section.
    shown["scanned"] += 1
    assert f"## Counts\n\n{counts_text(shown)}\n" in text
    assert shown["agrees: library_string"] == 2
    assert shown["differs: bare_version"] == 1


def test_two_components_on_one_file_are_shown_and_counted() -> None:
    files = libs("a", "libkrb5-fcafa220.so.3.3")
    two = [
        component("krb5-libs", "1.15.1-55", KRB5, "/lib64/libkrb5.so.3.3"),
        component(
            "krb5", "1.15.1-1", rpm("krb5", "1.15.1-1"), "/usr/lib/libkrb5.so.3.3"
        ),
    ]
    record = contains(
        "a", "libkrb5-fcafa220.so.3.3", "krb5", "1.15.1", "library_string"
    )
    text = report(
        [Package("a", "1.0")],
        by_phase({"a": ok_until_05("a", files)}),
        {"a": ok("a", "a.whl", [record])},
        {"a": ok("a", "a.whl", [sbom("s.json", two)])},
        ROWS,
        {},
    )
    assert "- auditwheel components that name a file: tied 2, not tied 0." in text
    assert "- Tied files not compared: 1 (several components 1)." in text
    assert (
        f"| krb5-libs 1.15.1-55 ({KRB5}); krb5 1.15.1-1 ({rpm('krb5', '1.15.1-1')}) "
        "| krb5 | 1.15.1 | library_string |  | not compared: several components |"
    ) in text


def test_an_unmapped_prefix_is_shown_as_not_mapped() -> None:
    files = libs("a", "libz-12345678.so.1")
    libz = component("zlib", "1.2.7-21", rpm("zlib", "1.2.7-21"), "/lib64/libz.so.1")
    text = report(
        [Package("a", "1.0")],
        by_phase({"a": ok_until_05("a", files)}),
        {"a": ok("a", "a.whl", [])},
        {"a": ok("a", "a.whl", [sbom("s.json", [libz])])},
        [],
        {},
    )
    assert "| — | — | — | not mapped | not compared: not mapped |" in text


def test_phase_09s_own_error_names_phase_09() -> None:
    error: Line = {"name": "c", "status": "error", "reason": "wheel x is missing"}
    text = report(
        [Package("c", "1.0")],
        by_phase({"c": ok_until_05("c", [])}),
        {"c": ok("c", "c.whl", [])},
        {"c": error},
        [],
        {},
    )
    assert text.endswith("\n## c 1.0\n\nerror at 09-sboms: wheel x is missing\n")
    assert "Packages scanned in phase 09: 0; with any SBOM: 0;" in text
