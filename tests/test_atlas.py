"""The bundled-library atlas on hand-built phase 01 to 09 lines, SBOM records
and map rows."""

import pytest

from pypiscan.atlas import INTRO, build_image, report, sbom_kind
from pypiscan.package_list import Package
from pypiscan.scan import Line
from test_fingerprint_report import by_phase, ok_until_05, row, stopped
from test_sbom_report import component, libs, ok, rpm, sbom

# Build images from purls.


@pytest.mark.parametrize(
    ("purl", "image"),
    [
        ("pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9?arch=x86_64", "CentOS 7"),
        ("pkg:rpm/almalinux/openssl-libs@1:1.1.1k-15.el8_6", "AlmaLinux 8"),
        ("pkg:rpm/rocky/zlib@1.2.11-40.el9#sub", "Rocky Linux 9"),
        ("pkg:rpm/rhel/zlib@1.2.11-40.el9", "RHEL 9"),
        ("pkg:deb/ubuntu/zlib1g@1:1.2.11.dfsg-2ubuntu9", "Ubuntu, release unknown"),
        ("pkg:deb/debian/zlib1g@1.2.11.el7-1", "Debian, release unknown"),
        ("pkg:apk/alpine/zlib@1.3.1-r2", "Alpine, release unknown"),
        ("pkg:rpm/centos/lcms2@2.19.1-1", "CentOS, release unknown"),
        ("pkg:rpm/centos/thing@1.el7", "CentOS, release unknown"),
        ("pkg:rpm/centos/thing", "CentOS, release unknown"),
        ("pkg:rpm/fedora/zlib@1.2.13-3.fc39", "fedora, release unknown"),
        ("pkg:rpm/opensuse/zlib@1.2-1.el8", "opensuse 8"),
        ("pkg:rpm/zlib@1.2.7-21.el7", "unknown 7"),
        ("pkg:generic/zlib@1.3.1", "unknown, release unknown"),
        ("not a purl", "unknown, release unknown"),
    ],
)
def test_build_image(purl: str, image: str) -> None:
    assert build_image(purl) == image


# SBOM kinds.


def test_sbom_kind() -> None:
    assert sbom_kind(sbom("s.json", [])) == "auditwheel"
    assert sbom_kind(sbom("s.json", [], tool="cargo-cyclonedx")) == "cargo-cyclonedx"
    two: Line = {
        **sbom("s.json", []),
        "tools": [{"name": "a", "version": "1"}, {"name": "b", "version": None}],
    }
    assert sbom_kind(two) == "a+b"
    assert sbom_kind({**sbom("s.json", []), "tools": []}) == "cyclonedx-json, no tools"
    assert sbom_kind({**sbom("s.json", []), "format": "spdx-json"}) == "spdx-json"
    assert sbom_kind(sbom("s.json", [], error="not_json")) == "error: not_json"


# The report.

ROWS = [
    row("libkrb5", "krb5", "library_string"),
    row("libopenblas", "openblas", "library_string"),
    row("libscipy_openblas", "openblas", "library_string"),
    row("libfreetype", "freetype"),
    row("libfreetype", "bzip2", "library_string"),
    row("libgfortran", "skip"),
]
KRB5 = rpm("krb5-libs", "1.15.1-55.el7_9")
GFORTRAN = "pkg:rpm/almalinux/libgfortran@8.5.0-18.el8_6"
DEB = "pkg:deb/ubuntu/libopenblas0@0.3.20-1"


def resolved(package: str, files: list[dict[str, str]], tag: str) -> dict[str, Line]:
    lines = ok_until_05(package, files)
    filename = f"{package}-1.0-cp312-cp312-{tag}.whl"
    lines["01-resolve"] = {**lines["01-resolve"], "filename": filename}
    return lines


TAG = "manylinux_2_28_x86_64"
OLD_TAG = "manylinux_2_17_x86_64.manylinux2014_x86_64"
BY_PACKAGE = {
    "a": resolved(
        "a",
        libs(
            "a",
            "libkrb5-fcafa220.so.3.3",
            "libopenblas-aaaaaaaa.so",
            "libscipy_openblas-bbbbbbbb.so",
            "libgfortran-cccccccc.so.5",
            "libfoo-dddddddd.so.1",
            "libfreetype-eeeeeeee.so.6",
        ),
        OLD_TAG,
    ),
    "c": resolved(
        "c",
        libs("c", "libopenblas-11111111.so", "libscipy_openblas-22222222.so"),
        TAG,
    ),
    "d": resolved("d", libs("d", "libkrb5-33333333.so.3.3"), TAG),
    "E": resolved("E", libs("E", "libfoo-44444444.so.1"), TAG),
    "f": resolved("f", libs("f", "libkrb5-55555555.so.3.3"), TAG),
    "g": resolved("g", [], TAG),
    "h": resolved("h", [], TAG),
    "b": stopped("b", "02-fetch", "skipped", "too_large"),
    "x": stopped("x", "03-inspect", "error", "bad zip"),
}
PHASE_09 = {
    "a": ok(
        "a",
        "a.whl",
        [
            sbom(
                "auditwheel.cdx.json",
                [
                    component("a", "1.0", "pkg:pypi/a@1.0"),
                    component("krb5-libs", "1", KRB5, "/lib64/libkrb5.so.3.3"),
                    component("gf", "8", GFORTRAN, "/lib64/libgfortran.so.5"),
                    component("ob", "0", DEB, "/usr/lib/libopenblas.so"),
                    component("lost", "1", rpm("lost", "1-1"), "/opt/liblost.so"),
                ],
            ),
            sbom("cargo.cdx.json", [], tool="cargo-cyclonedx"),
        ],
    ),
    "c": ok(
        "c",
        "c.whl",
        [
            {**sbom("spdx.json", []), "format": "spdx-json"},
            sbom("bad.json", [], error="not_json"),
            # Not auditwheel's, so its component is tied to nothing.
            sbom(
                "p.json",
                [component("ob", "0", DEB, "/usr/lib/libopenblas.so")],
                tool="pillow",
            ),
        ],
    ),
    "d": ok("d", "d.whl", [{**sbom("n.json", []), "tools": []}]),
    "E": ok("E", "E.whl", []),
    "f": {"name": "f", "status": "error", "reason": "wheel f.whl is missing"},
    "g": ok("g", "g.whl", [sbom("s.json", [], tool="cargo-cyclonedx")]),
    "h": ok("h", "h.whl", []),
    "b": {"name": "b", "status": "skipped", "reason": "02-fetch"},
    "x": {"name": "x", "status": "skipped", "reason": "03-inspect"},
}
PACKAGES = [Package(name, "1.0") for name in BY_PACKAGE]

EXPECTED = "\n".join(
    [
        INTRO,
        "## Counts",
        "",
        "- Packages in the episode: 9; wheels opened in phase 05: 7; packages "
        "skipped: 2 (error at 03-inspect: bad zip 1; skipped at 02-fetch: "
        "too_large 1).",
        "- Wheels with a `.libs/` directory (the rows): 5, with 11 `.libs/` files.",
        "- Libraries by the map's name: 2; rows carrying each: krb5 3; openblas 2.",
        "- Prefixes not in the map: 1, with 2 files.",
        "- Rows by platform tag: manylinux_2_28_x86_64 4; "
        "manylinux_2_17_x86_64.manylinux2014_x86_64 1.",
        "- Rows with an SBOM: 3; by kind, a wheel with several kinds counts "
        "under each: auditwheel 1; cargo-cyclonedx 1; "
        "cyclonedx-json, no tools 1; error: not_json 1; pillow 1; spdx-json 1.",
        "- Scanned wheels with an SBOM but no `.libs/`: 1; by kind, a wheel with "
        "several kinds counts under each: cargo-cyclonedx 1.",
        "- Rows with a file tied to an auditwheel component: 1; tied files by "
        "build image: AlmaLinux 8 1; CentOS 7 1; Ubuntu, release unknown 1.",
        "",
        "## Wheels",
        "",
        "| package | version | platform tag | SBOM | build image | libraries |",
        "|---|---|---|---|---|---|",
        f"| a | 1.0 | {OLD_TAG} | auditwheel, cargo-cyclonedx "
        "| AlmaLinux 8; CentOS 7; Ubuntu, release unknown "
        "| krb5 [CentOS 7]; `libfoo` (not in map); "
        "`libfreetype` (freetype, bzip2); `libgfortran` (skip) [AlmaLinux 8]; "
        "openblas [Ubuntu, release unknown] |",
        f"| c | 1.0 | {TAG} | error: not_json, pillow, spdx-json | — | openblas |",
        f"| d | 1.0 | {TAG} | cyclonedx-json, no tools | — | krb5 |",
        f"| E | 1.0 | {TAG} | none | — | `libfoo` (not in map) |",
        f"| f | 1.0 | {TAG} | error at 09-sboms: wheel f.whl is missing | — | krb5 |",
        "",
        "## Packages not opened",
        "",
        "- b 1.0: skipped at 02-fetch: too_large",
        "- x 1.0: error at 03-inspect: bad zip",
        "",
    ]
)


def full_report() -> str:
    return report(PACKAGES, by_phase(BY_PACKAGE), PHASE_09, ROWS)


def test_report() -> None:
    assert full_report() == EXPECTED


def table(text: str) -> list[list[str]]:
    lines = text.split("## Wheels\n\n")[1].split("\n\n")[0].splitlines()[2:]
    return [line.removeprefix("| ").removesuffix(" |").split(" | ") for line in lines]


def test_counts_equal_what_the_rows_show() -> None:
    text = full_report()
    rows = table(text)
    names = [r[0] for r in rows]
    assert names == sorted(names, key=str.lower)
    with_sbom = [r for r in rows if r[3] != "none" and not r[3].startswith("error at")]
    tied = [r for r in rows if r[4] != "—"]
    entries = [[e.split(" [")[0] for e in r[5].split("; ")] for r in rows]
    krb5 = [e for e in entries if "krb5" in e]
    assert f"(the rows): {len(rows)}," in text
    assert f"- Rows with an SBOM: {len(with_sbom)};" in text
    assert f"auditwheel component: {len(tied)};" in text
    assert f"krb5 {len(krb5)};" in text
    assert "manylinux_2_28_x86_64 4;" in text


def test_a_wheel_with_an_sbom_and_no_libs_is_counted_not_a_row() -> None:
    text = full_report()
    assert "| g |" not in text and "| h |" not in text
    assert "- Scanned wheels with an SBOM but no `.libs/`: 1;" in text


def test_a_prefix_is_never_shown_as_a_library() -> None:
    files = libs("a", "libopenblas-aaaaaaaa.so", "libfreetype-bbbbbbbb.so.6")
    text = report(
        [Package("a", "1.0")],
        by_phase({"a": resolved("a", files, TAG)}),
        {"a": ok("a", "a.whl", [])},
        [],
    )
    entries = "`libfreetype` (not in map); `libopenblas` (not in map)"
    assert f"| none | — | {entries} |\n" in text
    assert "- Libraries by the map's name: 0; rows carrying each: none." in text
    assert "- Prefixes not in the map: 2, with 2 files." in text
    assert "## Packages not opened" not in text


def test_a_wheel_with_two_kinds_counts_under_each() -> None:
    two = [sbom("a.json", []), sbom("c.json", [], tool="cargo-cyclonedx")]
    lines = {
        "r": resolved("r", libs("r", "libfoo-11111111.so.1"), TAG),
        "s": resolved("s", [], TAG),
    }
    text = report(
        [Package("r", "1.0"), Package("s", "1.0")],
        by_phase(lines),
        {"r": ok("r", "r.whl", two), "s": ok("s", "s.whl", two)},
        [],
    )
    each = "a wheel with several kinds counts under each"
    assert (
        f"- Rows with an SBOM: 1; by kind, {each}: auditwheel 1; cargo-cyclonedx 1.\n"
    ) in text
    assert (
        f"- Scanned wheels with an SBOM but no `.libs/`: 1; by kind, {each}: "
        "auditwheel 1; cargo-cyclonedx 1.\n"
    ) in text
    assert "| auditwheel, cargo-cyclonedx |" in text
