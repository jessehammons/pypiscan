from datetime import date
from pathlib import Path

import pytest

from pypiscan.cve_table import (
    Cve,
    CveTableError,
    Dispute,
    Fix,
    Severity,
    load_cve_table,
)
from pypiscan.library_map import MapRow, load_library_map

DATA = Path(__file__).parent.parent / "data"
WEBP = "https://chromium.googlesource.com/webm/libwebp"
FIX_1_3_2 = "2af26267cdfcb63a88e5c74a85927a12d6ca1d76"
FIX_1_4_0 = "902bc9190331343b2017211debcec8d2ab87e17a"
INTRODUCED = "a" * 40


def row(library: str, cpe: str = "", tags: str = "v{version}") -> MapRow:
    return MapRow(f"lib{library}", library, "r", tags, "", "", "", "", cpe, "")


ROWS = [
    row("libwebp", "webmproject:libwebp"),
    MapRow("libwebpmux", "libwebp", WEBP, "v{version}", "", "", "", "", "w:w", ""),
    row("foo", "foo:foo", tags="foo-{version}"),
    row("bar"),
    MapRow("libgfortran", "skip", "", "", "", "", "", "", "", ""),
]

CVE = """\
[[cve]]
id = "CVE-2023-4863"
library = "libwebp"
published = 2023-09-12
component = "library"
introduced = "unknown"
duplicates = ["CVE-2023-5129"]
sources = ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"]

[[cve.severity]]
source = "nvd@nist.gov"
cvss = "3.1"
score = 8.8
label = "HIGH"

[[cve.fix]]
commits = ["2af26267cdfcb63a88e5c74a85927a12d6ca1d76"]
tag = "v1.3.2"
date = 2023-09-13

[[cve.fix]]
commits = ["902bc9190331343b2017211debcec8d2ab87e17a"]
tag = "v1.4.0"
date = 2024-04-12
"""
HEAD = "CVE-2023-4863 libwebp"


def edit(old: str, new: str, text: str = CVE) -> str:
    assert text.count(old) == 1, old
    return text.replace(old, new)


def after(line: str, added: str, text: str = CVE) -> str:
    """``text`` with ``added`` on the line after ``line``."""
    return edit(f"{line}\n", f"{line}\n{added}\n", text)


def load(tmp_path: Path, text: str) -> list[Cve]:
    path = tmp_path / "cves.toml"
    path.write_text(text)
    return load_cve_table(path, ROWS)


def reject(tmp_path: Path, text: str) -> str:
    """The loader's message for ``text``, without the file's path."""
    path = tmp_path / "cves.toml"
    path.write_text(text)
    with pytest.raises(CveTableError) as exc:
        load_cve_table(path, ROWS)
    message = str(exc.value)
    assert message.startswith(f"{path}: ")
    return message.removeprefix(f"{path}: ")


def test_committed_table_loads_against_committed_map() -> None:
    rows = load_library_map(DATA / "libraries.csv")
    [cve] = load_cve_table(DATA / "cves.toml", rows)
    assert (cve.id, cve.library, cve.published) == (
        "CVE-2023-4863",
        "libwebp",
        date(2023, 9, 12),
    )
    assert (cve.component, cve.tool, cve.introduced) == ("library", None, "unknown")
    assert cve.duplicates == ("CVE-2023-5129",)
    assert cve.disputed is None
    assert cve.sources[0] == "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"
    assert len(cve.sources) == 4
    assert cve.severity == (
        Severity("nvd@nist.gov", "3.1", 8.8, "HIGH"),
        Severity("134c704f-9b21-4f2e-91b3-4a467353bcc0", "3.1", 8.8, "HIGH"),
    )
    assert cve.fix == (
        Fix((FIX_1_3_2,), "v1.3.2", date(2023, 9, 13)),
        Fix((FIX_1_4_0,), "v1.4.0", date(2024, 4, 12)),
    )


def test_an_empty_table_is_valid(tmp_path: Path) -> None:
    assert load(tmp_path, "# No CVEs yet.\n") == []


def test_unreadable_table(tmp_path: Path) -> None:
    path = tmp_path / "missing.toml"
    with pytest.raises(CveTableError, match=f"{path}: .*No such file"):
        load_cve_table(path, ROWS)
    path.write_bytes(b'x = "\xff"\n')
    with pytest.raises(CveTableError, match=f"{path}: "):
        load_cve_table(path, ROWS)


def test_toml_syntax_error_keeps_line_and_column(tmp_path: Path) -> None:
    message = reject(tmp_path, edit('component = "library"', "component = library"))
    assert "(at line 5, column 13)" in message


REJECTED = [
    # A key the table doesn't know, at every level, or a missing one.
    (f"extra = 1\n{CVE}", "extra: unknown key"),
    (after('id = "CVE-2023-4863"', 'note = "x"'), f"{HEAD}: note: unknown key"),
    (
        after('label = "HIGH"', 'vector = "AV:N"'),
        f"{HEAD}: severity[0].vector: unknown key",
    ),
    (
        after("date = 2023-09-13", 'branch = "1.3.1"'),
        f"{HEAD}: fix[0].branch: unknown key",
    ),
    (
        after(
            'introduced = "unknown"',
            'disputed = { reason = "r", source = "https://x", by = "y" }',
        ),
        f"{HEAD}: disputed.by: unknown key",
    ),
    (edit('component = "library"\n', ""), f"{HEAD}: component: missing"),
    (edit('tag = "v1.4.0"\n', ""), f"{HEAD}: fix[1].tag: missing"),
    (edit('cvss = "3.1"\n', ""), f"{HEAD}: severity[0].cvss: missing"),
    # Values of the wrong type.
    ("cve = 1\n", "cve: expected an array, got an integer"),
    ("cve = [1]\n", "cve[0]: expected a table, got an integer"),
    (edit('"CVE-2023-4863"\nlibrary', "4863\nlibrary"), "cve[0] libwebp: id: "),
    (
        edit('library = "libwebp"', "library = 1"),
        "CVE-2023-4863: library: expected a string, got an integer",
    ),
    (
        edit("published = 2023-09-12", 'published = "2023-09-12"'),
        f"{HEAD}: published: expected a date, got a string",
    ),
    (
        edit("published = 2023-09-12", "published = 2023-09-12T15:15:24.327"),
        f"{HEAD}: published: expected a date, got a date-time",
    ),
    (
        edit("published = 2023-09-12", "published = 2023-09-12T15:15:24Z"),
        f"{HEAD}: published: expected a date, got a date-time",
    ),
    (
        edit("date = 2024-04-12", "date = 18:53:18"),
        f"{HEAD}: fix[1].date: expected a date, got a time",
    ),
    (
        edit("score = 8.8", "score = true"),
        f"{HEAD}: severity[0].score: expected a number, got a boolean",
    ),
    (
        edit("score = 8.8", 'score = "8.8"'),
        f"{HEAD}: severity[0].score: expected a number, got a string",
    ),
    (
        edit('["CVE-2023-5129"]', '"CVE-2023-5129"'),
        f"{HEAD}: duplicates: expected an array, got a string",
    ),
    (
        edit(f'["{FIX_1_4_0}"]', "[902]"),
        f"{HEAD}: fix[1].commits[0]: expected a string, got an integer",
    ),
    (
        after('introduced = "unknown"', 'disputed = "yes"'),
        f"{HEAD}: disputed: expected a table, got a string",
    ),
    (
        edit(
            '[[cve.severity]]\nsource = "nvd@nist.gov"\ncvss = "3.1"\n'
            'score = 8.8\nlabel = "HIGH"\n',
            "",
            after(
                'introduced = "unknown"',
                'severity = { source = "s", cvss = "3.1", score = 8.8, '
                'label = "HIGH" }',
            ),
        ),
        f"{HEAD}: severity: expected an array, got a table",
    ),
    # The id's shape, and an id listed twice.
    (
        edit('id = "CVE-2023-4863"', 'id = "CVE-23-4863"'),
        "CVE-23-4863 libwebp: id: 'CVE-23-4863' isn't CVE-, a year, - and 4 or "
        "more digits",
    ),
    (edit('id = "CVE-2023-4863"', 'id = "CVE-2023-486"'), "CVE-2023-486 libwebp"),
    (edit('id = "CVE-2023-4863"', 'id = "cve-2023-4863"'), "cve-2023-4863 lib"),
    (CVE + "\n" + CVE, f"{HEAD}: id: listed twice for libwebp"),
    # Duplicates.
    (
        edit('["CVE-2023-5129"]', '["CVE-2023-4863"]'),
        f"{HEAD}: duplicates[0]: CVE-2023-4863 is also a row's id",
    ),
    (
        edit('["CVE-2023-5129"]', '["CVE-2023-5129", "CVE-2023-5129"]'),
        f"{HEAD}: duplicates[1]: CVE-2023-5129 is listed twice",
    ),
    (
        edit('["CVE-2023-5129"]', '["5129"]'),
        f"{HEAD}: duplicates[0]: '5129' isn't a CVE ID",
    ),
    # A library the map doesn't track, or one with no cpe.
    (
        edit('library = "libwebp"', 'library = "zlib"'),
        "CVE-2023-4863 zlib: library: 'zlib' isn't a library the map tracks",
    ),
    (
        edit('library = "libwebp"', 'library = "skip"'),
        "CVE-2023-4863 skip: library: 'skip' isn't a library the map tracks",
    ),
    (
        edit('library = "libwebp"', 'library = "bar"'),
        "CVE-2023-4863 bar: library: 'bar' has no cpe in the library map",
    ),
    (edit('library = "libwebp"', 'library = ""'), "CVE-2023-4863: library: is"),
    # The day NVD published it.
    (
        edit("published = 2023-09-12", "published = 2019-12-31"),
        f"{HEAD}: published: 2019-12-31 is before 2020-01-01",
    ),
    # The component and its tool.
    (
        edit('component = "library"', 'component = "binary"'),
        f"{HEAD}: component: 'binary' isn't library or tool",
    ),
    (
        edit('component = "library"', 'component = "tool"'),
        f"{HEAD}: tool: a tool CVE names its tool",
    ),
    (
        edit('component = "library"', 'component = "tool"\ntool = ""'),
        f"{HEAD}: tool: is empty",
    ),
    (
        after('component = "library"', 'tool = "cwebp"'),
        f"{HEAD}: tool: a library CVE has no tool",
    ),
    # The introducing commit.
    (
        edit('introduced = "unknown"', 'introduced = "v1.0.0"'),
        f"{HEAD}: introduced: 'v1.0.0' is neither unknown nor a commit: 40 "
        "lowercase hex digits",
    ),
    (
        edit('introduced = "unknown"', f'introduced = "{"A" * 40}"'),
        f"{HEAD}: introduced: '{'A' * 40}' is neither",
    ),
    (
        edit('introduced = "unknown"', 'introduced = "Unknown"'),
        f"{HEAD}: introduced: 'Unknown' is neither",
    ),
    # A dispute.
    (
        after('introduced = "unknown"', 'disputed = { reason = "upstream" }'),
        f"{HEAD}: disputed.source: missing",
    ),
    (
        after('introduced = "unknown"', 'disputed = { source = "https://x" }'),
        f"{HEAD}: disputed.reason: missing",
    ),
    # Sources.
    (
        edit('["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"]', "[]"),
        f"{HEAD}: sources: a CVE needs at least one source",
    ),
    (
        edit(
            '["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"]',
            f'["{WEBP}/+/refs/tags/v1.3.2/NEWS"]',
        ),
        f"{HEAD}: sources: no link to https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
    ),
    (
        edit("detail/CVE-2023-4863", "detail/CVE-2023-5129"),
        f"{HEAD}: sources: no link to https://nvd.nist.gov/vuln/detail/",
    ),
    (
        edit("detail/CVE-2023-4863", "detail/cve-2023-4863"),
        f"{HEAD}: sources: no link to https://nvd.nist.gov/vuln/detail/",
    ),
    (
        edit('4863"]', '4863", "http://example.org/advisory"]'),
        f"{HEAD}: sources[1]: 'http://example.org/advisory' doesn't start "
        "with https://",
    ),
    (
        edit('4863"]', '4863", "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"]'),
        f"{HEAD}: sources[1]: https://nvd.nist.gov/vuln/detail/CVE-2023-4863 "
        "is listed twice",
    ),
    (edit('sources = ["', 'sources = ["", "'), f"{HEAD}: sources[0]: is empty"),
    # Severity.
    (
        edit('score = 8.8\nlabel = "HIGH"', 'score = 6.5\nlabel = "MEDIUM"'),
        f"{HEAD}: severity: no score is labeled HIGH or CRITICAL",
    ),
    (
        edit(
            '[[cve.severity]]\nsource = "nvd@nist.gov"\ncvss = "3.1"\n'
            'score = 8.8\nlabel = "HIGH"\n',
            "",
        ),
        f"{HEAD}: severity: no score is labeled HIGH or CRITICAL",
    ),
    (
        edit('cvss = "3.1"', 'cvss = "2.0"'),
        f"{HEAD}: severity[0].cvss: CVSS version '2.0' isn't one of 3.0, 3.1, 4.0",
    ),
    (edit('cvss = "3.1"', 'cvss = "3"'), f"{HEAD}: severity[0].cvss: CVSS"),
    (
        edit('label = "HIGH"', 'label = "SEVERE"'),
        f"{HEAD}: severity[0].label: 'SEVERE' isn't one of NONE, LOW, MEDIUM, "
        "HIGH, CRITICAL",
    ),
    (edit('label = "HIGH"', 'label = "high"'), f"{HEAD}: severity[0].label: 'h"),
    (
        edit("score = 8.8", "score = 9.8"),
        f"{HEAD}: severity[0].label: HIGH doesn't fit score 9.8",
    ),
    (
        edit('source = "nvd@nist.gov"', 'source = ""'),
        f"{HEAD}: severity[0].source: is empty",
    ),
    # Fixes and their commits.
    (
        edit(f'["{FIX_1_3_2}"]', "[]"),
        f"{HEAD}: fix[0].commits: a fix needs at least one commit",
    ),
    (
        edit(f'["{FIX_1_3_2}"]', '["2af26267"]'),
        f"{HEAD}: fix[0].commits[0]: '2af26267' isn't a commit: 40 lowercase "
        "hex digits",
    ),
    (
        edit(FIX_1_3_2, FIX_1_3_2.upper()),
        f"{HEAD}: fix[0].commits[0]: '{FIX_1_3_2.upper()}' isn't a commit",
    ),
    (
        edit(f'["{FIX_1_4_0}"]', f'["{FIX_1_3_2}"]'),
        f"{HEAD}: fix[1].commits[0]: {FIX_1_3_2} appears twice in the row",
    ),
    (
        edit(f'["{FIX_1_4_0}"]', f'["{FIX_1_4_0}", "{FIX_1_4_0}"]'),
        f"{HEAD}: fix[1].commits[1]: {FIX_1_4_0} appears twice in the row",
    ),
    (
        edit('introduced = "unknown"', f'introduced = "{FIX_1_4_0}"'),
        f"{HEAD}: fix[1].commits[0]: {FIX_1_4_0} appears twice in the row",
    ),
    (
        edit('tag = "v1.3.2"', 'tag = "1.3.2"'),
        f"{HEAD}: fix[0].tag: '1.3.2' doesn't match the library's tags v{{version}}",
    ),
    (
        edit('tag = "v1.4.0"', 'tag = "v1.4.0 "'),
        f"{HEAD}: fix[1].tag: 'v1.4.0 ' doesn't match",
    ),
]


@pytest.mark.parametrize(
    ("text", "message"), REJECTED, ids=[message for _, message in REJECTED]
)
def test_rejects(tmp_path: Path, text: str, message: str) -> None:
    assert reject(tmp_path, text).startswith(message)


def test_a_bool_score_is_rejected_but_an_int_score_is_a_number(
    tmp_path: Path,
) -> None:
    assert "got a boolean" in reject(tmp_path, edit("score = 8.8", "score = false"))
    [cve] = load(
        tmp_path, edit('score = 8.8\nlabel = "HIGH"', 'score = 9\nlabel = "CRITICAL"')
    )
    assert cve.severity == (Severity("nvd@nist.gov", "3.1", 9.0, "CRITICAL"),)


SECOND_SEVERITY = 'label = "HIGH"\n\n[[cve.severity]]\nsource = "s"\ncvss = "4.0"\n'


@pytest.mark.parametrize(
    ("score", "label"),
    [
        ("0.0", "NONE"),
        ("0", "NONE"),
        ("0.1", "LOW"),
        ("3.9", "LOW"),
        ("4.0", "MEDIUM"),
        ("6.9", "MEDIUM"),
        ("7.0", "HIGH"),
        ("7", "HIGH"),
        ("8.9", "HIGH"),
        ("9.0", "CRITICAL"),
        ("10.0", "CRITICAL"),
        ("10", "CRITICAL"),
    ],
)
def test_score_bands(tmp_path: Path, score: str, label: str) -> None:
    added = f'{SECOND_SEVERITY}score = {score}\nlabel = "{label}"'
    [cve] = load(tmp_path, edit('label = "HIGH"', added))
    assert cve.severity[1] == Severity("s", "4.0", float(score), label)


@pytest.mark.parametrize(
    ("score", "label", "message"),
    [
        ("0.0", "LOW", "LOW doesn't fit score 0.0"),
        ("3.9", "MEDIUM", "MEDIUM doesn't fit score 3.9"),
        ("4.0", "LOW", "LOW doesn't fit score 4.0"),
        ("6.9", "HIGH", "HIGH doesn't fit score 6.9"),
        ("7.0", "MEDIUM", "MEDIUM doesn't fit score 7.0"),
        ("8.9", "CRITICAL", "CRITICAL doesn't fit score 8.9"),
        ("9.0", "HIGH", "HIGH doesn't fit score 9.0"),
        ("8.85", "HIGH", "8.85 isn't 0.0 to 10.0 with at most one decimal place"),
        ("10.1", "CRITICAL", "10.1 isn't 0.0 to 10.0 with at most one decimal place"),
        ("11", "CRITICAL", "11 isn't 0.0 to 10.0 with at most one decimal place"),
        ("-0.1", "NONE", "-0.1 isn't 0.0 to 10.0 with at most one decimal place"),
        ("-1", "NONE", "-1 isn't 0.0 to 10.0 with at most one decimal place"),
        ("nan", "HIGH", "nan isn't 0.0 to 10.0 with at most one decimal place"),
        ("inf", "CRITICAL", "inf isn't 0.0 to 10.0 with at most one decimal place"),
    ],
)
def test_rejects_scores(tmp_path: Path, score: str, label: str, message: str) -> None:
    added = f'{SECOND_SEVERITY}score = {score}\nlabel = "{label}"'
    field = "label" if "doesn't fit" in message else "score"
    text = edit('label = "HIGH"', added)
    assert reject(tmp_path, text) == f"{HEAD}: severity[1].{field}: {message}"


def test_accepts_what_the_table_allows(tmp_path: Path) -> None:
    text = edit('component = "library"', 'component = "tool"\ntool = "cwebp"')
    text = edit('introduced = "unknown"', f'introduced = "{INTRODUCED}"', text)
    text = after(
        f'introduced = "{INTRODUCED}"',
        'disputed = { reason = "upstream: not a bug", source = "https://x.org/d" }',
        text,
    )
    text = edit("published = 2023-09-12", "published = 2020-01-01", text)
    [cve] = load(tmp_path, text)
    assert (cve.component, cve.tool) == ("tool", "cwebp")
    assert cve.introduced == INTRODUCED
    assert cve.disputed == Dispute("upstream: not a bug", "https://x.org/d")
    assert cve.published == date(2020, 1, 1)


def test_a_cve_with_no_fix_or_duplicates(tmp_path: Path) -> None:
    text = CVE[: CVE.index("[[cve.fix]]")]
    text = edit('duplicates = ["CVE-2023-5129"]\n', "", text)
    [cve] = load(tmp_path, text)
    assert (cve.fix, cve.duplicates) == ((), ())


def test_a_fix_with_several_commits(tmp_path: Path) -> None:
    text = edit(f'["{FIX_1_4_0}"]', f'["{FIX_1_4_0}", "{INTRODUCED}"]')
    [cve] = load(tmp_path, text)
    assert cve.fix[1].commits == (FIX_1_4_0, INTRODUCED)


def other_library(text: str = CVE) -> str:
    """The same CVE listed for library foo, whose tags are foo-{version}."""
    text = edit('library = "libwebp"', 'library = "foo"', text)
    text = edit('tag = "v1.3.2"', 'tag = "foo-1.3.2"', text)
    return edit('tag = "v1.4.0"', 'tag = "foo-1.4.0"', text)


def other_cve(text: str = CVE) -> str:
    """Another CVE in libwebp, with the same duplicate."""
    text = edit('id = "CVE-2023-4863"', 'id = "CVE-2024-0001"', text)
    return edit("detail/CVE-2023-4863", "detail/CVE-2024-0001", text)


def test_a_cve_in_two_libraries_lists_its_duplicates_in_both(tmp_path: Path) -> None:
    cves = load(tmp_path, CVE + "\n" + other_library())
    assert [(cve.id, cve.library) for cve in cves] == [
        ("CVE-2023-4863", "libwebp"),
        ("CVE-2023-4863", "foo"),
    ]
    assert cves[1].fix[0].tag == "foo-1.3.2"


def test_the_tag_must_match_its_own_library(tmp_path: Path) -> None:
    text = edit('library = "libwebp"', 'library = "foo"')
    assert reject(tmp_path, text).startswith(
        "CVE-2023-4863 foo: fix[0].tag: 'v1.3.2' doesn't match the library's tags "
        "foo-{version}"
    )


def test_rejects_a_duplicate_of_two_cves(tmp_path: Path) -> None:
    assert reject(tmp_path, CVE + "\n" + other_cve()) == (
        "CVE-2024-0001 libwebp: duplicates[0]: CVE-2023-5129 is listed twice, also "
        "as a duplicate of CVE-2023-4863"
    )


def test_rejects_a_duplicate_that_is_a_later_rows_id(tmp_path: Path) -> None:
    first = edit('["CVE-2023-5129"]', '["CVE-2024-0001"]')
    second = edit('duplicates = ["CVE-2023-5129"]\n', "", other_cve())
    assert reject(tmp_path, first + "\n" + second) == (
        f"{HEAD}: duplicates[0]: CVE-2024-0001 is also a row's id"
    )
