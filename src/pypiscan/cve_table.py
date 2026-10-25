"""Load the CVE table: high and critical CVEs in the libraries the map tracks.

See README "The CVE table". The table is TOML with one ``[[cve]]`` table per
CVE and library, each with ``[[cve.severity]]`` and ``[[cve.fix]]`` tables.
``load_cve_table`` reads it against the loaded library map's rows and
rejects anything the README's list rejects, naming the CVE, its library and
the field, since tomllib gives no line numbers for values. Whether a fix's
tag exists and contains its commits is the range verifier's job (roadmap
6.3), not the loader's.
"""

import math
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import Path
from typing import cast

from pypiscan.library_map import NO_CPE, SKIP, MapRow, tag_matcher

# [0-9], not \d, which also matches other scripts' digits, such as
# FULLWIDTH DIGIT TWO.
CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
COMMIT = re.compile(r"[0-9a-f]{40}")
UNKNOWN = "unknown"
EARLIEST = date(2020, 1, 1)
COMPONENTS = ("library", "tool")
CVSS_VERSIONS = ("3.0", "3.1", "4.0")
# Each label's scores, in tenths, so floating point can't move a boundary.
BANDS = {
    "NONE": (0, 0),
    "LOW": (1, 39),
    "MEDIUM": (40, 69),
    "HIGH": (70, 89),
    "CRITICAL": (90, 100),
}
IN_SCOPE = ("HIGH", "CRITICAL")
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{}"

CVE_KEYS = ("id", "library", "published", "component", "introduced", "sources")
CVE_OPTIONAL = ("tool", "duplicates", "disputed", "severity", "fix")
SEVERITY_KEYS = ("source", "cvss", "score", "label")
FIX_KEYS = ("commits", "tag", "date")
DISPUTE_KEYS = ("reason", "source")

# TOML's name for each type tomllib gives, for messages. datetime is a
# subclass of date and bool of int, so types are looked up exactly.
TOML_TYPES: dict[type, str] = {
    str: "a string",
    bool: "a boolean",
    int: "an integer",
    float: "a float",
    datetime: "a date-time",
    date: "a date",
    time: "a time",
    list: "an array",
    dict: "a table",
}

type Table = dict[str, object]


class CveTableError(Exception):
    """The CVE table can't be read or breaks one of its rules."""


@dataclass(frozen=True)
class Severity:
    source: str
    cvss: str
    score: float
    label: str


@dataclass(frozen=True)
class Fix:
    commits: tuple[str, ...]
    tag: str
    date: date


@dataclass(frozen=True)
class Dispute:
    reason: str
    source: str


@dataclass(frozen=True)
class Cve:
    id: str
    library: str
    published: date
    component: str
    # The program, for a tool CVE; None for a library CVE.
    tool: str | None
    # A commit, or UNKNOWN.
    introduced: str
    duplicates: tuple[str, ...]
    disputed: Dispute | None
    sources: tuple[str, ...]
    severity: tuple[Severity, ...]
    fix: tuple[Fix, ...]


class _Problem(Exception):
    """A rejection inside one CVE: the field's path and what's wrong."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(field, message)
        self.field = field
        self.message = message


def _field(where: str, key: str) -> str:
    return f"{where}.{key}" if where else key


def _keys(
    table: Table, where: str, required: tuple[str, ...], optional: tuple[str, ...]
) -> None:
    for key in table:
        if key not in required + optional:
            raise _Problem(_field(where, key), "unknown key")
    for key in required:
        if key not in table:
            raise _Problem(_field(where, key), "missing")


def _wrong_type(field: str, expected: str, value: object) -> _Problem:
    return _Problem(field, f"expected {expected}, got {TOML_TYPES[type(value)]}")


def _str(value: object, field: str) -> str:
    if type(value) is not str:
        raise _wrong_type(field, "a string", value)
    if not value:
        raise _Problem(field, "is empty")
    return value


def _date(value: object, field: str) -> date:
    if type(value) is not date:
        raise _wrong_type(field, "a date", value)
    return value


def _array(value: object, field: str) -> list[object]:
    if type(value) is not list:
        raise _wrong_type(field, "an array", value)
    return cast(list[object], value)


def _table(value: object, field: str) -> Table:
    if type(value) is not dict:
        raise _wrong_type(field, "a table", value)
    return cast(Table, value)


def _strs(value: object, field: str) -> list[str]:
    return [_str(item, f"{field}[{i}]") for i, item in enumerate(_array(value, field))]


def _tables(value: object, field: str) -> list[Table]:
    items = _array(value, field)
    return [_table(item, f"{field}[{i}]") for i, item in enumerate(items)]


def _tenths(score: int | float) -> int | None:
    """``score`` in tenths, or None unless it is 0.0 to 10.0 with at most one
    decimal place."""
    if isinstance(score, float):
        if not math.isfinite(score):
            return None
        tenths = round(score * 10)
        if tenths / 10 != score:
            return None
    else:
        tenths = score * 10
    return tenths if 0 <= tenths <= 100 else None


def _severity(table: Table, where: str) -> Severity:
    _keys(table, where, SEVERITY_KEYS, ())
    source = _str(table["source"], f"{where}.source")
    cvss = _str(table["cvss"], f"{where}.cvss")
    if cvss not in CVSS_VERSIONS:
        raise _Problem(
            f"{where}.cvss",
            f"CVSS version {cvss!r} isn't one of {', '.join(CVSS_VERSIONS)}",
        )
    score = table["score"]
    if type(score) not in (int, float):
        raise _wrong_type(f"{where}.score", "a number", score)
    score = cast(int | float, score)
    tenths = _tenths(score)
    if tenths is None:
        raise _Problem(
            f"{where}.score",
            f"{score} isn't 0.0 to 10.0 with at most one decimal place",
        )
    label = _str(table["label"], f"{where}.label")
    if label not in BANDS:
        raise _Problem(f"{where}.label", f"{label!r} isn't one of {', '.join(BANDS)}")
    low, high = BANDS[label]
    if not low <= tenths <= high:
        raise _Problem(f"{where}.label", f"{label} doesn't fit score {score}")
    return Severity(source, cvss, float(score), label)


def _fix(
    table: Table, where: str, tags: Callable[[str], str | None], spelled: str
) -> Fix:
    _keys(table, where, FIX_KEYS, ())
    commits = _strs(table["commits"], f"{where}.commits")
    if not commits:
        raise _Problem(f"{where}.commits", "a fix needs at least one commit")
    for i, commit in enumerate(commits):
        if not COMMIT.fullmatch(commit):
            raise _Problem(
                f"{where}.commits[{i}]",
                f"{commit!r} isn't a commit: 40 lowercase hex digits",
            )
    tag = _str(table["tag"], f"{where}.tag")
    if tags(tag) is None:
        raise _Problem(
            f"{where}.tag", f"{tag!r} doesn't match the library's tags {spelled}"
        )
    return Fix(tuple(commits), tag, _date(table["date"], f"{where}.date"))


def _dispute(value: object) -> Dispute:
    table = _table(value, "disputed")
    _keys(table, "disputed", DISPUTE_KEYS, ())
    reason = _str(table["reason"], "disputed.reason")
    source = _str(table["source"], "disputed.source")
    if not source.startswith("https://"):
        raise _Problem("disputed.source", f"{source!r} doesn't start with https://")
    return Dispute(reason, source)


def _sources(value: object, cve_id: str) -> list[str]:
    sources = _strs(value, "sources")
    if not sources:
        raise _Problem("sources", "a CVE needs at least one source")
    for i, source in enumerate(sources):
        if not source.startswith("https://"):
            raise _Problem(f"sources[{i}]", f"{source!r} doesn't start with https://")
        if source in sources[:i]:
            raise _Problem(f"sources[{i}]", f"{source} is listed twice")
    if NVD_PAGE.format(cve_id) not in sources:
        raise _Problem("sources", f"no link to {NVD_PAGE.format(cve_id)}")
    return sources


def _cve(table: Table, tracked: dict[str, MapRow]) -> Cve:
    """One ``[[cve]]`` table, checked on its own and against the map."""
    _keys(table, "", CVE_KEYS, CVE_OPTIONAL)
    cve_id = _str(table["id"], "id")
    if not CVE_ID.fullmatch(cve_id):
        raise _Problem("id", f"{cve_id!r} isn't CVE-, a year, - and 4 or more digits")
    library = _str(table["library"], "library")
    row = tracked.get(library)
    if row is None:
        raise _Problem("library", f"{library!r} isn't a library the map tracks")
    if row.cpe == NO_CPE:
        raise _Problem("library", f"{library!r} has cpe none in the library map")
    published = _date(table["published"], "published")
    if published < EARLIEST:
        raise _Problem("published", f"{published} is before {EARLIEST}")
    component = _str(table["component"], "component")
    if component not in COMPONENTS:
        raise _Problem("component", f"{component!r} isn't library or tool")
    tool = None
    if component == "tool":
        if "tool" not in table:
            raise _Problem("tool", "a tool CVE names its tool")
        tool = _str(table["tool"], "tool")
    elif "tool" in table:
        raise _Problem("tool", "a library CVE has no tool")
    introduced = _str(table["introduced"], "introduced")
    if introduced != UNKNOWN and not COMMIT.fullmatch(introduced):
        raise _Problem(
            "introduced",
            f"{introduced!r} is neither {UNKNOWN} nor a commit: "
            "40 lowercase hex digits",
        )
    duplicates = _strs(table.get("duplicates", []), "duplicates")
    for i, duplicate in enumerate(duplicates):
        if not CVE_ID.fullmatch(duplicate):
            raise _Problem(f"duplicates[{i}]", f"{duplicate!r} isn't a CVE ID")
        if duplicate in duplicates[:i]:
            raise _Problem(f"duplicates[{i}]", f"{duplicate} is listed twice")
    disputed = _dispute(table["disputed"]) if "disputed" in table else None
    sources = _sources(table["sources"], cve_id)
    severity = [
        _severity(t, f"severity[{i}]")
        for i, t in enumerate(_tables(table.get("severity", []), "severity"))
    ]
    if not any(s.label in IN_SCOPE for s in severity):
        raise _Problem("severity", f"no score is labeled {' or '.join(IN_SCOPE)}")
    tags = tag_matcher(row.tags)
    fixes = [
        _fix(t, f"fix[{i}]", tags, row.tags)
        for i, t in enumerate(_tables(table.get("fix", []), "fix"))
    ]
    seen = {introduced} - {UNKNOWN}
    for i, fix in enumerate(fixes):
        for j, commit in enumerate(fix.commits):
            if commit in seen:
                raise _Problem(
                    f"fix[{i}].commits[{j}]", f"{commit} appears twice in the row"
                )
            seen.add(commit)
    return Cve(
        cve_id,
        library,
        published,
        component,
        tool,
        introduced,
        tuple(duplicates),
        disputed,
        tuple(sources),
        tuple(severity),
        tuple(fixes),
    )


def _label(table: Table, index: int) -> str:
    """The CVE and library a ``[[cve]]`` table names, or its index."""
    cve_id, library = table.get("id"), table.get("library")
    label = cve_id if type(cve_id) is str and cve_id else f"cve[{index}]"
    return f"{label} {library}" if type(library) is str and library else label


def _between(cves: list[Cve], path: Path) -> None:
    """Rejections that compare rows: an id and library listed twice, and a
    duplicate that is a row's id or is listed for two CVEs."""
    ids = {cve.id for cve in cves}
    seen: set[tuple[str, str]] = set()
    duplicate_of: dict[str, str] = {}
    for cve in cves:
        where = f"{path}: {cve.id} {cve.library}"
        if (cve.id, cve.library) in seen:
            raise CveTableError(f"{where}: id: listed twice for {cve.library}")
        seen.add((cve.id, cve.library))
        for i, duplicate in enumerate(cve.duplicates):
            if duplicate in ids:
                raise CveTableError(
                    f"{where}: duplicates[{i}]: {duplicate} is also a row's id"
                )
            # A CVE listed for two libraries lists its duplicates in both rows.
            other = duplicate_of.setdefault(duplicate, cve.id)
            if other != cve.id:
                raise CveTableError(
                    f"{where}: duplicates[{i}]: {duplicate} is listed twice, "
                    f"also as a duplicate of {other}"
                )


def load_cve_table(path: Path, rows: list[MapRow]) -> list[Cve]:
    """Read and validate the CVE table against the loaded map's rows,
    keeping its CVEs in order."""
    try:
        with path.open("rb") as f:
            document = tomllib.load(f)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise CveTableError(f"{path}: {exc}") from exc
    unknown = [key for key in document if key != "cve"]
    if unknown:
        raise CveTableError(f"{path}: {unknown[0]}: unknown key")
    # A library's rows agree on cpe and tags, so any one of them will do.
    tracked = {row.library: row for row in rows if row.library != SKIP}
    cves: list[Cve] = []
    try:
        tables = _tables(document.get("cve", []), "cve")
    except _Problem as problem:
        raise CveTableError(f"{path}: {problem.field}: {problem.message}") from None
    for index, table in enumerate(tables):
        try:
            cves.append(_cve(table, tracked))
        except _Problem as problem:
            raise CveTableError(
                f"{path}: {_label(table, index)}: {problem.field}: {problem.message}"
            ) from None
    _between(cves, path)
    return cves
