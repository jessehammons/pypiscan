"""The staleness report: how far each bundled library's version lagged its
upstream's releases on the day the wheel was uploaded.

See README "The staleness report" (roadmap S.1). ``report`` is a pure function
of phases 01 to 05, 06 and 08's lines, the library map's rows, the list of
ambiguous versions and the lines' ends of life (roadmap S.4); ``scan``
writes the result as ``staleness-report.md``. It names no CVE: it is a
measurement, not a finding.
"""

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import PurePosixPath
from typing import cast

from pypiscan.fingerprint_report import (
    FINGERPRINT,
    NONE,
    Line,
    cells,
    libraries_by_prefix,
    missing,
    row,
    stopped,
)
from pypiscan.library_map import (
    MAINTAINED,
    SINGLE_LINE,
    SKIP,
    Ambiguous,
    LineEol,
    MapRow,
    release_line,
)
from pypiscan.package_list import Package

# Phase 06's lines from this schema_version on list each tag's date and
# whether it is a release.
FLAGGED = 3
RERUN = "rerun from phase 06"
NO_TAG = "no release tag for the version"
# A version that can be ordered as a tuple of integers.
DOTTED = re.compile(r"\d+(\.\d+)*")
INTRO = """\
# Staleness report

How far each bundled library's version lagged its upstream's releases on
the day the wheel was uploaded, counting only releases tagged by then. It
is a measurement, not a finding, and every version is shown with the basis
it rests on; see "The staleness report" in the README.
"""
HEADER = (
    "| file | library | version | basis | note | newest at upload "
    "| newer | days behind | line | line status | newest on line at upload "
    "| days behind on line |\n|---|---|---|---|---|---|---|---|---|---|---|---|"
)
# The line cell of a library that maintains one line.
ALL = "all"

type Key = tuple[int, ...]


def releases(upstream: Line) -> dict[Key, tuple[str, date]]:
    """Phase 06's tags marked as releases, as version, keyed by the version
    as integers, with the earliest date a tag gives it."""
    found: dict[Key, tuple[str, date]] = {}
    for tag in cast(list[Mapping[str, object]], upstream["tags"]):
        if tag["release"] is True:
            version = str(tag["version"])
            key = tuple(int(n) for n in version.split("."))
            day = date.fromisoformat(str(tag["date"]))
            if key not in found or day < found[key][1]:
                found[key] = (version, day)
    return found


def upload_day(resolved: Line) -> date:
    """Phase 01's upload time as a day in UTC."""
    return datetime.fromisoformat(str(resolved["upload_time"])).astimezone(UTC).date()


def _not_compared(upstream: Line) -> str | None:
    """Why phase 06's line leaves a library uncompared, or None."""
    if cast(int, upstream["schema_version"]) < FLAGGED:
        return RERUN
    if upstream["status"] == "skipped":
        return str(upstream["reason"])
    if upstream["status"] != "ok":
        return f"phase 06 {upstream['status']}"
    return None


def _lag(
    found: Mapping[Key, tuple[str, date]], read_as: Key, uploaded: date
) -> tuple[str, str, str]:
    """Newest release at upload, newer releases and days behind, among
    ``found``."""
    newer = sorted(
        (key, day)
        for key, (_, day) in found.items()
        if key > read_as and day <= uploaded
    )
    if not newer:
        version, day = found[read_as]
        return f"{version} ({day})", "0", "0"
    newest, newest_day = found[newer[-1][0]]
    behind = (uploaded - min(day for _, day in newer)).days
    return f"{newest} ({newest_day})", str(len(newer)), str(behind)


def line_status(eol: str | None, uploaded: date) -> str:
    """A line's status on the upload day, from its eol in the list of lines'
    ends of life, or ``None`` when the list leaves it out."""
    if eol is None:
        return "unknown"
    if eol == MAINTAINED or date.fromisoformat(eol) > uploaded:
        return "maintained"
    return f"EOL {eol}"


def staleness(
    version: str,
    others: Sequence[str],
    upstream: Line,
    uploaded: date,
    line: str = SINGLE_LINE,
    eols: Mapping[str, str] | None = None,
) -> tuple[str, ...] | str:
    """Note, newest release at upload, newer releases, days behind, line,
    line status, newest on the line at upload and days behind on the line,
    or the reason the version isn't compared. An ambiguous version is read
    as the newest release it may be. ``line`` is the library's line column
    and ``eols`` its lines' ends of life."""
    found = releases(upstream)
    bundled = [
        key
        for v in (version, *others)
        if DOTTED.fullmatch(v) and (key := tuple(int(n) for n in v.split("."))) in found
    ]
    if not bundled:
        return NO_TAG
    read_as = max(bundled)
    note = f"read as {found[read_as][0]}" if others else ""
    newest, newer, behind = _lag(found, read_as, uploaded)
    on_line = release_line(found[read_as][0], line)
    if on_line is None:
        return note, newest, newer, behind, ALL, "single line", newest, behind
    n = len(on_line.split("."))
    same = {k: v for k, v in found.items() if k[:n] == read_as[:n]}
    line_newest, _, line_behind = _lag(same, read_as, uploaded)
    status = line_status((eols or {}).get(on_line), uploaded)
    return note, newest, newer, behind, on_line, status, line_newest, line_behind


def _row(
    name: str,
    library: str,
    record: Line | None,
    recognized: bool,
    upstream: Line | None,
    uploaded: date,
    ambiguous: Ambiguous,
    lines: tuple[Mapping[str, str], LineEol],
    counts: Counter[str],
) -> str:
    version, basis, note = cells(library, record, recognized, ambiguous)
    blank = [NONE] * 6
    if library == SKIP:
        counts["skipped"] += 1
        return row(name, library, version, basis, note, "skipped", *blank)
    notes = [note] if note else []
    if basis == "bare_version":
        notes.insert(0, "hint")
    result: tuple[str, ...] | str
    if record is None or record["version"] is None:
        result = missing(library, record, recognized)
    elif upstream is None:
        result = "not in phase 06"
    elif why := _not_compared(upstream):
        result = why
    else:
        others = ambiguous.get(library, {}).get(version, [])
        line, eols = lines[0].get(library, SINGLE_LINE), lines[1].get(library)
        result = staleness(version, others, upstream, uploaded, line, eols)
    if isinstance(result, str):
        counts[f"not compared: {result}"] += 1
        shown = f"not compared: {result}"
        return row(name, library, version, basis, "; ".join(notes), shown, *blank)
    extra, newest, newer, behind, *on_line = result
    notes += [extra] if extra else []
    counts[f"{'current' if newer == '0' else 'behind'}: {basis}"] += 1
    status, line_behind = on_line[1], on_line[3]
    counts[f"line status: {'EOL' if status.startswith('EOL') else status}"] += 1
    counts[f"{'current' if line_behind == '0' else 'behind'} on line: {basis}"] += 1
    return row(
        name, library, version, basis, "; ".join(notes), newest, newer, behind, *on_line
    )


def _section(
    package: Package,
    part_1: Mapping[str, Mapping[str, Line]],
    fingerprints: Line,
    upstream: Mapping[str, Line],
    by_prefix: Mapping[str, list[str]],
    recognized: set[tuple[str, str]],
    ambiguous: Ambiguous,
    lines: tuple[Mapping[str, str], LineEol],
    counts: Counter[str],
) -> list[str]:
    out = [f"## {package.name} {package.version}", ""]
    if fingerprints["status"] != "ok":
        counts["packages not scanned"] += 1
        out.append(stopped(package.name, fingerprints, part_1, FINGERPRINT))
        return out
    uploaded = upload_day(part_1["01-resolve"][package.name])
    out += [f"`{fingerprints['wheel']}`, uploaded {uploaded}", ""]
    libraries = part_1["05-libraries"][package.name]
    files = cast(list[Mapping[str, str]], libraries.get("libraries") or [])
    if not files:
        out.append("No .libs/ files.")
        return out
    contains = {
        (str(r["path"]), str(r["library"])): r
        for r in cast(list[Line], fingerprints["records"])
        if r["relation"] == "contains"
    }
    out.append(HEADER)
    for found in files:
        name = PurePosixPath(found["path"]).name
        prefix = found["prefix"]
        for library in by_prefix.get(prefix, []):
            out.append(
                _row(
                    name,
                    library,
                    contains.get((found["path"], library)),
                    (prefix, library) in recognized,
                    upstream.get(library),
                    uploaded,
                    ambiguous,
                    lines,
                    counts,
                )
            )
    return out


def _split(counts: Counter[str], outcome: str) -> str:
    """The count of ``outcome`` and, in parentheses, how it splits."""
    parts = sorted(
        (key.removeprefix(f"{outcome}: "), n)
        for key, n in counts.items()
        if key.startswith(f"{outcome}: ")
    )
    total = sum(n for _, n in parts)
    return f"{total} ({', '.join(f'{k} {n}' for k, n in parts)})" if parts else "0"


def report(
    packages: Sequence[Package],
    part_1: Mapping[str, Mapping[str, Line]],
    upstream: Mapping[str, Line],
    fingerprints: Mapping[str, Line],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
    line_eol: LineEol,
) -> str:
    """The report's text, from phases 01 to 05's lines keyed by phase and
    package name, phase 06's keyed by library, phase 08's keyed by package
    name, the map's rows, the list of ambiguous versions and the lines'
    ends of life."""
    by_prefix = libraries_by_prefix(rows)
    lines = ({r.library: r.line for r in rows}, line_eol)
    recognized = {(r.prefix, r.library) for r in rows if r.kind}
    counts: Counter[str] = Counter()
    sections: list[str] = []
    for package in packages:
        sections += _section(
            package,
            part_1,
            fingerprints[package.name],
            upstream,
            by_prefix,
            recognized,
            ambiguous,
            lines,
            counts,
        )
        sections.append("")
    c = counts
    summary = [
        f"- Compared: current {_split(c, 'current')}; "
        f"behind {_split(c, 'behind')}. By basis.",
        f"- On the bundled version's line: current {_split(c, 'current on line')}; "
        f"behind {_split(c, 'behind on line')}. By basis.",
        f"- Compared, by line status: {_split(c, 'line status')}.",
        f"- Not compared: {_split(c, 'not compared')}. By reason.",
        f"- Files whose prefix is marked skip: {c['skipped']}.",
        f"- Packages not scanned: {c['packages not scanned']}.",
    ]
    if any(_not_compared(line) == RERUN for line in upstream.values()):
        summary.insert(
            0,
            "- Phase 06's lines predate tag dates or release flags, so their "
            f"libraries aren't compared: {RERUN}.",
        )
    return "\n".join([INTRO, "## Counts", "", *summary, "", *sections])
