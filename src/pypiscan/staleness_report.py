"""The staleness report: how far each bundled library's version lagged its
upstream's releases on the day the wheel was uploaded.

See README "The staleness report" (roadmap S.1). ``report`` is a pure function
of phases 01 to 05, 06, 08 and, once it is finished, 10's lines, the library
map's rows, the list of ambiguous versions and the lines' ends of life
(roadmap S.4); ``scan`` writes the result as ``staleness-report.md``. Rows
and counts are kept apart by linkage (roadmap T.3). It names no CVE: it is a
measurement, not a finding.
"""

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import PurePosixPath
from typing import cast

from pypiscan.fingerprint import LINKAGES, Linkage, linkage_of
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
# Phase 10's lines from this schema_version on hold static_lib records.
STATIC_RECORDS = 2
STATIC = "10-static"
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
    "| file | linkage | library | version | basis | note | newest at upload "
    "| newer | days behind | line | line status | newest on line at upload "
    "| days behind on line |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|"
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
    linkage: Linkage,
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
        return row(name, linkage, library, version, basis, note, "skipped", *blank)
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
        joined = "; ".join(notes)
        return row(name, linkage, library, version, basis, joined, shown, *blank)
    extra, newest, newer, behind, *on_line = result
    notes += [extra] if extra else []
    counts[f"{'current' if newer == '0' else 'behind'}: {basis}"] += 1
    status, line_behind = on_line[1], on_line[3]
    counts[f"line status: {'EOL' if status.startswith('EOL') else status}"] += 1
    counts[f"{'current' if line_behind == '0' else 'behind'} on line: {basis}"] += 1
    return row(
        name,
        linkage,
        library,
        version,
        basis,
        "; ".join(notes),
        newest,
        newer,
        behind,
        *on_line,
    )


type Context = tuple[
    Mapping[str, Line],
    Mapping[str, list[str]],
    set[tuple[str, str]],
    Ambiguous,
    tuple[Mapping[str, str], LineEol],
]


def _static_rows(
    package: Package,
    static: Line,
    part_1: Mapping[str, Mapping[str, Line]],
    uploaded: date,
    context: Context,
    counts: Counter[str],
) -> tuple[list[str], str | None]:
    """A package's static_lib rows from its phase 10 line, each named by its
    member, or why there are none."""
    if static["status"] != "ok":
        counts["phase 10 not ok"] += 1
        return [], stopped(package.name, static, part_1, STATIC)
    upstream, _, _, ambiguous, lines = context
    found: list[str] = []
    for binary in cast(list[Line], static["binaries"]):
        for record in cast(list[Line], binary["fingerprints"]):
            if linkage_of(record) != "static_lib":
                continue
            library = str(record["library"])
            found.append(
                _row(
                    str(binary["path"]),
                    "static_lib",
                    library,
                    record,
                    True,
                    upstream.get(library),
                    uploaded,
                    ambiguous,
                    lines,
                    counts,
                )
            )
    return found, None


def _section(
    package: Package,
    part_1: Mapping[str, Mapping[str, Line]],
    fingerprints: Line,
    static: Line | None,
    context: Context,
    counts: Mapping[Linkage, Counter[str]],
) -> list[str]:
    upstream, by_prefix, recognized, ambiguous, lines = context
    out = [f"## {package.name} {package.version}", ""]
    if fingerprints["status"] != "ok":
        out.append(stopped(package.name, fingerprints, part_1, FINGERPRINT))
        return out
    uploaded = upload_day(part_1["01-resolve"][package.name])
    out += [f"`{fingerprints['wheel']}`, uploaded {uploaded}", ""]
    libraries = part_1["05-libraries"][package.name]
    files = cast(list[Mapping[str, str]], libraries.get("libraries") or [])
    contains = {
        (str(r["path"]), str(r["library"])): r
        for r in cast(list[Line], fingerprints["records"])
        if r["relation"] == "contains" and linkage_of(r) == "shared_lib"
    }
    shared: list[str] = []
    for found in files:
        name = PurePosixPath(found["path"]).name
        prefix = found["prefix"]
        for library in by_prefix.get(prefix, []):
            shared.append(
                _row(
                    name,
                    "shared_lib",
                    library,
                    contains.get((found["path"], library)),
                    (prefix, library) in recognized,
                    upstream.get(library),
                    uploaded,
                    ambiguous,
                    lines,
                    counts["shared_lib"],
                )
            )
    static_rows, why = (
        ([], None)
        if static is None
        else _static_rows(
            package, static, part_1, uploaded, context, counts["static_lib"]
        )
    )
    if not files:
        out.append("No .libs/ files.")
    if shared or static_rows:
        out += [""] if not files else []
        out += [HEADER, *shared, *static_rows]
    if why is not None:
        out += ["", f"No static rows: {why}"]
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


def _summary(c: Counter[str], linkage: Linkage) -> list[str]:
    summary = [
        f"### {linkage}",
        "",
        f"- Compared: current {_split(c, 'current')}; "
        f"behind {_split(c, 'behind')}. By basis.",
        f"- On the bundled version's line: current {_split(c, 'current on line')}; "
        f"behind {_split(c, 'behind on line')}. By basis.",
        f"- Compared, by line status: {_split(c, 'line status')}.",
        f"- Not compared: {_split(c, 'not compared')}. By reason.",
    ]
    if linkage == "shared_lib":
        summary.append(f"- Files whose prefix is marked skip: {c['skipped']}.")
    else:
        summary.append(
            f"- Packages whose phase 10 line isn't ok: {c['phase 10 not ok']}."
        )
    return [*summary, ""]


def _static_problem(static: Mapping[str, Line] | None) -> str | None:
    """Why static rows are absent, or None."""
    if static is None:
        return "Static rows are absent: phase 10 isn't finished."
    if any(
        cast(int, line["schema_version"]) < STATIC_RECORDS for line in static.values()
    ):
        return (
            "Static rows are absent: phase 10's lines predate static_lib "
            "records; rerun from phase 10."
        )
    return None


def report(
    packages: Sequence[Package],
    part_1: Mapping[str, Mapping[str, Line]],
    upstream: Mapping[str, Line],
    fingerprints: Mapping[str, Line],
    static: Mapping[str, Line] | None,
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
    line_eol: LineEol,
) -> str:
    """The report's text, from phases 01 to 05's lines keyed by phase and
    package name, phase 06's keyed by library, phases 08 and 10's keyed by
    package name (10's ``None`` when it isn't finished), the map's rows, the
    list of ambiguous versions and the lines' ends of life."""
    context: Context = (
        upstream,
        libraries_by_prefix(rows),
        {(r.prefix, r.library) for r in rows if r.kind},
        ambiguous,
        ({r.library: r.line for r in rows}, line_eol),
    )
    absent = _static_problem(static)
    counts: dict[Linkage, Counter[str]] = {k: Counter() for k in LINKAGES}
    sections: list[str] = []
    for package in packages:
        sections += _section(
            package,
            part_1,
            fingerprints[package.name],
            None if absent or static is None else static[package.name],
            context,
            counts,
        )
        sections.append("")
    summary: list[str] = []
    if any(_not_compared(line) == RERUN for line in upstream.values()):
        summary.append(
            "- Phase 06's lines predate tag dates or release flags, so their "
            f"libraries aren't compared: {RERUN}."
        )
    if absent:
        summary.append(f"- {absent}")
    # Per package, so once above the per-linkage blocks.
    not_scanned = sum(fingerprints[p.name]["status"] != "ok" for p in packages)
    summary += [f"- Packages not scanned: {not_scanned}.", ""]
    # One block per linkage present, so the .libs/ counts stay comparable
    # with reports from before static rows.
    present: list[Linkage] = ["shared_lib"] if absent else ["shared_lib", "static_lib"]
    for linkage in present:
        summary += _summary(counts[linkage], linkage)
    return "\n".join([INTRO, "## Counts", "", *summary, *sections])
