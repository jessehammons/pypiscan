"""The staleness report: how far each bundled library's version lagged its
upstream's releases on the day the wheel was uploaded.

See README "The staleness report" (roadmap S.1). ``report`` is a pure function
of phases 01 to 05, 06 and 08's lines, the library map's rows and the list of
ambiguous versions; ``scan`` writes the result as ``staleness-report.md``. It
names no CVE: it is a measurement, not a finding.
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
from pypiscan.library_map import SKIP, Ambiguous, MapRow
from pypiscan.package_list import Package

# Phase 06's lines from this schema_version on list each tag's date.
DATED = 2
RERUN = "rerun from phase 06"
NO_TAG = "no release tag for the version"
RELEASE = re.compile(r"\d+(\.\d+)*")
INTRO = """\
# Staleness report

How far each bundled library's version lagged its upstream's releases on
the day the wheel was uploaded, counting only releases tagged by then. It
is a measurement, not a finding, and every version is shown with the basis
it rests on; see "The staleness report" in the README.
"""
HEADER = (
    "| file | library | version | basis | note | newest at upload "
    "| newer | days behind |\n|---|---|---|---|---|---|---|---|"
)

type Key = tuple[int, ...]


def releases(upstream: Line) -> dict[Key, tuple[str, date]]:
    """Phase 06's release tags as version, keyed by the version as integers,
    with the earliest date a tag gives it."""
    found: dict[Key, tuple[str, date]] = {}
    for tag in cast(list[Mapping[str, str]], upstream["tags"]):
        version = tag["version"]
        if RELEASE.fullmatch(version):
            key = tuple(int(n) for n in version.split("."))
            day = date.fromisoformat(tag["date"])
            if key not in found or day < found[key][1]:
                found[key] = (version, day)
    return found


def upload_day(resolved: Line) -> date:
    """Phase 01's upload time as a day in UTC."""
    return datetime.fromisoformat(str(resolved["upload_time"])).astimezone(UTC).date()


def _not_compared(upstream: Line) -> str | None:
    """Why phase 06's line leaves a library uncompared, or None."""
    if cast(int, upstream["schema_version"]) < DATED:
        return RERUN
    if upstream["status"] == "skipped":
        return str(upstream["reason"])
    if upstream["status"] != "ok":
        return f"phase 06 {upstream['status']}"
    return None


def staleness(
    version: str,
    others: Sequence[str],
    upstream: Line,
    uploaded: date,
) -> tuple[str, str, str, str] | str:
    """Note, newest release at upload, newer releases and days behind, or the
    reason the version isn't compared. An ambiguous version is read as the
    newest release it may be."""
    found = releases(upstream)
    bundled = [
        key
        for v in (version, *others)
        if RELEASE.fullmatch(v)
        and (key := tuple(int(n) for n in v.split("."))) in found
    ]
    if not bundled:
        return NO_TAG
    read_as = max(bundled)
    newer = sorted(
        (key, day)
        for key, (_, day) in found.items()
        if key > read_as and day <= uploaded
    )
    note = f"read as {found[read_as][0]}" if others else ""
    if not newer:
        version_, day = found[read_as]
        return note, f"{version_} ({day})", "0", "0"
    newest, newest_day = found[newer[-1][0]]
    behind = (uploaded - min(day for _, day in newer)).days
    return note, f"{newest} ({newest_day})", str(len(newer)), str(behind)


def _row(
    name: str,
    library: str,
    record: Line | None,
    recognized: bool,
    upstream: Line | None,
    uploaded: date,
    ambiguous: Ambiguous,
    counts: Counter[str],
) -> str:
    version, basis, note = cells(library, record, recognized, ambiguous)
    if library == SKIP:
        counts["skipped"] += 1
        return row(name, library, version, basis, note, "skipped", NONE, NONE)
    notes = [note] if note else []
    if basis == "bare_version":
        notes.insert(0, "hint")
    result: tuple[str, str, str, str] | str
    if record is None or record["version"] is None:
        result = missing(library, record, recognized)
    elif upstream is None:
        result = "not in phase 06"
    elif why := _not_compared(upstream):
        result = why
    else:
        others = ambiguous.get(library, {}).get(version, [])
        result = staleness(version, others, upstream, uploaded)
    if isinstance(result, str):
        counts[f"not compared: {result}"] += 1
        shown = f"not compared: {result}"
        return row(name, library, version, basis, "; ".join(notes), shown, NONE, NONE)
    extra, newest, newer, behind = result
    notes += [extra] if extra else []
    counts[f"{'current' if newer == '0' else 'behind'}: {basis}"] += 1
    return row(name, library, version, basis, "; ".join(notes), newest, newer, behind)


def _section(
    package: Package,
    part_1: Mapping[str, Mapping[str, Line]],
    fingerprints: Line,
    upstream: Mapping[str, Line],
    by_prefix: Mapping[str, list[str]],
    recognized: set[tuple[str, str]],
    ambiguous: Ambiguous,
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
) -> str:
    """The report's text, from phases 01 to 05's lines keyed by phase and
    package name, phase 06's keyed by library, phase 08's keyed by package
    name, the map's rows and the list of ambiguous versions."""
    by_prefix = libraries_by_prefix(rows)
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
            counts,
        )
        sections.append("")
    c = counts
    summary = [
        f"- Compared: current {_split(c, 'current')}; "
        f"behind {_split(c, 'behind')}. By basis.",
        f"- Not compared: {_split(c, 'not compared')}. By reason.",
        f"- Files whose prefix is marked skip: {c['skipped']}.",
        f"- Packages not scanned: {c['packages not scanned']}.",
    ]
    if any(_not_compared(line) == RERUN for line in upstream.values()):
        summary.insert(
            0,
            "- Phase 06's lines predate tag dates, so their libraries aren't "
            f"compared: {RERUN}.",
        )
    return "\n".join([INTRO, "## Counts", "", *summary, "", *sections])
