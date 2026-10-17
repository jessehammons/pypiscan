"""The fingerprint report: every `.libs/` file, and each library its prefix
maps to, with the version and its basis, or why there is none.

See README "How a scan runs" (phase 08) and roadmap 4.5. ``report`` is a pure
function of phases 01 to 05, 07 and 08's lines, the library map's rows and
the list of ambiguous versions (roadmap 4.7); ``scan`` reads the files and
writes the result as ``fingerprint-report.md``.
"""

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import cast

from pypiscan.library_map import SKIP, Ambiguous, MapRow
from pypiscan.package_list import Package

Line = Mapping[str, object]

INTRO = """\
Every version below is a signal for deciding whether a CVE might be worth
investigating, not a conclusion. Its basis says which signal it rests on;
see "How versions are identified" in the README.
"""
NONE = "—"
FINGERPRINT = "08-fingerprint"
HEADER = "| file | library | version | basis | note |\n|---|---|---|---|---|"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _row(*cells: str) -> str:
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def _recorded(record: Line, ambiguous: Ambiguous) -> tuple[str, str, str]:
    """Version, basis and note for a library with a phase 08 record."""
    version, basis = record["version"], str(record["basis"])
    notes: list[str] = []
    if version is None:
        notes.append("matches disagree")
    elif record["conflict"]:
        notes.append("conflict")
    if basis == "bare_version":
        notes.append("needs another source")
    others = ambiguous.get(str(record["library"]), {}).get(str(version), [])
    if version is not None and others:
        notes.append(f"ambiguous: may also be {' or '.join(others)}")
    if version is None:
        return NONE, NONE, "; ".join(notes)
    return str(version), basis, "; ".join(notes)


def _has_recognizers(line: Line | None, prefix: str) -> bool:
    """Whether phase 07 listed recognizers for this library under ``prefix``."""
    if line is None or line["status"] != "ok":
        return False
    entries = cast(list[Mapping[str, str]], line["recognizers"])
    return any(entry["prefix"] == prefix for entry in entries)


def _stopped(package: str, line: Line, part_1: Mapping[str, Mapping[str, Line]]) -> str:
    """``<status> at <phase>: <reason>`` for a package phase 08 didn't scan.

    A skipped line's reason names the phase where the package's line first
    wasn't ok; that phase's line gives the reason. Any other reason is phase
    08's own.
    """
    phase = str(line["reason"])
    if phase in part_1:
        line = part_1[phase][package]
    else:
        phase = FINGERPRINT
    return f"{line['status']} at {phase}: {_cell(str(line['reason']))}"


def _section(
    package: Package,
    part_1: Mapping[str, Mapping[str, Line]],
    fingerprints: Line,
    recognizers: Mapping[str, Line],
    by_prefix: Mapping[str, list[str]],
    ambiguous: Ambiguous,
) -> list[str]:
    out = [f"## {package.name} {package.version}", ""]
    if fingerprints["status"] != "ok":
        out.append(_stopped(package.name, fingerprints, part_1))
        return out
    out += [f"`{fingerprints['wheel']}`", ""]
    libraries = part_1.get("05-libraries", {}).get(package.name) or {}
    files = cast(list[Mapping[str, str]], libraries.get("libraries") or [])
    if not files:
        out.append("No .libs/ files.")
        return out
    records = {
        (str(r["path"]), str(r["library"])): r
        for r in cast(list[Line], fingerprints["records"])
    }
    out.append(HEADER)
    for found in files:
        name = PurePosixPath(found["path"]).name
        for library in by_prefix.get(found["prefix"], []):
            record = records.get((found["path"], library))
            if library == SKIP:
                cells = (NONE, NONE, "not tracked")
            elif record is not None:
                cells = _recorded(record, ambiguous)
            elif _has_recognizers(recognizers.get(library), found["prefix"]):
                cells = (NONE, NONE, "not detected")
            else:
                cells = (NONE, NONE, "no recognizer")
            out.append(_row(name, library, *cells))
    return out


def report(
    packages: Sequence[Package],
    part_1: Mapping[str, Mapping[str, Line]],
    recognizers: Mapping[str, Line],
    fingerprints: Mapping[str, Line],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
) -> str:
    """The report's text, from phases 01 to 05's lines keyed by phase and
    package name, phase 08's keyed by package name, phase 07's keyed by
    library, the map's rows and the list of ambiguous versions."""
    by_prefix: dict[str, list[str]] = {}
    for row in rows:
        names = by_prefix.setdefault(row.prefix, [])
        if row.library not in names:
            names.append(row.library)
    out = [INTRO]
    for package in packages:
        out += _section(
            package,
            part_1,
            fingerprints[package.name],
            recognizers,
            by_prefix,
            ambiguous,
        )
        out.append("")
    return "\n".join(out)
