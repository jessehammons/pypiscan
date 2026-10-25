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

from pypiscan.fingerprint import linkage_of
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


def cell(text: str) -> str:
    return text.replace("|", "\\|")


def row(*cells: str) -> str:
    return "| " + " | ".join(cell(c) for c in cells) + " |"


def ambiguous_note(library: str, version: str, ambiguous: Ambiguous) -> str:
    """``ambiguous: may also be …`` for a version the list marks, else ``""``."""
    others = ambiguous.get(library, {}).get(version, [])
    return f"ambiguous: may also be {' or '.join(others)}" if others else ""


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
    if version is not None and (
        note := ambiguous_note(str(record["library"]), str(version), ambiguous)
    ):
        notes.append(note)
    if version is None:
        return NONE, NONE, "; ".join(notes)
    return str(version), basis, "; ".join(notes)


def missing(library: str, record: Line | None, recognized: bool) -> str:
    """Why a library has no version: ``recognized`` says whether the map
    gives it recognizers under the file's prefix."""
    if library == SKIP:
        return "not tracked"
    if record is None:
        return "not detected" if recognized else "no recognizer"
    return "matches disagree"


def cells(
    library: str, record: Line | None, recognized: bool, ambiguous: Ambiguous
) -> tuple[str, str, str]:
    """Version, basis and note for a library under a file's prefix."""
    if library == SKIP or record is None:
        return NONE, NONE, missing(library, record, recognized)
    return _recorded(record, ambiguous)


def _has_recognizers(line: Line | None, prefix: str) -> bool:
    """Whether phase 07 listed recognizers for this library under ``prefix``."""
    if line is None or line["status"] != "ok":
        return False
    entries = cast(list[Mapping[str, str]], line["recognizers"])
    return any(entry["prefix"] == prefix for entry in entries)


def stopped(
    package: str, line: Line, earlier: Mapping[str, Mapping[str, Line]], own: str
) -> str:
    """``<status> at <phase>: <reason>`` for a package phase ``own`` didn't
    scan, given the earlier phases' lines keyed by phase and package.

    A skipped line's reason names the phase where the package's line first
    wasn't ok; that phase's line gives the reason. Any other reason is
    ``own``'s.
    """
    phase = str(line["reason"])
    if phase in earlier:
        line = earlier[phase][package]
    else:
        phase = own
    return f"{line['status']} at {phase}: {cell(str(line['reason']))}"


def libraries_by_prefix(rows: Sequence[MapRow]) -> dict[str, list[str]]:
    """The libraries the map gives each prefix, in map order. A detector
    row's empty prefix names no `.libs/` file, so it isn't one."""
    by_prefix: dict[str, list[str]] = {}
    for each in rows:
        if not each.prefix:
            continue
        names = by_prefix.setdefault(each.prefix, [])
        if each.library not in names:
            names.append(each.library)
    return by_prefix


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
        out.append(stopped(package.name, fingerprints, part_1, FINGERPRINT))
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
        if linkage_of(r) == "shared_lib"
    }
    out.append(HEADER)
    for found in files:
        name = PurePosixPath(found["path"]).name
        for library in by_prefix.get(found["prefix"], []):
            record = records.get((found["path"], library))
            recognized = _has_recognizers(recognizers.get(library), found["prefix"])
            out.append(
                row(name, library, *cells(library, record, recognized, ambiguous))
            )
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
    by_prefix = libraries_by_prefix(rows)
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
