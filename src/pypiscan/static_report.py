"""The static discovery report: unconfirmed candidates for statically linked
libraries in binaries outside `.libs/`, and those binaries' templates.

See README "The static discovery report" and roadmap T.1. ``report`` is a
pure function of phases 01 to 05, 08, 09 and 10's lines, the library map's
rows and the list of ambiguous versions; ``scan`` reads the files and writes
the result as ``static-report.md``. Phases other than 04, 05 and 10 only
show where a package stopped.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast

from pypiscan.fingerprint_report import NONE, ambiguous_note, row, stopped
from pypiscan.library_map import Ambiguous, MapRow
from pypiscan.library_report import TEMPLATE_LIMIT, code, count
from pypiscan.noise import usable
from pypiscan.package_list import Package
from pypiscan.wheel_strings import BinaryStrings

Line = Mapping[str, object]

STATIC = "10-static"
LABEL = "unconfirmed static candidate"
HEADER_RISK = "header string risk"
HEADERS = (".h", ".h.in")
INTRO = """\
A candidate is a string in a binary outside `.libs/`, mostly an extension
module, that a library map recognizer or the zlib detector matched. It is a
measurement for choosing which statically linked libraries to detect, not a
fingerprint record and not a finding. A candidate marked header string risk
matches a string from a public header, which shows what a binary was
compiled against, not that it contains the library.
"""
TABLE = (
    "| member | library | version | kind | string | note |\n|---|---|---|---|---|---|"
)


def _header_rows(rows: Sequence[MapRow]) -> set[tuple[str, str, str]]:
    """(library, kind, pattern) of each map row whose identity_file is a
    header."""
    return {
        (r.library, r.kind, r.pattern)
        for r in rows
        if r.identity_file.endswith(HEADERS)
    }


def _note(
    candidate: Line, headers: set[tuple[str, str, str]], ambiguous: Ambiguous
) -> str:
    library, version = str(candidate["library"]), candidate["version"]
    notes = [LABEL]
    if (library, candidate["kind"], candidate["pattern"]) in headers:
        notes.append(HEADER_RISK)
    if version is None:
        notes.append("matches disagree")
    elif note := ambiguous_note(library, str(version), ambiguous):
        notes.append(note)
    return "; ".join(notes)


@dataclass
class _Template:
    wheels: set[str] = field(default_factory=set[str])
    binaries: int = 0
    # The first example: its text, wheel and member.
    example: tuple[str, str, str] = ("", "", "")
    packages: list[str] = field(default_factory=list[str])


def _templates(
    packages: Sequence[Package],
    strings: Mapping[str, Line],
    static: Mapping[str, Line],
) -> list[tuple[str, _Template]]:
    """Templates of the usable strings in phase 10's binaries, in packages
    whose phase 10 line is ok, ranked by wheels, binaries, then text."""
    found: dict[str, _Template] = {}
    for package in packages:
        line = static[package.name]
        if line["status"] != "ok":
            continue
        wheel = str(line["wheel"])
        paths = {b["path"] for b in cast(list[Mapping[str, str]], line["binaries"])}
        records = cast(list[BinaryStrings], strings[package.name]["records"])
        for binary in records:
            if binary["path"] not in paths:
                continue
            seen: set[str] = set()
            for s in filter(usable, binary["strings"]):
                template = s["template"][:TEMPLATE_LIMIT]
                entry = found.get(template)
                if entry is None:
                    example = (s["text"][:TEMPLATE_LIMIT], wheel, binary["path"])
                    entry = found[template] = _Template(example=example)
                if template not in seen:
                    seen.add(template)
                    entry.binaries += 1
                entry.wheels.add(wheel)
                if package.name not in entry.packages:
                    entry.packages.append(package.name)
    return sorted(
        found.items(), key=lambda t: (-len(t[1].wheels), -t[1].binaries, t[0])
    )


def report(
    packages: Sequence[Package],
    earlier: Mapping[str, Mapping[str, Line]],
    static: Mapping[str, Line],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
) -> str:
    """The report's text, from phases 01 to 05, 08 and 09's lines keyed by
    phase and package name, phase 10's keyed by package name, the map's rows
    and the list of ambiguous versions."""
    headers = _header_rows(rows)
    scanned = [p for p in packages if static[p.name]["status"] == "ok"]
    stops: Counter[str] = Counter()
    for package in packages:
        line = static[package.name]
        if line["status"] != "ok":
            phase = str(line["reason"])
            stops[phase if phase in earlier else STATIC] += 1
    binaries = 0
    by_library: Counter[str] = Counter()
    by_kind: Counter[str] = Counter()
    risky = 0
    sections: list[str] = []
    for package in packages:
        line = static[package.name]
        sections += ["", f"### {package.name} {package.version}", ""]
        if line["status"] != "ok":
            sections.append(stopped(package.name, line, earlier, STATIC))
            continue
        found = cast(list[Line], line["binaries"])
        binaries += len(found)
        table: list[str] = []
        for binary in found:
            for candidate in cast(list[Line], binary["candidates"]):
                note = _note(candidate, headers, ambiguous)
                by_library[str(candidate["library"])] += 1
                by_kind[str(candidate["kind"])] += 1
                risky += HEADER_RISK in note
                version = candidate["version"]
                table.append(
                    row(
                        str(binary["path"]),
                        str(candidate["library"]),
                        NONE if version is None else str(version),
                        str(candidate["kind"]),
                        code(str(candidate["text"])),
                        note,
                    )
                )
        sections += [
            f"`{line['wheel']}`: {count(len(found), 'binary', 'binaries')} "
            "outside `.libs/`",
            "",
        ]
        sections += [TABLE, *table] if table else ["No candidates."]
    templates = _templates(packages, earlier.get("04-strings", {}), static)

    def tally(counter: Counter[str]) -> str:
        return ", ".join(f"{k} {n}" for k, n in sorted(counter.items())) or "none"

    out = [
        "# Static discovery report",
        "",
        INTRO,
        "## Counts",
        "",
        f"- {count(len(scanned), 'package')} scanned in phase 10 of "
        f"{len(packages)}; not scanned, by the phase where they stopped: "
        f"{tally(stops)}",
        f"- {count(binaries, 'binary', 'binaries')} outside `.libs/`",
        f"- {count(sum(by_library.values()), 'candidate')}: by library, "
        f"{tally(by_library)}; by kind, {tally(by_kind)}",
        f"- {count(risky, 'candidate')} marked {HEADER_RISK}",
        f"- {count(len(templates), 'distinct template')}",
        "",
        "## Candidates",
        *sections,
        "",
        "## Templates",
        "",
        "Templates of the strings in those binaries that pass the noise "
        f"filter, cut to {TEMPLATE_LIMIT} characters, ranked by how many "
        "wheels carry them, then by how many binaries, then alphabetically.",
        "",
    ]
    for i, (template, entry) in enumerate(templates, 1):
        text, wheel, member = entry.example
        out += [
            f"{i}. {count(len(entry.wheels), 'wheel')}, "
            f"{count(entry.binaries, 'binary', 'binaries')}: {code(template)}",
            f"   - e.g. {code(text)} in `{wheel}` `{member}`",
            f"   - {', '.join(entry.packages)}",
        ]
    return "\n".join(out) + "\n"
