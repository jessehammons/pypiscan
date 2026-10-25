"""Phase 05's prefixes, the library report and the library map's TODO.

See README "How a scan runs". A prefix is a `.libs/` file's name without
auditwheel's hash and version suffix. The report groups phase 04's strings
by prefix so the maintainer can tell which upstream library each one is.
"""

import csv
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from pypiscan.library_map import COLUMNS
from pypiscan.noise import usable
from pypiscan.wheel_strings import StringRecord

TEMPLATE_LIMIT = 200

# auditwheel's hash: "-" and 8 hex digits, before the extension or, in a
# library repaired twice (numpy's libgfortran-83c28eba-468e71e5.so.5.0.0),
# before another hash.
AUDITWHEEL_HASH = re.compile(r"-[0-9a-f]{8}(?=[-.])")

Line = Mapping[str, object]


def prefix(path: str) -> str:
    """A `.libs/` member's name without auditwheel's hash and what follows it.

    ``libjpeg-1a2b3c4d.so.62.4.0`` gives ``libjpeg``. A name with no such
    hash is cut at its first ``.so``.
    """
    name = path.rpartition("/")[2]
    match = AUDITWHEEL_HASH.search(name)
    if match:
        return name[: match.start()]
    end = name.find(".so")
    return name[:end] if end > 0 else name


def libraries(inspect_records: Iterable[Mapping[str, object]]) -> list[Line]:
    """Each `.libs/` record from phase 03 as its path and prefix."""
    return [
        {"path": record["path"], "prefix": prefix(cast(str, record["path"]))}
        for record in inspect_records
        if record["in_libs_dir"]
    ]


@dataclass
class _Prefix:
    name: str
    packages: list[str] = field(default_factory=list[str])
    files: int = 0
    # Template -> the packages whose files carry it, and its first example.
    wheels: dict[str, set[str]] = field(default_factory=dict[str, set[str]])
    examples: dict[str, str] = field(default_factory=dict[str, str])


def _prefixes(
    packages: Sequence[str], lines: Mapping[str, Mapping[str, Line]]
) -> list[_Prefix]:
    """Every prefix in phase 05's ok lines, most widely carried first."""
    found: dict[str, _Prefix] = {}
    for name in packages:
        line = lines[name].get("05-libraries")
        if line is None or line["status"] != "ok":
            continue
        # The manual step passes phase 05's lines alone.
        records = lines[name].get("04-strings", {}).get("records", [])
        strings = {
            cast(str, record["path"]): cast(list[StringRecord], record["strings"])
            for record in cast(list[Line], records)
        }
        for library in cast(list[dict[str, str]], line["libraries"]):
            entry = found.setdefault(library["prefix"], _Prefix(library["prefix"]))
            entry.files += 1
            if name not in entry.packages:
                entry.packages.append(name)
            for string in filter(usable, strings.get(library["path"], [])):
                template = string["template"][:TEMPLATE_LIMIT]
                entry.wheels.setdefault(template, set()).add(name)
                entry.examples.setdefault(template, string["text"][:TEMPLATE_LIMIT])
    return sorted(found.values(), key=lambda p: (-len(p.packages), -p.files, p.name))


def code(text: str) -> str:
    """``text`` as a Markdown code span, whatever backticks it contains."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def count(n: int, noun: str, plural: str = "") -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {plural or noun + 's'}"


def report(packages: Sequence[str], lines: Mapping[str, Mapping[str, Line]]) -> str:
    """The library report as Markdown, readable on a phone."""
    found = _prefixes(packages, lines)
    carriers = {name for entry in found for name in entry.packages}
    out = [
        "# Library report",
        "",
        f"{count(len(packages), 'package')} scanned, "
        f"{len(carriers)} with `.libs/` shared libraries, "
        f"{count(len(found), 'prefix', 'prefixes')}, ordered by how many "
        "wheels carry them.",
        "",
        "Templates use only strings in data sections that pass the noise "
        f"filter, cut to {TEMPLATE_LIMIT} characters, with one real example "
        "each. Every template is listed, ranked by how many wheels carry it, "
        "ties alphabetical.",
        "",
        "## Prefixes",
        "",
    ]
    out += [
        f"{i}. {code(entry.name)}: {count(len(entry.packages), 'wheel')}, "
        f"{count(entry.files, 'file')}"
        for i, entry in enumerate(found, 1)
    ]
    for i, entry in enumerate(found, 1):
        ranked = sorted(entry.wheels, key=lambda t: (-len(entry.wheels[t]), t))
        out += [
            "",
            f"## {i}. {code(entry.name)}: {count(len(ranked), 'template')}",
            "",
            f"{count(len(entry.packages), 'wheel')}, "
            f"{count(entry.files, 'file')}: {', '.join(entry.packages)}",
            "",
        ]
        if not ranked:
            out.append("No usable strings.")
        for j, template in enumerate(ranked, 1):
            wheels = count(len(entry.wheels[template]), "wheel")
            out += [
                f"{j}. {wheels}: {code(template)}",
                f"   - e.g. {code(entry.examples[template])}",
            ]
    return "\n".join(out) + "\n"


def todo(
    packages: Sequence[str], lines: Mapping[str, Mapping[str, Line]], listed: set[str]
) -> list[str]:
    """Phase 05's prefixes that the library map doesn't list, in report order."""
    return [e.name for e in _prefixes(packages, lines) if e.name not in listed]


def write_todo(path: Path, prefixes: Sequence[str]) -> None:
    """Write ``library-map-todo.csv``: map rows with only the prefix filled in."""
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(COLUMNS)
        writer.writerows([p] + [""] * (len(COLUMNS) - 1) for p in prefixes)
