"""``pypiscan wheel``: what one wheel bundles, from the scan's own phases.

Runs phases 03, 04, 05, 09 and 10 over one wheel file, in order, through
each phase's ``run``, with an ``earlier`` mapping shaped like an episode's,
and turns their lines into records.
"""

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from pypiscan.library_map import LibraryMapError, MapRow, load_library_map
from pypiscan.package_list import Package
from pypiscan.sbom_report import file_components, is_auditwheel, tie
from pypiscan.scan import (
    Line,
    Phase,
    inspect_phase,
    libraries_phase,
    recognizers_phase,
    sboms_phase,
    static_phase,
    strings_phase,
    upstream_libraries,
)
from pypiscan.wheel_inspect import WheelError

SCHEMA_VERSION = 1


def platform_tags(filename: str) -> list[str]:
    """The platform tags in a wheel filename, such as
    ``manylinux_2_17_x86_64`` and ``manylinux2014_x86_64``; none for a name
    that isn't a wheel's."""
    if not filename.endswith(".whl"):
        return []
    parts = filename.removesuffix(".whl").split("-")
    return parts[-1].split(".") if len(parts) in (5, 6) else []


def _line(phase: Phase[Package], package: Package, earlier: Mapping[str, Line]) -> Line:
    """``phase``'s line for ``package``, as an episode stores it; a line
    that isn't ok stops the command."""
    result = phase.run(package, earlier)
    if result.status != "ok":
        raise WheelError(f"{phase.name}: {result.status}: {result.reason}")
    return {
        "schema_version": phase.schema_version,
        "name": package.name,
        "status": result.status,
        "reason": result.reason,
        **result.data,
    }


def recognizer_lines(rows: Sequence[MapRow]) -> list[Line]:
    """Phase 07's lines for every library in the map."""
    phase = recognizers_phase(rows)
    lines: list[Line] = []
    for library in upstream_libraries(rows):
        result = phase.run(library, {})
        lines.append(
            {
                "schema_version": phase.schema_version,
                "library": library.name,
                "status": result.status,
                "reason": result.reason,
                **result.data,
            }
        )
    return lines


def phase_lines(wheel: Path, rows: Sequence[MapRow]) -> dict[str, Line]:
    """Phases 03, 04, 05, 09 and 10's lines for ``wheel``, keyed by phase."""
    if not wheel.is_file():
        raise WheelError(f"{wheel} is not a file")
    sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    name, _, rest = wheel.name.partition("-")
    package = Package(name, rest.partition("-")[0])
    earlier: dict[str, Line] = {
        "01-resolve": {"status": "ok", "filename": wheel.name, "sha256": sha256},
        "02-fetch": {"status": "ok", "path": str(wheel)},
    }
    for phase in (
        inspect_phase(),
        strings_phase(),
        # Its finish, which writes the library report, isn't run.
        libraries_phase(Path()),
        sboms_phase(),
        static_phase(recognizer_lines(rows), rows),
    ):
        earlier[phase.name] = _line(phase, package, earlier)
    return earlier


def summarize(wheel: Path, library_map: Path) -> list[Line]:
    """The ``wheel`` command's records for one wheel file."""
    try:
        rows = load_library_map(library_map)
    except (LibraryMapError, OSError) as exc:
        raise WheelError(str(exc)) from exc
    lines = phase_lines(wheel, rows)
    by_prefix: dict[str, list[str]] = {}
    for row in rows:
        if row.prefix and row.library not in by_prefix.get(row.prefix, []):
            by_prefix.setdefault(row.prefix, []).append(row.library)

    def record(kind: str, **fields: object) -> Line:
        return {"schema_version": SCHEMA_VERSION, "kind": kind, **fields}

    files = cast(list[Line], lines["05-libraries"]["libraries"])
    sboms = cast(list[Line], lines["09-sboms"]["records"])
    binaries = cast(list[Line], lines["10-static"]["binaries"])
    paths = [cast(str, f["path"]) for f in files]
    tied, untied = tie(file_components(sboms), paths)
    records = [
        record(
            "wheel",
            filename=wheel.name,
            sha256=lines["01-resolve"]["sha256"],
            platform_tags=platform_tags(wheel.name),
        )
    ]
    records += [
        record(
            "library",
            path=f["path"],
            prefix=f["prefix"],
            libraries=by_prefix.get(cast(str, f["prefix"]), []),
        )
        for f in files
    ]
    records += [record("sbom", sbom=s) for s in sboms]
    records += [record("untied_component", component=c) for c in untied]
    if any(is_auditwheel(s) for s in sboms):
        records += [record("untied_file", path=p) for p in paths if not tied[p]]
    records += [
        record(
            "static",
            path=b["path"],
            sha256=b["sha256"],
            candidates=b["candidates"],
            fingerprints=b["fingerprints"],
        )
        for b in binaries
        if b["candidates"] or b["fingerprints"]
    ]
    return records
