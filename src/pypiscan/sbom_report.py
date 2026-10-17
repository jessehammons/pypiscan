"""The SBOM report: auditwheel's components tied to ``.libs/`` files by their
bom-refs, and their versions compared with the files' fingerprint versions.

See README "Comparing SBOMs with fingerprints" (roadmap 5.2). ``report`` is a
pure function of phases 01 to 05, 08 and 09's lines, the library map's rows
and the list of ambiguous versions; ``scan`` writes the result as
``sbom-report.md``. An SBOM is a claim: nothing here changes a record.
"""

import hashlib
import re
from collections import Counter
from collections.abc import Mapping, Sequence
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

LIBRARY_DIRS = ("/lib64/", "/usr/lib64/", "/lib/", "/usr/lib/")
DISTRIBUTIONS = ("pkg:rpm/", "pkg:deb/", "pkg:apk/")
SBOMS = "09-sboms"
NOT = "not compared"
HASHED = re.compile(r"(.*)-[0-9a-f]{8}")
DIGEST = re.compile(r"[0-9a-f]{64}")
EPOCH = re.compile(r"\d+:")
INTRO = """\
# SBOM report

An SBOM is a claim about what a wheel bundles, not a measurement, and a
difference below is checked by hand; see "Comparing SBOMs with fingerprints"
in the README. The counts cover auditwheel's SBOMs only: other SBOMs are
listed, not compared.
"""
FILES = (
    "| file | component | library | version | basis | note | comparison |\n"
    "|---|---|---|---|---|---|---|"
)
UNTIED = "| name | version | purl | bom-ref |\n|---|---|---|---|"


def original_name(file_name: str) -> str | None:
    """The name auditwheel copied a ``.libs/`` file from: the part before the
    first ``.`` loses its trailing ``-`` and 8 hex digits."""
    base, dot, rest = file_name.partition(".")
    hashed = HASHED.fullmatch(base)
    return f"{hashed[1]}.{rest}" if dot and hashed else None


def path_hashes(file_name: str) -> set[str]:
    """The sha256 of each path, in ``LIBRARY_DIRS``, the file may come from."""
    name = original_name(file_name)
    if name is None:
        return set()
    return {hashlib.sha256((d + name).encode()).hexdigest() for d in LIBRARY_DIRS}


def is_auditwheel(record: Line) -> bool:
    """Whether a phase 09 record is a CycloneDX file, read in full, that
    auditwheel wrote."""
    tools = cast(list[Line], record["tools"] or [])
    return (
        record["format"] == "cyclonedx-json"
        and record["error"] is None
        and any(tool["name"] == "auditwheel" for tool in tools)
    )


def file_digest(component: Line) -> str | None:
    """The hex digits of a bom-ref that names a file: exactly the component's
    own purl, ``#`` and 64 lowercase hex digits."""
    purl, ref = component["purl"], component["bom-ref"]
    if not isinstance(purl, str) or not isinstance(ref, str):
        return None
    digest = ref[len(purl) + 1 :]
    named = ref == f"{purl}#{digest}" and DIGEST.fullmatch(digest)
    return digest if named else None


def file_components(records: Sequence[Line]) -> list[Line]:
    """The components of auditwheel's SBOMs whose bom-refs name a file."""
    return [
        component
        for record in records
        if is_auditwheel(record)
        for component in cast(list[Line], record["components"])
        if file_digest(component)
    ]


def tie(
    components: Sequence[Line], paths: Sequence[str]
) -> tuple[dict[str, list[Line]], list[Line]]:
    """Each ``.libs/`` path's tied components, and the components tied to
    none: those that match no file, or more than one."""
    hashes = {path: path_hashes(PurePosixPath(path).name) for path in paths}
    tied: dict[str, list[Line]] = {path: [] for path in paths}
    untied: list[Line] = []
    for component in components:
        matches = [path for path in paths if file_digest(component) in hashes[path]]
        if len(matches) == 1:
            tied[matches[0]].append(component)
        else:
            untied.append(component)
    return tied, untied


def upstream_version(purl: object, version: object) -> str | None:
    """A distribution package's version cut to its upstream release, or
    ``None`` for any other purl or no version."""
    if not (isinstance(purl, str) and purl.startswith(DISTRIBUTIONS)):
        return None
    if not isinstance(version, str):
        return None
    if purl.startswith("pkg:deb/") and (epoch := EPOCH.match(version)):
        version = version[epoch.end() :]
    head, dash, _ = version.rpartition("-")
    return head if dash else version


def compare(
    components: Sequence[Line],
    libraries: Sequence[str],
    record: Line | None,
    recognized: bool,
    ambiguous: Ambiguous,
) -> tuple[str, str]:
    """How a tied file compares: ``agrees`` or ``differs`` and the fingerprint
    version's basis, or ``not compared`` and why. ``record`` is the contains
    record of the prefix's one library, and ``recognized`` whether the map
    gives that library recognizers under the prefix."""
    if len(components) > 1:
        return NOT, "several components"
    if not libraries:
        return NOT, "not mapped"
    if len(libraries) > 1:
        return NOT, "several libraries"
    [library], [component] = libraries, components
    if library == SKIP or record is None or record["version"] is None:
        return NOT, missing(library, record, recognized)
    claimed = upstream_version(component["purl"], component["version"])
    if claimed is None:
        return NOT, "no distribution version"
    version = str(record["version"])
    same = claimed in [version, *ambiguous.get(library, {}).get(version, [])]
    return "agrees" if same else "differs", str(record["basis"])


def _text(value: object) -> str:
    return NONE if value is None else str(value)


def _sbom_file(record: Line) -> str:
    head = f"- `{record['path']}`"
    if record["error"] is not None:
        return f"{head}: error: {record['error']}"
    if record["format"] != "cyclonedx-json":
        return f"{head}: {record['format']}; listed, not compared"
    tools = ", ".join(
        " ".join(str(v) for v in (tool["name"], tool["version"]) if v is not None)
        for tool in cast(list[Line], record["tools"])
    )
    count = len(cast(list[Line], record["components"]))
    how = "compared" if is_auditwheel(record) else "listed, not compared"
    plural = "" if count == 1 else "s"
    return f"{head}: tools {tools or NONE}; {count} component{plural}; {how}"


def _component(component: Line) -> str:
    name, version, purl = (_text(component[k]) for k in ("name", "version", "purl"))
    return f"{name} {version} ({purl})"


def _section(
    package: Package,
    part_1: Mapping[str, Mapping[str, Line]],
    fingerprints: Line,
    sboms: Line,
    by_prefix: Mapping[str, list[str]],
    recognized: set[tuple[str, str]],
    ambiguous: Ambiguous,
    counts: Counter[str],
) -> list[str]:
    head = [f"## {package.name} {package.version}", ""]
    if sboms["status"] != "ok":
        earlier = {**part_1, FINGERPRINT: {package.name: fingerprints}}
        return [*head, stopped(package.name, sboms, earlier, SBOMS)]
    records = cast(list[Line], sboms["records"])
    found = cast(
        list[Mapping[str, str]], part_1["05-libraries"][package.name]["libraries"]
    )
    counts["scanned"] += 1
    counts["with an SBOM"] += bool(records)
    counts["with auditwheel"] += any(is_auditwheel(r) for r in records)
    if not records and not found:
        return []
    out = [*head, f"`{sboms['wheel']}`", ""]
    out += [_sbom_file(r) for r in records] or ["No SBOM files."]
    components = file_components(records)
    tied, untied = tie(components, [f["path"] for f in found])
    counts["components tied"] += len(components) - len(untied)
    counts["components not tied"] += len(untied)
    contains = {
        (str(r["path"]), str(r["library"])): r
        for r in cast(list[Line], fingerprints["records"])
        if r["relation"] == "contains"
    }
    out += ["", FILES] if found else ["", "No .libs/ files."]
    for each in found:
        path, prefix = each["path"], each["prefix"]
        libraries = by_prefix.get(prefix, [])
        first = [PurePosixPath(path).name, NONE, NONE]
        if tied[path]:
            counts["files tied"] += 1
            record = contains.get((path, libraries[0])) if libraries else None
            known = bool(libraries) and (prefix, libraries[0]) in recognized
            outcome, why = compare(tied[path], libraries, record, known, ambiguous)
            counts[f"{outcome}: {why}"] += 1
            first[1] = "; ".join(_component(c) for c in tied[path])
            first[2] = f"{outcome}: {why}" if outcome == NOT else outcome
        else:
            counts["files not tied"] += 1
        for i, library in enumerate(libraries or [NONE]):
            record = contains.get((path, library))
            shown = (
                cells(library, record, (prefix, library) in recognized, ambiguous)
                if libraries
                else (NONE, NONE, "not mapped")
            )
            name, component, comparison = first if i == 0 else ("", "", "")
            out.append(row(name, component, library, *shown, comparison))
    if untied:
        out += ["", "auditwheel components tied to no file:", "", UNTIED]
        out += [
            row(*(_text(c[k]) for k in ("name", "version", "purl", "bom-ref")))
            for c in untied
        ]
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
    fingerprints: Mapping[str, Line],
    sboms: Mapping[str, Line],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
) -> str:
    """The report's text, from phases 01 to 05's lines keyed by phase and
    package name, phase 08's and 09's keyed by package name, the map's rows
    and the list of ambiguous versions."""
    by_prefix = libraries_by_prefix(rows)
    recognized = {(r.prefix, r.library) for r in rows if r.kind}
    counts: Counter[str] = Counter()
    sections: list[str] = []
    for package in packages:
        name = package.name
        section = _section(
            package,
            part_1,
            fingerprints[name],
            sboms[name],
            by_prefix,
            recognized,
            ambiguous,
            counts,
        )
        sections += [*section, ""] if section else []
    c = counts
    summary = [
        f"- Packages scanned in phase 09: {c['scanned']}; with any SBOM: "
        f"{c['with an SBOM']}; with an auditwheel SBOM: {c['with auditwheel']}.",
        f"- auditwheel components that name a file: tied {c['components tied']}, "
        f"not tied {c['components not tied']}.",
        f"- `.libs/` files in scanned packages: tied {c['files tied']}, "
        f"not tied {c['files not tied']}.",
        f"- Tied files that agree: {_split(c, 'agrees')}.",
        f"- Tied files that differ: {_split(c, 'differs')}.",
        f"- Tied files not compared: {_split(c, NOT)}.",
    ]
    return "\n".join([INTRO, "## Counts", "", *summary, "", *sections])
