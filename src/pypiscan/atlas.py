"""The bundled-library atlas: one row per wheel with a ``.libs/`` file, its
platform tag, SBOM kinds, build images and libraries by the map's name.

See README "The bundled-library atlas" (roadmap C.3). ``report`` is a pure
function of phases 01 to 05 and 09's lines and the library map's rows;
``scan`` writes the result as ``atlas.md``. It names what wheels carry, not
versions.
"""

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import cast

from pypiscan.fingerprint_report import (
    NONE,
    NOT_IN_MAP,
    Line,
    libraries_by_prefix,
    row,
    stopped,
)
from pypiscan.library_map import SKIP, MapRow
from pypiscan.package_list import Package
from pypiscan.sbom_report import SBOMS, file_components, tie

LIBRARIES = "05-libraries"
DISTRIBUTION_NAMES = {
    "centos": "CentOS",
    "almalinux": "AlmaLinux",
    "rocky": "Rocky Linux",
    "rhel": "RHEL",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
}
EL_RELEASE = re.compile(r"\.el(\d+)")
INTRO = """\
# Bundled-library atlas

What each wheel's `.libs/` directory carries, from a pypiscan episode; see
"The bundled-library atlas" in pypiscan's README.

- It lists only shared libraries in a wheel's `.libs/` directory. Libraries
  compiled into extension modules or other libraries, such as
  cryptography's OpenSSL or lxml's zlib, aren't in it (see "Findings so
  far" in the README).
- It names what wheels carry, not versions: versions and their basis are in
  `fingerprint-report.md`, and SBOM claims in `sbom-report.md`.
- A build image is shown only where an auditwheel component is tied to the
  file. No image doesn't mean an upstream build.
"""
HEADER = (
    "| package | version | platform tag | SBOM | build image | libraries |\n"
    "|---|---|---|---|---|---|"
)


def build_image(purl: str) -> str:
    """The build image a tied component's purl names: its distribution and,
    for an rpm version whose last ``-`` part has ``.el`` and digits, those
    digits as its release."""
    kind, namespace, version = None, "", ""
    if purl.startswith("pkg:"):
        path = purl[len("pkg:") :].partition("#")[0].partition("?")[0]
        kind, *namespace_parts, last = path.split("/")
        namespace = "/".join(namespace_parts)
        version = last.rpartition("@")[2] if "@" in last else ""
    distribution = DISTRIBUTION_NAMES.get(namespace, namespace or "unknown")
    head, dash, release = version.rpartition("-")
    found = EL_RELEASE.search(release) if kind == "rpm" and head and dash else None
    return f"{distribution} {found[1]}" if found else f"{distribution}, release unknown"


def sbom_kind(record: Line) -> str:
    """One SBOM file's kind: its tools' names for a CycloneDX file read in
    full, else its format or its error."""
    if record["error"] is not None:
        return f"error: {record['error']}"
    if record["format"] != "cyclonedx-json":
        return str(record["format"])
    tools = cast(list[Line], record["tools"])
    names = list(dict.fromkeys(str(tool["name"]) for tool in tools))
    return "+".join(names) if names else "cyclonedx-json, no tools"


def _joined(values: Iterable[str]) -> str:
    return "; ".join(sorted(set(values))) or NONE


def _counted(counts: Counter[str]) -> str:
    """``a 2; b 1``, most first, or ``none``. Keys can hold commas."""
    parts = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return "; ".join(f"{k} {n}" for k, n in parts) or "none"


def _entry(prefix: str, libraries: Sequence[str]) -> tuple[str, str]:
    """A prefix's entry in the libraries column, and the text it sorts by."""
    if len(libraries) == 1 and libraries[0] != SKIP:
        return libraries[0], libraries[0]
    label = ", ".join(libraries) if libraries else NOT_IN_MAP
    return f"`{prefix}` ({label})", prefix


def report(
    packages: Sequence[Package],
    part_1: Mapping[str, Mapping[str, Line]],
    sboms: Mapping[str, Line],
    rows: Sequence[MapRow],
) -> str:
    """The atlas's text, from phases 01 to 05's lines keyed by phase and
    package name, phase 09's keyed by package name and the map's rows."""
    by_prefix = libraries_by_prefix(rows)
    counts: dict[str, Counter[str]] = {
        key: Counter()
        for key in (
            "skipped",
            "libraries",
            "unmapped",
            "tags",
            "row kinds",
            "other kinds",
            "images",
        )
    }
    opened = files = with_sbom = other_sbom = tied_rows = 0
    table: list[tuple[str, str]] = []
    not_opened: list[str] = []
    for package in packages:
        name = package.name
        line = part_1[LIBRARIES][name]
        if line["status"] != "ok":
            where = stopped(name, line, part_1, LIBRARIES)
            counts["skipped"][where] += 1
            not_opened.append(f"- {name} {package.version}: {where}")
            continue
        opened += 1
        found = cast(list[Mapping[str, str]], line["libraries"])
        sbom = sboms[name]
        records = cast(list[Line], sbom["records"]) if sbom["status"] == "ok" else []
        kinds = {sbom_kind(r) for r in records}
        if not found:
            other_sbom += bool(records)
            counts["other kinds"].update(kinds)
            continue
        files += len(found)
        with_sbom += bool(records)
        counts["row kinds"].update(kinds)
        tied, _ = tie(file_components(records), [f["path"] for f in found])
        tied_rows += any(tied.values())
        entries: dict[str, tuple[str, set[str]]] = {}
        named: set[str] = set()
        for each in found:
            libraries = by_prefix.get(each["prefix"], [])
            text, key = _entry(each["prefix"], libraries)
            images = {build_image(str(c["purl"])) for c in tied[each["path"]]}
            counts["images"].update(images)
            entries.setdefault(text, (key, set()))[1].update(images)
            if text == key:
                named.add(text)
            if not libraries:
                counts["unmapped"][each["prefix"]] += 1
        counts["libraries"].update(named)
        shown = [
            f"{text} [{_joined(images)}]" if images else text
            for text, (_, images) in sorted(
                entries.items(), key=lambda item: (item[1][0].lower(), item[0])
            )
        ]
        tag = str(part_1["01-resolve"][name]["filename"])
        tag = tag.removesuffix(".whl").rpartition("-")[2]
        counts["tags"][tag] += 1
        if sbom["status"] == "ok":
            sbom_cell = ", ".join(sorted(kinds)) or "none"
        else:
            sbom_cell = stopped(name, sbom, part_1, SBOMS)
        all_images = {image for _, images in entries.values() for image in images}
        cells = (
            name,
            package.version,
            tag,
            sbom_cell,
            _joined(all_images),
            "; ".join(shown),
        )
        table.append((name.lower(), row(*cells)))
    c = counts
    unmapped = c["unmapped"]
    summary = [
        f"- Packages in the episode: {len(packages)}; wheels opened in phase "
        f"05: {opened}; packages skipped: {sum(c['skipped'].values())} "
        f"({_counted(c['skipped'])}).",
        f"- Wheels with a `.libs/` directory (the rows): {len(table)}, with "
        f"{files} `.libs/` files.",
        f"- Libraries by the map's name: {len(c['libraries'])}; rows carrying "
        f"each: {_counted(c['libraries'])}.",
        f"- Prefixes not in the map: {len(unmapped)}, with "
        f"{sum(unmapped.values())} files.",
        f"- Rows by platform tag: {_counted(c['tags'])}.",
        f"- Rows with an SBOM: {with_sbom}; by kind: {_counted(c['row kinds'])}.",
        f"- Scanned wheels with an SBOM but no `.libs/`: {other_sbom}; by kind: "
        f"{_counted(c['other kinds'])}.",
        f"- Rows with a file tied to an auditwheel component: {tied_rows}; tied "
        f"files by build image: {_counted(c['images'])}.",
    ]
    out = [INTRO, "## Counts", "", *summary, "", "## Wheels", "", HEADER]
    out += [text for _, text in sorted(table)]
    if not_opened:
        out += ["", "## Packages not opened", "", *not_opened]
    return "\n".join([*out, ""])
