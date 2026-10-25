"""Identify bundled libraries and their versions from strings in ELF binaries.

Evidence kinds, record format and detector rules are specified in the README
section "How versions are identified". Library-specific knowledge lives in
``pypiscan.detectors``; this module only scans and builds records. Scan
phase 08 builds its records with ``record`` too, from matches it finds in
phase 04's strings and, through ``pypiscan.version_function``, in version
functions' machine code.
"""

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal, TypedDict

from pypiscan.elf_sections import Sections, section_at, sections
from pypiscan.wheel_inspect import iter_elf_members

SCHEMA_VERSION = 3

Kind = Literal[
    "library_string",
    "build_path",
    "version_function_machine_code",
    "bare_version",
    "header_string",
    "filename",
]
Basis = Literal[
    "library_string",
    "build_path",
    "version_function_machine_code",
    "bare_version",
    "header_string",
]
# The kinds that set a version, strongest first.
VERSION_KINDS: tuple[Basis, ...] = (
    "library_string",
    "build_path",
    "version_function_machine_code",
    "bare_version",
)
Relation = Literal["contains", "compiled_against"]


@dataclass(frozen=True)
class Citation:
    """Where upstream defines a pattern's string: the C variable or macro
    ``symbol``, whose literal starts at ``file:line`` at release ``tag`` of
    the GitHub repository ``repo``. ``scripts/upstream_fixtures.py`` extracts
    every cited symbol at every release tag."""

    repo: str
    tag: str
    file: str
    line: int
    symbol: str

    def __str__(self) -> str:
        return f"{self.repo} {self.file}:{self.line} @ {self.tag} ({self.symbol})"


@dataclass(frozen=True)
class Pattern:
    """One string a detector looks for.

    ``regex`` must match a whole string and capture the version in a group
    named ``version``. ``source`` cites the upstream definitions of a library
    or header string, one citation per wording the regex accepts; for a
    filename pattern it describes the naming convention instead.
    """

    library: str
    kind: Kind
    regex: re.Pattern[bytes]
    source: tuple[Citation, ...] | str


@dataclass(frozen=True)
class Detector:
    """Patterns for one library family.

    ``derivatives`` maps a derivative to the original whose library strings
    it also carries (for example ``{"zlib-ng": "zlib"}``). When a derivative's
    own library strings are present, the original's matches are attributed to
    the derivative and don't set its version.
    """

    patterns: tuple[Pattern, ...]
    filename_patterns: tuple[Pattern, ...] = ()
    derivatives: Mapping[str, str] = field(default_factory=dict[str, str])


class EvidenceRecord(TypedDict):
    kind: Kind
    text: str
    offset: int | None
    section: str | None


class FingerprintRecord(TypedDict):
    schema_version: int
    wheel: str
    path: str
    sha256: str
    library: str
    relation: Relation
    basis: Basis
    version: str | None
    conflict: bool
    evidence: list[EvidenceRecord]


@dataclass
class Match:
    library: str
    kind: Kind
    text: str
    offset: int | None
    version: str | None  # None when the match must not set the version
    section: str | None = None


def _decode(raw: bytes) -> str:
    return raw.decode("ascii", "backslashreplace")


def _matches(detector: Detector, path: str, data: bytes) -> list[Match]:
    found = [
        Match(
            p.library,
            p.kind,
            _decode(m.group(0).rstrip(b"\0")),
            m.start(),
            _decode(m.group("version")),
        )
        for p in detector.patterns
        for m in p.regex.finditer(data)
    ]
    name = PurePosixPath(path).name.encode()
    found += [
        Match(p.library, p.kind, _decode(m.group(0)), None, None)
        for p in detector.filename_patterns
        if (m := p.regex.fullmatch(name))
    ]
    has_library_strings = {m.library for m in found if m.kind == "library_string"}
    for derivative, original in detector.derivatives.items():
        if derivative in has_library_strings:
            for m in found:
                if m.library == original:
                    m.library, m.version = derivative, None
    found.sort(key=lambda m: (m.offset is None, m.offset or 0))
    return found


def resolve(matches: list[Match]) -> tuple[Relation, Basis, str | None, bool] | None:
    """Relation, basis, version and conflict for one library's matches.

    The strongest version-setting kind present is the basis, and sets the
    version if its matches agree. Any two version-setting matches that
    disagree make a conflict. Header strings alone give ``compiled_against``;
    filename evidence alone gives nothing. A match whose version is ``None``
    counts toward neither version nor conflict.
    """
    kinds = {m.kind for m in matches}
    for basis in VERSION_KINDS:
        if basis in kinds:
            versions = {m.version for m in matches if m.kind == basis} - {None}
            setting = {m.version for m in matches if m.kind in VERSION_KINDS}
            conflict = len(setting - {None}) > 1
            version = versions.pop() if len(versions) == 1 else None
            return "contains", basis, version, conflict
    headers = {m.text for m in matches if m.kind == "header_string"}
    if headers:
        version = headers.pop() if len(headers) == 1 else None
        return "compiled_against", "header_string", version, False
    return None


def record(
    wheel_name: str, path: str, sha256: str, library: str, matches: list[Match]
) -> FingerprintRecord | None:
    """The record for one binary and library, or ``None`` if it has none."""
    result = resolve(matches)
    if result is None:
        return None
    relation, basis, version, conflict = result
    return {
        "schema_version": SCHEMA_VERSION,
        "wheel": wheel_name,
        "path": path,
        "sha256": sha256,
        "library": library,
        "relation": relation,
        "basis": basis,
        "version": version,
        "conflict": conflict,
        "evidence": [
            {"kind": m.kind, "text": m.text, "offset": m.offset, "section": m.section}
            for m in matches
        ],
    }


def binary_matches(
    detectors: Iterable[Detector], path: str, data: bytes
) -> list[dict[str, list[Match]]]:
    """Each detector's matches in one binary, by library, with sections."""
    mapped: Sections | None = None
    found: list[dict[str, list[Match]]] = []
    for detector in detectors:
        by_library: dict[str, list[Match]] = {}
        for m in _matches(detector, path, data):
            if m.offset is not None:
                if mapped is None:
                    mapped = sections(data)
                m.section = section_at(mapped, m.offset)
            by_library.setdefault(m.library, []).append(m)
        found.append(by_library)
    return found


def fingerprint_binary(
    detectors: Iterable[Detector], wheel_name: str, path: str, data: bytes
) -> list[FingerprintRecord]:
    """Return one record per library detected in one binary."""
    sha256 = hashlib.sha256(data).hexdigest()
    return [
        found
        for by_library in binary_matches(detectors, path, data)
        for library, matches in by_library.items()
        if (found := record(wheel_name, path, sha256, library, matches))
    ]


def fingerprint_wheel(
    wheel: Path, detectors: Iterable[Detector]
) -> list[FingerprintRecord]:
    """Return fingerprint records for every ELF member of ``wheel``."""
    detectors = tuple(detectors)
    return [
        record
        for path, data in iter_elf_members(wheel)
        for record in fingerprint_binary(detectors, wheel.name, path, data)
    ]
