"""Identify bundled libraries and their versions from strings in ELF binaries.

Evidence kinds, record format and detector rules are specified in the README
section "How versions are identified". Library-specific knowledge lives in
``pypiscan.detectors``; this module only scans and builds records.
"""

import hashlib
import io
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal, TypedDict

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from pypiscan.wheel_inspect import iter_elf_members

SCHEMA_VERSION = 1

Kind = Literal["library_string", "header_string", "filename"]


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
    relation: Literal["contains", "compiled_against"]
    version: str | None
    conflict: bool
    evidence: list[EvidenceRecord]


@dataclass
class _Match:
    library: str
    kind: Kind
    text: str
    offset: int | None
    version: str | None  # None when the match must not set the version


def _sections(data: bytes) -> list[tuple[int, int, str]]:
    """Return ``(offset, size, name)`` for each section with file contents."""
    try:
        elf = ELFFile(io.BytesIO(data))
        return [
            (s["sh_offset"], s["sh_size"], s.name)
            for s in elf.iter_sections()
            if s["sh_type"] != "SHT_NOBITS" and s["sh_size"] > 0
        ]
    # Same pyelftools failure modes as wheel_inspect._needed.
    except (ELFError, AssertionError, ValueError, OverflowError):
        return []


def _section_at(sections: list[tuple[int, int, str]], offset: int) -> str | None:
    for start, size, name in sections:
        if start <= offset < start + size:
            return name
    return None


def _decode(raw: bytes) -> str:
    return raw.decode("ascii", "backslashreplace")


def _matches(detector: Detector, path: str, data: bytes) -> list[_Match]:
    found = [
        _Match(
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
        _Match(p.library, p.kind, _decode(m.group(0)), None, None)
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


def _resolve(
    matches: list[_Match],
) -> tuple[Literal["contains", "compiled_against"], str | None, bool] | None:
    lib = [m for m in matches if m.kind == "library_string"]
    if lib:
        versions = {m.version for m in lib if m.version is not None}
        conflict = len(versions) > 1
        version = versions.pop() if len(versions) == 1 else None
        return "contains", version, conflict
    headers = {m.text for m in matches if m.kind == "header_string"}
    if headers:
        return "compiled_against", headers.pop() if len(headers) == 1 else None, False
    return None  # filename evidence alone never produces a record


def fingerprint_binary(
    detectors: Iterable[Detector], wheel_name: str, path: str, data: bytes
) -> list[FingerprintRecord]:
    """Return one record per library detected in one binary."""
    sha256 = hashlib.sha256(data).hexdigest()
    sections: list[tuple[int, int, str]] | None = None
    records: list[FingerprintRecord] = []
    for detector in detectors:
        by_library: dict[str, list[_Match]] = {}
        for m in _matches(detector, path, data):
            by_library.setdefault(m.library, []).append(m)
        for library, matches in by_library.items():
            result = _resolve(matches)
            if result is None:
                continue
            if sections is None:
                sections = _sections(data)
            relation, version, conflict = result
            records.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "wheel": wheel_name,
                    "path": path,
                    "sha256": sha256,
                    "library": library,
                    "relation": relation,
                    "version": version,
                    "conflict": conflict,
                    "evidence": [
                        {
                            "kind": m.kind,
                            "text": m.text,
                            "offset": m.offset,
                            "section": None
                            if m.offset is None
                            else _section_at(sections, m.offset),
                        }
                        for m in matches
                    ],
                }
            )
    return records


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
