"""List the version-like printable strings in a wheel's ELF binaries.

A printable string is a run of printable ASCII (0x20-0x7E, plus tab), ended
by any other byte and kept exactly as found. It is listed if it contains a
version-like token: digit runs joined by dots, with at least one dot. Its
template replaces every digit run with ``#``, so strings that differ only in
their numbers share a template.
"""

import hashlib
import re
from pathlib import Path
from typing import TypedDict

from pypiscan.elf_sections import section_at, sections
from pypiscan.wheel_inspect import SkippedMember, iter_elf_members

SCHEMA_VERSION = 1

PRINTABLE = re.compile(rb"[\t\x20-\x7e]+")
VERSION_TOKEN = re.compile(rb"[0-9]+(?:\.[0-9]+)+")
DIGITS = re.compile(r"[0-9]+")


class StringRecord(TypedDict):
    offset: int
    section: str | None
    text: str
    template: str


class BinaryStrings(TypedDict):
    schema_version: int
    wheel: str
    path: str
    sha256: str
    strings: list[StringRecord]


def template(text: str) -> str:
    """Replace every digit run in ``text`` with ``#``."""
    return DIGITS.sub("#", text)


def binary_strings(data: bytes) -> list[StringRecord]:
    """Return each version-like printable string in ``data``, in file order."""
    mapped = sections(data)
    records: list[StringRecord] = []
    for match in PRINTABLE.finditer(data):
        raw = match.group()
        if not VERSION_TOKEN.search(raw):
            continue
        text = raw.decode("ascii")
        records.append(
            {
                "offset": match.start(),
                "section": section_at(mapped, match.start()),
                "text": text,
                "template": template(text),
            }
        )
    return records


def strings_wheel(
    wheel: Path,
    max_member_size: int | None = None,
    skipped: list[SkippedMember] | None = None,
) -> list[BinaryStrings]:
    """Return one record per ELF member of ``wheel``, in archive order."""
    return [
        {
            "schema_version": SCHEMA_VERSION,
            "wheel": wheel.name,
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "strings": binary_strings(data),
        }
        for path, data in iter_elf_members(wheel, max_member_size, skipped)
    ]
