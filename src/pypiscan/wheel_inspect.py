"""List the ELF binaries inside a wheel without extracting it."""

import hashlib
import io
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import TypedDict

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile

SCHEMA_VERSION = 2
ELF_MAGIC = b"\x7fELF"


class WheelError(Exception):
    """The input can't be read as a wheel."""


class ElfRecord(TypedDict):
    schema_version: int
    wheel: str
    path: str
    size: int
    sha256: str
    in_libs_dir: bool
    needed: list[str] | None


def _needed(data: bytes) -> list[str] | None:
    """Return the ``DT_NEEDED`` entries of an ELF image, in file order.

    Reads the loader's view (the ``PT_DYNAMIC`` segment), so binaries with
    stripped section headers still resolve. A binary with no dynamic segment
    is statically linked and returns ``[]``. Returns ``None`` if the image
    can't be parsed.
    """
    try:
        elf = ELFFile(io.BytesIO(data))
        # DynamicTag sets ``needed`` with setattr, so it isn't a typed attribute.
        return [
            str(vars(tag)["needed"])
            for segment in elf.iter_segments()
            if isinstance(segment, DynamicSegment)
            for tag in segment.iter_tags("DT_NEEDED")
        ]
    # Besides ELFError, pyelftools lets other errors through on malformed input:
    # AssertionError when the dynamic string table can't be located,
    # UnicodeDecodeError (a ValueError) when a stripped binary's DT_NEEDED name
    # isn't UTF-8, and OverflowError when seeking to a name offset near 2**64.
    except (ELFError, AssertionError, ValueError, OverflowError):
        return None


def _in_libs_dir(member: str) -> bool:
    top, sep, _ = member.partition("/")
    return bool(sep) and top.endswith(".libs")


def iter_elf_members(wheel: Path) -> Iterator[tuple[str, bytes]]:
    """Yield ``(member path, contents)`` for each ELF member, in archive order.

    Each ELF member is read into memory as data; nothing is written to disk
    and no member is executed. Raises ``WheelError`` if ``wheel`` can't be read.
    """
    if not wheel.is_file():
        raise WheelError(f"{wheel}: no such file")
    try:
        with zipfile.ZipFile(wheel) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                with zf.open(info) as f:
                    if f.read(len(ELF_MAGIC)) != ELF_MAGIC:
                        continue
                    data = ELF_MAGIC + f.read()
                yield info.filename, data
    except zipfile.BadZipFile as exc:
        raise WheelError(f"{wheel}: not a valid zip file ({exc})") from exc
    except OSError as exc:
        raise WheelError(f"{wheel}: {exc}") from exc


def inspect_wheel(wheel: Path) -> list[ElfRecord]:
    """Return one record per ELF member of ``wheel``, in archive order."""
    return [
        {
            "schema_version": SCHEMA_VERSION,
            "wheel": wheel.name,
            "path": path,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "in_libs_dir": _in_libs_dir(path),
            "needed": _needed(data),
        }
        for path, data in iter_elf_members(wheel)
    ]
