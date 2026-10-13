"""List the ELF binaries inside a wheel without extracting it."""

import hashlib
import io
import zipfile
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
    # pyelftools signals some malformed input with assertions, not ELFError.
    except (ELFError, AssertionError):
        return None


def _in_libs_dir(member: str) -> bool:
    top, sep, _ = member.partition("/")
    return bool(sep) and top.endswith(".libs")


def inspect_wheel(wheel: Path) -> list[ElfRecord]:
    """Return one record per ELF member of ``wheel``, in archive order.

    Each ELF member is read into memory, hashed and parsed as data; nothing
    is written to disk and no member is executed.
    """
    if not wheel.is_file():
        raise WheelError(f"{wheel}: no such file")
    try:
        with zipfile.ZipFile(wheel) as zf:
            return [
                record
                for info in zf.infolist()
                if not info.is_dir()
                and (record := _inspect_member(zf, info, wheel.name)) is not None
            ]
    except zipfile.BadZipFile as exc:
        raise WheelError(f"{wheel}: not a valid zip file ({exc})") from exc
    except OSError as exc:
        raise WheelError(f"{wheel}: {exc}") from exc


def _inspect_member(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, wheel_name: str
) -> ElfRecord | None:
    with zf.open(info) as f:
        if f.read(len(ELF_MAGIC)) != ELF_MAGIC:
            return None
        data = ELF_MAGIC + f.read()
    return {
        "schema_version": SCHEMA_VERSION,
        "wheel": wheel_name,
        "path": info.filename,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "in_libs_dir": _in_libs_dir(info.filename),
        "needed": _needed(data),
    }
