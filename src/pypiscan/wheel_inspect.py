"""List the ELF binaries inside a wheel without extracting it."""

import hashlib
import zipfile
from pathlib import Path
from typing import TypedDict

SCHEMA_VERSION = 1
ELF_MAGIC = b"\x7fELF"
_CHUNK_SIZE = 1 << 20


class WheelError(Exception):
    """The input can't be read as a wheel."""


class ElfRecord(TypedDict):
    schema_version: int
    wheel: str
    path: str
    size: int
    sha256: str
    in_libs_dir: bool


def _in_libs_dir(member: str) -> bool:
    top, sep, _ = member.partition("/")
    return bool(sep) and top.endswith(".libs")


def inspect_wheel(wheel: Path) -> list[ElfRecord]:
    """Return one record per ELF member of ``wheel``, in archive order.

    Members are streamed from the archive and hashed in memory; nothing is
    written to disk and no member is executed.
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
        head = f.read(len(ELF_MAGIC))
        if head != ELF_MAGIC:
            return None
        digest = hashlib.sha256(head)
        size = len(head)
        while chunk := f.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return {
        "schema_version": SCHEMA_VERSION,
        "wheel": wheel_name,
        "path": info.filename,
        "size": size,
        "sha256": digest.hexdigest(),
        "in_libs_dir": _in_libs_dir(info.filename),
    }
