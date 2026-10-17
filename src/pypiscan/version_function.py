"""Read a library's version from its version function's machine code.

See README "Version function machine code". ``shape`` is a pure function
from a function's code to what it returns, and ``version`` applies a map
row's encoding to that. ``match`` finds the function in an ELF image's
``.dynsym``, reads its code and, for a string, the string it points to,
without running anything. Code that isn't exactly one of the accepted
shapes gives nothing, so a misread function is a missed version, not a
wrong one.
"""

import io
import re
from dataclasses import dataclass
from typing import Literal

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from pypiscan.elf_sections import section_at, sections
from pypiscan.fingerprint import Match
from pypiscan.library_map import VERSION_FUNCTION, VersionFunction, matcher

type Shape = Literal["integer", "string", "out"]

ENDBR64 = "f3 0f 1e fa"
# Each shape's bytes, with "imm" for a little-endian 32-bit immediate: as an
# optimizing compiler emits it, and inside an unoptimized build's frame.
SHAPES: tuple[tuple[Shape, str], ...] = (
    ("integer", "b8 imm c3"),
    ("string", "48 8d 05 imm c3"),
    ("out", "c7 07 imm c7 06 imm c7 02 imm c3"),
    ("integer", "55 48 89 e5 b8 imm 5d c3"),
    ("string", "55 48 89 e5 48 8d 05 imm 5d c3"),
    (
        "out",
        "55 48 89 e5 48 89 7d f8 48 89 75 f0 48 89 55 e8 "
        "48 8b 45 f8 c7 00 imm 48 8b 45 f0 c7 00 imm "
        "48 8b 45 e8 c7 00 imm 90 5d c3",
    ),
)
# The longest shape, endbr64 included, in bytes.
MAX_CODE = 4 + max(len(code.split()) + 3 * code.count("imm") for _, code in SHAPES)
# A string a version function returns: 1 to 255 printable bytes and a NUL.
STRING = re.compile(rb"([\x20-\x7e]{1,255})\0")


def _compile(code: str) -> re.Pattern[bytes]:
    parts = [
        b"(.{4})" if part == "imm" else re.escape(bytes.fromhex(part))
        for part in code.split()
    ]
    return re.compile(b"".join(parts), re.DOTALL)


_COMPILED: list[tuple[Shape, re.Pattern[bytes]]] = [
    (name, _compile(prefix + code))
    for name, code in SHAPES
    for prefix in ("", ENDBR64 + " ")
]


@dataclass(frozen=True)
class Returned:
    """What a function's code returns. ``values`` holds the integer, the
    three stored integers, or a string's displacement; ``end`` is the
    offset in the code just after the ``lea``, which the displacement is
    relative to."""

    shape: Shape
    values: tuple[int, ...]
    end: int = 0


def shape(code: bytes) -> Returned | None:
    """The shape of the function starting at ``code[0]``, or ``None``.

    Bytes after the shape's ``ret`` are ignored.
    """
    for name, regex in _COMPILED:
        if match := regex.match(code):
            values = tuple(
                int.from_bytes(group, "little", signed=True) for group in match.groups()
            )
            # A string's lea ends with its displacement, the only immediate.
            return Returned(name, values, match.end(1) if name == "string" else 0)
    return None


def _fields(value: int, widths: tuple[int, ...], base: int) -> str:
    fields: list[int] = []
    for width in reversed(widths):
        value, field = divmod(value, base**width)
        fields.append(field)
    fields.append(value)
    return ".".join(str(field) for field in reversed(fields))


def version(
    returned: Returned, row: VersionFunction, string: str | None = None
) -> tuple[str, str] | None:
    """The result as read and the version it gives, or ``None``.

    ``string`` is what a string shape points to.
    """
    values = returned.values
    if row.encoding in ("bits", "decimal") and returned.shape == "integer":
        [value] = values
        if value < row.minimum:
            return None
        if row.encoding == "bits":
            return f"{value:#x}", _fields(value, row.widths, 2)
        return str(value), _fields(value, row.widths, 10)
    if row.encoding == "out" and returned.shape == "out":
        if min(values) < 0:
            return None
        return ", ".join(map(str, values)), ".".join(map(str, values))
    if row.encoding != "string" or returned.shape != "string" or not string:
        return None
    match = matcher(row.pattern, VERSION_FUNCTION).fullmatch(string)
    return (f'"{string}"', match[1]) if match else None


def _offset(elf: ELFFile, address: int) -> tuple[int, int] | None:
    """The file offset of ``address`` and of the end of the ``PT_LOAD``
    segment's file contents holding it."""
    for segment in elf.iter_segments("PT_LOAD"):
        start, size = segment["p_vaddr"], segment["p_filesz"]
        if start <= address < start + size:
            offset = segment["p_offset"] + address - start
            return offset, segment["p_offset"] + size
    return None


def _address(elf: ELFFile, function: str) -> int | None:
    """The address of ``function`` among the defined functions in .dynsym."""
    dynsym = elf.get_section_by_name(".dynsym")
    if not isinstance(dynsym, SymbolTableSection):
        return None
    addresses = {
        symbol["st_value"]
        for symbol in dynsym.get_symbol_by_name(function) or []
        if symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_shndx"] != "SHN_UNDEF"
    }
    return addresses.pop() if len(addresses) == 1 else None


def match(data: bytes, library: str, row: VersionFunction) -> Match | None:
    """The match for ``library`` if ``row``'s function gives a version.

    Raises pyelftools' errors (``ELFError`` and the others
    ``wheel_inspect._needed`` names) for an image it can't parse.
    """
    elf = ELFFile(io.BytesIO(data))
    address = _address(elf, row.function)
    where = None if address is None else _offset(elf, address)
    if address is None or where is None:
        return None
    offset, end = where
    returned = shape(data[offset : min(end, offset + MAX_CODE)])
    if returned is None:
        return None
    string = None
    if returned.shape == "string":
        target = _offset(elf, address + returned.end + returned.values[0])
        if target is None:
            return None
        found = STRING.match(data[target[0] : min(target[1], target[0] + 256)])
        if found is None:
            return None
        string = found[1].decode("ascii")
    result = version(returned, row, string)
    if result is None:
        return None
    text, found_version = result
    return Match(
        library,
        VERSION_FUNCTION,
        f"{row.function}: {text}",
        offset,
        found_version,
        section_at(sections(data), offset),
    )
