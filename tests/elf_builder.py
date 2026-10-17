"""Build minimal ELF64 images for tests; no real binaries are committed."""

import struct
from dataclasses import dataclass

# ELF64 little-endian layouts: file header, program header, section header,
# dynamic entry.
_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
_PHDR = struct.Struct("<IIQQQQQQ")
_SHDR = struct.Struct("<IIQQQQIIQQ")
DYN = struct.Struct("<qQ")
_PT_LOAD, _PTDYNAMIC = 1, 2
_SHT_PROGBITS, _SHT_STRTAB, _SHT_DYNAMIC = 1, 3, 6
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ = 0, 1, 5, 10


def _align(n: int, to: int = 8) -> int:
    return -(-n // to) * to


def build_elf(
    needed: list[str] | None,
    *,
    section_headers: bool = True,
    unmapped_strtab: bool = False,
    rodata: bytes = b"",
    trailer: bytes = b"",
) -> bytes:
    """Build a minimal x86_64 shared object for pyelftools to parse.

    ``needed=None`` builds a statically linked image with no ``PTDYNAMIC``
    segment. Virtual addresses equal file offsets, so one ``PT_LOAD`` maps the
    whole file and ``DT_STRTAB`` resolves even without section headers;
    ``unmapped_strtab`` points it outside the file instead. ``rodata`` goes
    in a ``.rodata`` section; ``trailer`` follows everything, outside any
    section.
    """
    dynamic = needed is not None
    phnum = 2 if dynamic else 1
    out = bytearray(_EHDR.size + phnum * _PHDR.size)

    dynstr_off = dynstr_size = dyn_off = dyn_size = 0
    if dynamic:
        dynstr = bytearray(b"\0")
        name_offsets: list[int] = []
        for name in needed:
            name_offsets.append(len(dynstr))
            dynstr += name.encode() + b"\0"
        dynstr_off, dynstr_size = len(out), len(dynstr)
        out += dynstr
        out += bytes(_align(len(out)) - len(out))
        dyn_off = len(out)
        for offset in name_offsets:
            out += DYN.pack(DT_NEEDED, offset)
        out += DYN.pack(DT_STRTAB, 0x7FFF0000 if unmapped_strtab else dynstr_off)
        out += DYN.pack(DT_STRSZ, dynstr_size)
        out += DYN.pack(DT_NULL, 0)
        dyn_size = len(out) - dyn_off

    rodata_off = len(out)
    out += rodata

    shoff = shnum = shstrndx = 0
    if section_headers:
        shstrtab = b"\0.dynstr\0.dynamic\0.shstrtab\0.rodata\0"
        shstrtab_off = len(out)
        out += shstrtab
        out += bytes(_align(len(out)) - len(out))
        shoff = len(out)
        sections = [_SHDR.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
        if dynamic:
            sections.append(
                _SHDR.pack(1, _SHT_STRTAB, 2, dynstr_off, dynstr_off,
                           dynstr_size, 0, 0, 1, 0)
            )  # fmt: skip
            sections.append(
                _SHDR.pack(9, _SHT_DYNAMIC, 3, dyn_off, dyn_off, dyn_size,
                           1, 0, 8, DYN.size)
            )  # fmt: skip
        if rodata:
            sections.append(
                _SHDR.pack(28, _SHT_PROGBITS, 2, rodata_off, rodata_off,
                           len(rodata), 0, 0, 1, 0)
            )  # fmt: skip
        sections.append(
            _SHDR.pack(18, _SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab),
                       0, 0, 1, 0)
        )  # fmt: skip
        shnum, shstrndx = len(sections), len(sections) - 1
        out += b"".join(sections)

    out += trailer
    ident = b"\x7fELF\x02\x01\x01".ljust(16, b"\0")
    out[: _EHDR.size] = _EHDR.pack(
        ident, 3, 62, 1, 0, _EHDR.size, shoff, 0,
        _EHDR.size, _PHDR.size, phnum, _SHDR.size, shnum, shstrndx,
    )  # fmt: skip
    phdrs = _PHDR.pack(_PT_LOAD, 5, 0, 0, 0, len(out), len(out), 0x1000)
    if dynamic:
        phdrs += _PHDR.pack(_PTDYNAMIC, 6, dyn_off, dyn_off, dyn_off,
                            dyn_size, dyn_size, 8)  # fmt: skip
    out[_EHDR.size : _EHDR.size + len(phdrs)] = phdrs
    return bytes(out)


_SYM = struct.Struct("<IBBHQQ")
_SHT_DYNSYM = 11
_STB_GLOBAL, STT_OBJECT, STT_FUNC = 1, 1, 2
SHN_UNDEF = 0
# The .text section's index in ``build_dso``'s section headers.
_TEXT_INDEX = 3


@dataclass(frozen=True)
class Symbol:
    """A ``.dynsym`` entry: ``offset`` is its address relative to ``.text``."""

    name: str
    offset: int = 0
    type: int = STT_FUNC
    defined: bool = True


def build_dso(
    text: bytes,
    symbols: list[Symbol],
    *,
    vaddr: int = 0x400000,
    load_size: int | None = None,
) -> bytes:
    """Build an x86_64 shared object with a ``.dynstr``, ``.dynsym`` and
    ``.text``, and one ``PT_LOAD`` mapping the file at ``vaddr``, so an
    address is its file offset plus ``vaddr``. ``load_size`` cuts the
    segment's file size short, from the start of the file."""
    out = bytearray(_EHDR.size + _PHDR.size)
    dynstr = bytearray(b"\0")
    names: list[int] = []
    for symbol in symbols:
        names.append(len(dynstr))
        dynstr += symbol.name.encode() + b"\0"
    dynstr_off = len(out)
    out += dynstr
    out += bytes(_align(len(out)) - len(out))
    text_off = len(out) + _SYM.size * (len(symbols) + 1)
    entries = [_SYM.pack(0, 0, 0, 0, 0, 0)]
    for symbol, name in zip(symbols, names, strict=True):
        shndx = _TEXT_INDEX if symbol.defined else SHN_UNDEF
        value = vaddr + text_off + symbol.offset if symbol.defined else 0
        info = (_STB_GLOBAL << 4) | symbol.type
        entries.append(_SYM.pack(name, info, 0, shndx, value, 0))
    dynsym_off = len(out)
    out += b"".join(entries)
    out += text
    shstrtab = b"\0.dynstr\0.dynsym\0.text\0.shstrtab\0"
    shstrtab_off = len(out)
    out += shstrtab
    out += bytes(_align(len(out)) - len(out))
    shoff = len(out)
    out += b"".join(
        [
            _SHDR.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            _SHDR.pack(1, _SHT_STRTAB, 2, vaddr + dynstr_off, dynstr_off,
                       len(dynstr), 0, 0, 1, 0),
            _SHDR.pack(9, _SHT_DYNSYM, 2, vaddr + dynsym_off, dynsym_off,
                       _SYM.size * len(entries), 1, 1, 8, _SYM.size),
            _SHDR.pack(17, _SHT_PROGBITS, 6, vaddr + text_off, text_off,
                       len(text), 0, 0, 16, 0),
            _SHDR.pack(23, _SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab),
                       0, 0, 1, 0),
        ]
    )  # fmt: skip
    ident = b"\x7fELF\x02\x01\x01".ljust(16, b"\0")
    out[: _EHDR.size] = _EHDR.pack(
        ident, 3, 62, 1, 0, _EHDR.size, shoff, 0,
        _EHDR.size, _PHDR.size, 1, _SHDR.size, 5, 4,
    )  # fmt: skip
    size = len(out) if load_size is None else load_size
    out[_EHDR.size : _EHDR.size + _PHDR.size] = _PHDR.pack(
        _PT_LOAD, 5, 0, vaddr, vaddr, size, size, 0x1000
    )
    return bytes(out)
