"""Build minimal ELF64 images for tests; no real binaries are committed."""

import struct

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
