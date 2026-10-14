"""Map file offsets in an ELF image to the section that holds them."""

import io

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

Sections = list[tuple[int, int, str]]


def sections(data: bytes) -> Sections:
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


def section_at(sections: Sections, offset: int) -> str | None:
    """The name of the section containing ``offset``, or ``None``."""
    for start, size, name in sections:
        if start <= offset < start + size:
            return name
    return None
