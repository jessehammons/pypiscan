"""The noise filter: drop strings that can't identify a library.

See README "How versions are identified". Only strings in data sections
count, and known noise is removed. ``NOISE`` is the one list of noise
patterns; it grows as the library report shows more.
"""

import re

from pypiscan.wheel_strings import StringRecord

DATA_SECTIONS = frozenset({".rodata", ".data", ".data.rel.ro"})

NOISE = [
    # Compiler and build notes.
    re.compile(r"GCC:"),
    re.compile(r"annobin"),
    # Symbol versions.
    re.compile(r"@GLIBC_"),
    # The build image's own paths.
    re.compile(r"/opt/_internal/"),
]


def usable(record: StringRecord) -> bool:
    """Whether a ``strings`` record is in a data section and isn't noise."""
    if record["section"] not in DATA_SECTIONS:
        return False
    return not any(pattern.search(record["text"]) for pattern in NOISE)
