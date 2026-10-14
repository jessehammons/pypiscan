"""The noise filter: drop strings that can't identify a library.

See README "How versions are identified". Only strings in data sections
count, and known noise is removed: the patterns in ``NOISE``, the one list
that grows as the library report shows more, and strings that hold only
object identifiers.
"""

import re

from pypiscan.wheel_strings import VERSION_TOKEN, StringRecord

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

# Object identifiers, such as OpenSSL's 2.16.840.1.101.3.4.1.42: a string
# whose every version-like token has five or more dot-separated parts.
# Release versions almost never have more than four (zlib 1.3.1.1), so a
# string that also holds a token of two to four parts is kept. One known
# exception is dropped: numpy's OpenBLAS, "OpenBLAS 0.3.34.106.0 …". The
# token is the one ``strings`` uses to list a string at all, as text.
TOKEN = re.compile(VERSION_TOKEN.pattern.decode("ascii"))
OID_MIN_PARTS = 5


def only_oids(text: str) -> bool:
    """Whether every version-like token in ``text`` is an object identifier."""
    tokens = TOKEN.findall(text)
    return bool(tokens) and all(t.count(".") + 1 >= OID_MIN_PARTS for t in tokens)


def usable(record: StringRecord) -> bool:
    """Whether a ``strings`` record is in a data section and isn't noise."""
    text = record["text"]
    if record["section"] not in DATA_SECTIONS or only_oids(text):
        return False
    return not any(pattern.search(text) for pattern in NOISE)
