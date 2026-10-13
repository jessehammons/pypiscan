"""zlib and its derivative zlib-ng.

zlib-ng carries zlib's deflate and inflate banners (2.3.3 has classic zlib
1.3.1's banners byte for byte), so only its own identity string tells the two
apart: ``zlibng_string`` in 2.0.x (" zlib-ng 2.0.6 forked from zlib") and
``vstring`` from 2.1.0 on (" zlib-ng 2.3.3").
"""

import re

from pypiscan.fingerprint import Detector, Pattern

# Library strings start with their own distinctive text and end with NUL. The
# byte before them can be unrelated data, so they don't require a boundary.
# Header strings are bare versions, so they must not follow a printable byte.
_START = rb"(?<![\x20-\x7e])"
_VERSION = rb"(?P<version>[0-9][0-9A-Za-z.\-]*)"
_FILE_VERSION = rb"\.so\.(?P<version>[0-9][0-9A-Za-z.\-]*)"

ZLIB = Detector(
    patterns=(
        Pattern(
            "zlib",
            "library_string",
            re.compile(
                rb" deflate "
                + _VERSION
                + rb" Copyright 1995(?:-[0-9]{4})? Jean-loup Gailly"
                + rb"(?: and Mark Adler)? \x00"
            ),
            # " and Mark Adler" from v1.2.3.5; v0.71-v0.95 carry no version.
            "madler/zlib deflate.c (deflate_copyright) @ v0.99-v1.3.2; "
            "file:line per tag in tests/upstream/zlib.tsv",
        ),
        Pattern(
            "zlib",
            "library_string",
            re.compile(
                rb" inflate "
                + _VERSION
                + rb" Copyright 1995(?:-[0-9]{4})? Mark Adler \x00"
            ),
            "madler/zlib inftrees.c (inflate_copyright) @ v0.99-v1.3.2; "
            "file:line per tag in tests/upstream/zlib.tsv",
        ),
        Pattern(
            "zlib-ng",
            "library_string",
            re.compile(rb" zlib-ng " + _VERSION + rb"(?: forked from zlib)?\x00"),
            "zlib-ng/zlib-ng zutil.c (zlibng_string) @ 1.9.9-b1-2.0.7, "
            "(vstring) @ 2.1.0-beta1-2.3.3; file:line per tag in "
            "tests/upstream/zlib-ng.tsv",
        ),
        Pattern(
            "zlib-ng",
            "header_string",
            re.compile(_START + rb"(?P<version>[0-9]+(?:\.[0-9]+)+\.zlib-ng)\x00"),
            "zlib-ng/zlib-ng zlib.h (ZLIB_VERSION, compat mode) @ 1.9.9-b1-2.0.7, "
            "zlib.h.in @ 2.1.0-beta1-2.3.3; file:line per tag in "
            "tests/upstream/zlib-ng.tsv",
        ),
    ),
    filename_patterns=(
        Pattern(
            "zlib",
            "filename",
            re.compile(rb"libz(?:-[0-9a-f]{8})?" + _FILE_VERSION),
            "auditwheel-renamed or plain libz.so.<version>",
        ),
        Pattern(
            "zlib-ng",
            "filename",
            re.compile(rb"libz-ng(?:-[0-9a-f]{8})?" + _FILE_VERSION),
            "auditwheel-renamed or plain libz-ng.so.<version>",
        ),
    ),
    derivatives={"zlib-ng": "zlib"},
)
