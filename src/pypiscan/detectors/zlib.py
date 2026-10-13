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
                + rb" Copyright 1995-[0-9]{4} Jean-loup Gailly and Mark Adler \x00"
            ),
            "madler/zlib deflate.c:54-55 @ v1.3.2 (deflate_copyright)",
        ),
        Pattern(
            "zlib",
            "library_string",
            re.compile(
                rb" inflate " + _VERSION + rb" Copyright 1995-[0-9]{4} Mark Adler \x00"
            ),
            "madler/zlib inftrees.c:25-26 @ v1.3.2 (inflate_copyright)",
        ),
        Pattern(
            "zlib-ng",
            "library_string",
            re.compile(rb" zlib-ng " + _VERSION + rb"(?: forked from zlib)?\x00"),
            "zlib-ng/zlib-ng zutil.c:23-24 @ 2.0.0-2.0.7 (zlibng_string), "
            "@ 2.1.0-beta1-2.3.3 (vstring)",
        ),
        Pattern(
            "zlib-ng",
            "header_string",
            re.compile(_START + rb"(?P<version>[0-9]+(?:\.[0-9]+)+\.zlib-ng)\x00"),
            "zlib-ng/zlib-ng zlib.h.in:61 @ 2.3.3 (ZLIB_VERSION, compat mode)",
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
