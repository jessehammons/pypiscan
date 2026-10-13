"""zlib and its derivative zlib-ng.

zlib-ng carries zlib's deflate and inflate banners (2.3.3 has classic zlib
1.3.1's banners byte for byte), so only its own identity string tells the two
apart: ``zlibng_string`` in 2.0.x (" zlib-ng 2.0.6 forked from zlib") and
``vstring`` from 2.1.0 on (" zlib-ng 2.3.3").
"""

import re

from pypiscan.fingerprint import Citation, Detector, Pattern

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
            (
                Citation("madler/zlib", "v1.3.2", "deflate.c", 55, "deflate_copyright"),
                # Before v1.2.3.5, no " and Mark Adler".
                Citation(
                    "madler/zlib", "v1.2.3.4", "deflate.c", 55, "deflate_copyright"
                ),
                # A single year, not a range.
                Citation(
                    "madler/zlib", "v1.0-pre", "deflate.c", 54, "deflate_copyright"
                ),
                # zlib-ng carries the banner too; see the module docstring.
                Citation(
                    "zlib-ng/zlib-ng", "2.3.3", "deflate.c", 61, "deflate_copyright"
                ),
            ),
        ),
        Pattern(
            "zlib",
            "library_string",
            re.compile(
                rb" inflate "
                + _VERSION
                + rb" Copyright 1995(?:-[0-9]{4})? Mark Adler \x00"
            ),
            (
                Citation(
                    "madler/zlib", "v1.3.2", "inftrees.c", 26, "inflate_copyright"
                ),
                # A single year, not a range.
                Citation(
                    "madler/zlib", "v1.0-pre", "inftrees.c", 9, "inflate_copyright"
                ),
                Citation(
                    "zlib-ng/zlib-ng", "2.3.3", "inftrees.c", 10, "inflate_copyright"
                ),
            ),
        ),
        Pattern(
            "zlib-ng",
            "library_string",
            re.compile(rb" zlib-ng " + _VERSION + rb"(?: forked from zlib)?\x00"),
            (
                Citation("zlib-ng/zlib-ng", "2.3.3", "zutil.c", 24, "vstring"),
                # Named zlibng_string, worded "... forked from zlib", until 2.1.0.
                Citation("zlib-ng/zlib-ng", "2.0.7", "zutil.c", 24, "zlibng_string"),
            ),
        ),
        Pattern(
            "zlib-ng",
            "header_string",
            re.compile(_START + rb"(?P<version>[0-9]+(?:\.[0-9]+)+\.zlib-ng)\x00"),
            # Compat mode; the header became a template in 2.1.0.
            (
                Citation("zlib-ng/zlib-ng", "2.3.3", "zlib.h.in", 61, "ZLIB_VERSION"),
                Citation("zlib-ng/zlib-ng", "2.0.7", "zlib.h", 57, "ZLIB_VERSION"),
            ),
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
