"""The version function decoder: its code shapes, encodings and ELF lookup.

See README "Version function machine code". ELF images are built by
``elf_builder.build_dso``; no real binaries are committed.
"""

import pytest

from elf_builder import STT_OBJECT, Symbol, build_dso, build_elf
from pypiscan.library_map import parse_version_function
from pypiscan.version_function import Returned, Shape, match, shape, version

ENDBR64 = "f3 0f 1e fa "
# Each shape, with "imm" for a 32-bit immediate, as README "Version function
# machine code" gives them.
PLAIN_INTEGER = "b8 imm c3"
PLAIN_STRING = "48 8d 05 imm c3"
PLAIN_OUT = "c7 07 imm c7 06 imm c7 02 imm c3"
FRAMED_INTEGER = "55 48 89 e5 b8 imm 5d c3"
FRAMED_STRING = "55 48 89 e5 48 8d 05 imm 5d c3"
FRAMED_OUT = (
    "55 48 89 e5 48 89 7d f8 48 89 75 f0 48 89 55 e8 "
    "48 8b 45 f8 c7 00 imm 48 8b 45 f0 c7 00 imm "
    "48 8b 45 e8 c7 00 imm 90 5d c3"
)
# Each shape, the immediates to fill in, and its result.
SHAPES = [
    (PLAIN_INTEGER, (0x10600,), Returned("integer", (0x10600,))),
    (PLAIN_STRING, (0x43DD17,), Returned("string", (0x43DD17,), 7)),
    (PLAIN_OUT, (4, 3, 5), Returned("out", (4, 3, 5))),
    (FRAMED_INTEGER, (0x10600,), Returned("integer", (0x10600,))),
    (FRAMED_STRING, (0x43DD17,), Returned("string", (0x43DD17,), 11)),
    (FRAMED_OUT, (4, 3, 5), Returned("out", (4, 3, 5))),
]


def code(text: str, *values: int) -> bytes:
    """``text``'s bytes, with each "imm" filled in from ``values``."""
    filled = iter(values)
    return b"".join(
        next(filled).to_bytes(4, "little", signed=True)
        if part == "imm"
        else bytes.fromhex(part)
        for part in text.split()
    )


@pytest.mark.parametrize(("text", "values", "returned"), SHAPES)
def test_every_shape(text: str, values: tuple[int, ...], returned: Returned) -> None:
    raw = code(text, *values)
    assert shape(raw) == returned
    # A shape's bytes after its ret are ignored.
    assert shape(raw + b"\xcc\xcc") == returned
    end = returned.end + 4 if returned.shape == "string" else 0
    assert shape(code(ENDBR64) + raw) == Returned(returned.shape, values, end)


def test_lcms2_framed_integer() -> None:
    # Pillow 12.3.0's liblcms2 cmsGetEncodedCMMversion, built unoptimized.
    found = shape(bytes.fromhex("55 48 89 e5 b8 8e 08 00 00 5d c3"))
    assert found == Returned("integer", (2190,))


def test_immediates_are_signed_little_endian() -> None:
    assert shape(bytes.fromhex("b8 ff ff ff ff c3")) == Returned("integer", (-1,))
    assert shape(bytes.fromhex("b8 01 02 03 04 c3")) == Returned(
        "integer", (0x04030201,)
    )


@pytest.mark.parametrize(("text", "values", "returned"), SHAPES)
def test_anything_else_gives_nothing(
    text: str, values: tuple[int, ...], returned: Returned
) -> None:
    raw = code(text, *values)
    # Truncated, or a trailing byte other than ret.
    assert shape(raw[:-1]) is None
    assert shape(raw[:-1] + b"\xc2") is None
    assert shape(raw[:-1] + b"\x90\xc3") is None
    # A wrong byte anywhere outside the immediates.
    offsets = [i for i, part in enumerate(_bytes(text)) if part]
    assert len(offsets) == len(raw) - 4 * len(values)
    for i in offsets:
        assert shape(raw[:i] + bytes([raw[i] ^ 0x01]) + raw[i + 1 :]) is None
    # endbr64 only comes first, and once.
    assert shape(code(ENDBR64 + ENDBR64) + raw) is None
    assert shape(b"\x90" + raw) is None


def _bytes(text: str) -> list[bool]:
    """For each byte of ``text``, whether it's outside an immediate."""
    return [
        flag
        for part in text.split()
        for flag in ([False] * 4 if part == "imm" else [True])
    ]


def test_empty_code_gives_nothing() -> None:
    assert shape(b"") is None


def read(pattern: str, values: tuple[int, ...], kind: Shape = "integer") -> object:
    return version(Returned(kind, values), parse_version_function(f"f -> {pattern}"))


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("bits *.8.8", 0x10600, ("0x10600", "1.6.0")),
        ("bits *.8.8", 0x1020304, ("0x1020304", "258.3.4")),
        ("bits *.12.12", 0x1002000, ("0x1002000", "1.2.0")),
        ("bits *.12.12", 0x1000009, ("0x1000009", "1.0.9")),
        ("bits *.8.8", 0, ("0x0", "0.0.0")),
        ("bits *.8.8", -1, None),
        ("decimal *.4 from 100000", 170011, ("170011", "17.11")),
        ("decimal *.4 from 100000", 100000, ("100000", "10.0")),
        ("decimal *.4 from 100000", 99999, None),
        ("decimal *.2.2 from 0", 90624, ("90624", "9.6.24")),
        ("decimal *.4 from 0", -5, None),
    ],
)
def test_integer_encodings(
    pattern: str, value: int, expected: tuple[str, str] | None
) -> None:
    assert read(pattern, (value,)) == expected


def test_out_encoding() -> None:
    assert read("out", (4, 3, 5), "out") == ("4, 3, 5", "4.3.5")
    assert read("out", (0, 0, 0), "out") == ("0, 0, 0", "0.0.0")
    for values in [(-1, 3, 5), (4, -3, 5), (4, 3, -5)]:
        assert read("out", values, "out") is None


def test_string_encoding() -> None:
    returned = Returned("string", (0,), 7)
    avif = parse_version_function("avifVersion -> string {version}")
    assert version(returned, avif, "1.4.2") == ('"1.4.2"', "1.4.2")
    # The whole string must match.
    assert version(returned, avif, "v1.4.2") is None
    dav1d = parse_version_function("dav1d_version -> string {version}-0-g{any}")
    assert version(returned, dav1d, "1.5.3-0-gb546257") == (
        '"1.5.3-0-gb546257"',
        "1.5.3",
    )
    # A build made between releases.
    assert version(returned, dav1d, "1.5.3-4-gabcdef0") is None
    assert version(returned, dav1d, None) is None


def test_shape_must_fit_the_encoding() -> None:
    integer = Returned("integer", (0x10600,))
    out = Returned("out", (4, 3, 5))
    string = Returned("string", (0,), 7)
    bits = parse_version_function("f -> bits *.8.8")
    assert version(out, bits) is None
    assert version(string, bits, "1.6.0") is None
    assert version(integer, parse_version_function("f -> out")) is None
    assert version(integer, parse_version_function("f -> string {version}")) is None


# The ELF part.

WEBP = parse_version_function("WebPGetDecoderVersion -> bits *.8.8")
AVIF = parse_version_function("avifVersion -> string {version}")


def lea(disp: int) -> bytes:
    return b"\x48\x8d\x05" + disp.to_bytes(4, "little", signed=True) + b"\xc3"


def test_lookup() -> None:
    text = b"\xcc" * 3 + code(PLAIN_INTEGER, 0x10600)
    data = build_dso(text, [Symbol("Other", 0), Symbol("WebPGetDecoderVersion", 3)])
    found = match(data, "libwebp", WEBP)
    assert found is not None
    assert (found.library, found.kind, found.text, found.version) == (
        "libwebp",
        "version_function_machine_code",
        "WebPGetDecoderVersion: 0x10600",
        "1.6.0",
    )
    # The offset is the function's first byte in the file, in .text.
    assert found.offset is not None
    assert data[found.offset :].startswith(code(PLAIN_INTEGER, 0x10600))
    assert found.section == ".text"
    # Mapped through PT_LOAD at another load address, it's the same.
    moved = build_dso(text, [Symbol("WebPGetDecoderVersion", 3)], vaddr=0x7000)
    assert match(moved, "libwebp", WEBP) is not None


@pytest.mark.parametrize(
    "symbols",
    [
        [],
        [Symbol("WebPGetDecoderVersion", defined=False)],
        [Symbol("WebPGetDecoderVersion", type=STT_OBJECT)],
        [Symbol("WebPGetDecoderVersion", 0), Symbol("WebPGetDecoderVersion", 8)],
    ],
    ids=["absent", "undefined", "not-a-function", "two-addresses"],
)
def test_symbol_that_gives_nothing(symbols: list[Symbol]) -> None:
    text = code(PLAIN_INTEGER, 0x10600) + b"\xcc\xcc" + code(PLAIN_INTEGER, 0x10600)
    assert match(build_dso(text, symbols), "libwebp", WEBP) is None


def test_two_entries_at_one_address_are_one_function() -> None:
    symbols = [Symbol("WebPGetDecoderVersion"), Symbol("WebPGetDecoderVersion")]
    assert match(build_dso(code(PLAIN_INTEGER, 0x10600), symbols), "libwebp", WEBP)


def test_code_running_past_the_segment_gives_nothing() -> None:
    symbols = [Symbol("WebPGetDecoderVersion")]
    whole = build_dso(code(PLAIN_INTEGER, 0x10600), symbols)
    found = match(whole, "libwebp", WEBP)
    assert found is not None and found.offset is not None
    # The segment ends one byte before the ret.
    cut = build_dso(code(PLAIN_INTEGER, 0x10600), symbols, load_size=found.offset + 5)
    assert match(cut, "libwebp", WEBP) is None
    exact = build_dso(code(PLAIN_INTEGER, 0x10600), symbols, load_size=found.offset + 6)
    assert match(exact, "libwebp", WEBP) is not None
    # A function outside the segment altogether.
    assert (
        match(
            build_dso(code(PLAIN_INTEGER, 0x10600), symbols, load_size=64),
            "libwebp",
            WEBP,
        )
        is None
    )


def avif(after: bytes, disp: int = 1, **kw: int) -> object:
    data = build_dso(lea(disp) + after, [Symbol("avifVersion")], **kw)
    found = match(data, "libavif", AVIF)
    return None if found is None else (found.text, found.version)


def test_string_target() -> None:
    # The target is just after the lea plus the displacement.
    assert avif(b"1.4.2\0") == ('avifVersion: "1.4.2"', "1.4.2")
    assert avif(b"\0" * 4 + b"1.4.2\0", 5) == ('avifVersion: "1.4.2"', "1.4.2")
    assert avif(b"9.9.9\0" + b"1.4.2\0", 7) == ('avifVersion: "1.4.2"', "1.4.2")


def test_string_lengths() -> None:
    assert avif(b"1" * 255 + b"\0") == (f'avifVersion: "{"1" * 255}"', "1" * 255)
    # No NUL within 256 bytes, or an empty string.
    assert avif(b"1" * 256 + b"\0") is None
    assert avif(b"\0") is None


def test_string_target_that_gives_nothing() -> None:
    # Outside any segment, before or after it.
    assert avif(b"1.4.2\0", 0x10000000) is None
    assert avif(b"1.4.2\0", -0x10000000) is None
    # Not printable ASCII.
    assert avif(b"1.4\x01.2\0") is None
    assert avif(b"1.4\x7f.2\0") is None
    assert avif(b"1.4\t2\0") is None


def test_string_must_end_inside_the_segment() -> None:
    data = build_dso(lea(1) + b"1.4.2\0", [Symbol("avifVersion")])
    found = match(data, "libavif", AVIF)
    assert found is not None and found.offset is not None
    end = found.offset + 8 + 5
    cut = build_dso(lea(1) + b"1.4.2\0", [Symbol("avifVersion")], load_size=end)
    assert match(cut, "libavif", AVIF) is None


def test_image_with_no_dynsym_gives_nothing() -> None:
    assert match(build_elf([], rodata=b"\xb8\x00\x06\x01\x00\xc3"), "x", WEBP) is None


def test_result_the_encoding_rejects_gives_nothing() -> None:
    pq = parse_version_function("PQlibVersion -> decimal *.4 from 100000")
    data = build_dso(code(PLAIN_INTEGER, 90624), [Symbol("PQlibVersion")])
    assert match(data, "postgresql", pq) is None
    data = build_dso(code(PLAIN_INTEGER, 170011), [Symbol("PQlibVersion")])
    found = match(data, "postgresql", pq)
    assert found is not None and found.text == "PQlibVersion: 170011"
