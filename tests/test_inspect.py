import hashlib
import json
import struct
import zipfile
from pathlib import Path

import pytest

from pypiscan.cli import main
from pypiscan.wheel_inspect import (
    SCHEMA_VERSION,
    WheelError,
    inspect_wheel,
)

# ELF64 little-endian layouts: file header, program header, section header,
# dynamic entry.
_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
_PHDR = struct.Struct("<IIQQQQQQ")
_SHDR = struct.Struct("<IIQQQQIIQQ")
_DYN = struct.Struct("<qQ")
_PT_LOAD, _PT_DYNAMIC = 1, 2
_SHT_STRTAB, _SHT_DYNAMIC = 3, 6
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ = 0, 1, 5, 10


def _align(n: int, to: int = 8) -> int:
    return -(-n // to) * to


def build_elf(
    needed: list[str] | None,
    *,
    section_headers: bool = True,
    unmapped_strtab: bool = False,
    trailer: bytes = b"",
) -> bytes:
    """Build a minimal x86_64 shared object for pyelftools to parse.

    ``needed=None`` builds a statically linked image with no ``PT_DYNAMIC``
    segment. Virtual addresses equal file offsets, so one ``PT_LOAD`` maps the
    whole file and ``DT_STRTAB`` resolves even without section headers;
    ``unmapped_strtab`` points it outside the file instead.
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
            out += _DYN.pack(_DT_NEEDED, offset)
        out += _DYN.pack(_DT_STRTAB, 0x7FFF0000 if unmapped_strtab else dynstr_off)
        out += _DYN.pack(_DT_STRSZ, dynstr_size)
        out += _DYN.pack(_DT_NULL, 0)
        dyn_size = len(out) - dyn_off

    shoff = shnum = shstrndx = 0
    if section_headers:
        shstrtab = b"\0.dynstr\0.dynamic\0.shstrtab\0"
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
                           1, 0, 8, _DYN.size)
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
        phdrs += _PHDR.pack(_PT_DYNAMIC, 6, dyn_off, dyn_off, dyn_off,
                            dyn_size, dyn_size, 8)  # fmt: skip
    out[_EHDR.size : _EHDR.size + len(phdrs)] = phdrs
    return bytes(out)


LIBS_ELF = build_elf(["libc.so.6"], trailer=b"libz payload")
EXT_ELF = build_elf(["libz-abc123.so.1.3.1", "libc.so.6"])

# Stripped images whose DT_NEEDED entry is corrupt after the fact: a name that
# isn't UTF-8, and a name offset near 2**64.
_STRIPPED = build_elf(["libz.so.1"], section_headers=False)
NON_UTF8_NAME_ELF = _STRIPPED.replace(b"libz.so.1", b"libz\xff.so1")
HUGE_NAME_OFFSET_ELF = _STRIPPED.replace(
    _DYN.pack(_DT_NEEDED, 1), _DYN.pack(_DT_NEEDED, 0xFFFFFFFFFFFFFFF0)
)


def build_wheel(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("foo.libs/"), b"")
        zf.writestr(zipfile.ZipInfo("foo/"), b"")
        for name, data in members.items():
            zf.writestr(name, data)
    return path


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    return build_wheel(
        tmp_path / "foo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        {
            "foo.libs/libz-abc123.so.1.3.1": LIBS_ELF,
            "foo/_speedups.cpython-312-x86_64-linux-gnu.so": EXT_ELF,
            "foo/__init__.py": b"print('not elf')\n",
            "foo/empty.so": b"",
            "foo/short.so": b"\x7fEL",
            "foo-1.0.dist-info/RECORD": b"",
        },
    )


def test_lists_only_elf_members(wheel: Path) -> None:
    records = inspect_wheel(wheel)

    assert records == [
        {
            "schema_version": SCHEMA_VERSION,
            "wheel": wheel.name,
            "path": "foo.libs/libz-abc123.so.1.3.1",
            "size": len(LIBS_ELF),
            "sha256": hashlib.sha256(LIBS_ELF).hexdigest(),
            "in_libs_dir": True,
            "needed": ["libc.so.6"],
        },
        {
            "schema_version": SCHEMA_VERSION,
            "wheel": wheel.name,
            "path": "foo/_speedups.cpython-312-x86_64-linux-gnu.so",
            "size": len(EXT_ELF),
            "sha256": hashlib.sha256(EXT_ELF).hexdigest(),
            "in_libs_dir": False,
            "needed": ["libz-abc123.so.1.3.1", "libc.so.6"],
        },
    ]


def test_schema_version_is_2() -> None:
    assert SCHEMA_VERSION == 2


@pytest.mark.parametrize(
    ("elf", "expected"),
    [
        pytest.param(build_elf(["libc.so.6"]), ["libc.so.6"], id="one"),
        pytest.param(
            build_elf(["libpng16.so.16", "libz.so.1", "libm.so.6"]),
            ["libpng16.so.16", "libz.so.1", "libm.so.6"],
            id="order-kept",
        ),
        pytest.param(build_elf([]), [], id="dynamic-no-needed"),
        pytest.param(build_elf(None), [], id="static"),
        pytest.param(
            build_elf(["libz.so.1"], section_headers=False),
            ["libz.so.1"],
            id="stripped-section-headers",
        ),
        pytest.param(
            build_elf(["libz.so.1"], section_headers=False, unmapped_strtab=True),
            None,
            id="unresolvable-strtab",
        ),
        pytest.param(NON_UTF8_NAME_ELF, None, id="non-utf8-name"),
        pytest.param(HUGE_NAME_OFFSET_ELF, None, id="huge-name-offset"),
        pytest.param(b"\x7fELF" + b"\xff" * 100, None, id="malformed"),
        pytest.param(b"\x7fELF", None, id="magic-only"),
    ],
)
def test_needed(tmp_path: Path, elf: bytes, expected: list[str] | None) -> None:
    whl = build_wheel(tmp_path / "x.whl", {"x.libs/libx.so": elf})

    (record,) = inspect_wheel(whl)

    assert record["needed"] == expected
    assert record["size"] == len(elf)


def test_large_member_is_hashed_in_full(tmp_path: Path) -> None:
    data = build_elf(["libc.so.6"], trailer=bytes(range(256)) * 10_000)
    whl = build_wheel(tmp_path / "big.whl", {"big.libs/libbig.so": data})

    (record,) = inspect_wheel(whl)

    assert record["size"] == len(data)
    assert record["sha256"] == hashlib.sha256(data).hexdigest()
    assert record["needed"] == ["libc.so.6"]


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        ("foo.libs/libz.so", True),
        ("foo.libs/sub/libz.so", True),
        ("foo/bar.libs/libz.so", False),
        ("foo.libs", False),
        ("foolibs/libz.so", False),
    ],
)
def test_in_libs_dir_uses_top_level_directory(
    tmp_path: Path, member: str, expected: bool
) -> None:
    whl = build_wheel(tmp_path / "x.whl", {member: LIBS_ELF})

    (record,) = inspect_wheel(whl)

    assert record["in_libs_dir"] is expected


def test_wheel_without_elf_yields_nothing(tmp_path: Path) -> None:
    whl = build_wheel(tmp_path / "pure.whl", {"pure/__init__.py": b""})

    assert inspect_wheel(whl) == []


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(WheelError, match="no such file"):
        inspect_wheel(tmp_path / "missing.whl")


def test_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(WheelError, match="no such file"):
        inspect_wheel(tmp_path)


def test_non_zip_raises(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"this is not a zip archive")

    with pytest.raises(WheelError, match="not a valid zip file"):
        inspect_wheel(bogus)


def test_corrupt_member_raises(tmp_path: Path) -> None:
    whl = tmp_path / "corrupt.whl"
    with zipfile.ZipFile(whl, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("foo.libs/libz.so", LIBS_ELF)
    raw = bytearray(whl.read_bytes())
    raw[raw.index(b"libz payload")] ^= 0xFF  # breaks the member's CRC
    whl.write_bytes(bytes(raw))

    with pytest.raises(WheelError, match="not a valid zip file"):
        inspect_wheel(whl)


def test_cli_prints_json_lines(wheel: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inspect", str(wheel)]) == 0

    out, err = capsys.readouterr()
    lines = out.splitlines()
    assert [json.loads(line) for line in lines] == inspect_wheel(wheel)
    assert err == ""


@pytest.mark.parametrize("name", ["missing.whl", "bogus.whl"])
def test_cli_errors_exit_nonzero(
    tmp_path: Path, name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "bogus.whl").write_bytes(b"not a zip")

    assert main(["inspect", str(tmp_path / name)]) == 1

    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("pypiscan inspect: error: ")
    assert name in err


def test_cli_requires_wheel_argument() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["inspect"])
    assert excinfo.value.code == 2
