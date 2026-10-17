"""Malformed archives become errors, not crashes, in every zip reader.

Each archive is a stored zip with one member, written by hand so that any
header field can be set, then given one case's bytes. Each case expects the
exception zipfile raised for it on Python 3.13.
"""

import hashlib
import lzma
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from pypiscan import wheel_sboms
from pypiscan.cli import main
from pypiscan.package_list import Package
from pypiscan.scan import (
    Line,
    MemberError,
    inspect_phase,
    read_members,
    sboms_phase,
)
from pypiscan.wheel_inspect import WheelError, inspect_wheel
from pypiscan.wheel_sboms import SbomRecord, sboms_wheel
from pypiscan.wheel_strings import strings_wheel

MEMBER = "demo-1.0.dist-info/sboms/a.json"


def stored(
    data: bytes = b"{}",
    *,
    name: bytes = MEMBER.encode(),
    flags: int = 0,
    method: int = zipfile.ZIP_STORED,
    offset: int = 0,
    extra: bytes = b"",
) -> bytes:
    """A zip holding one member: its local header, its central directory
    entry (with ``extra``) and the end of central directory record."""
    common = (flags, method, 0, 0, zlib.crc32(data), len(data), len(data), len(name))
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, *common, 0) + name + data
    entry = struct.pack(
        "<4s6H3L5H2L", b"PK\x01\x02", 20, 20, *common, len(extra), 0, 0, 0, 0, offset
    )
    central = entry + name + extra
    end = struct.pack(
        "<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0
    )
    return local + central + end


# zipfile's LZMA member header (LZMA SDK 9.20, 5 bytes of properties), valid
# LZMA1 properties, then compressed data that is garbage.
LZMA_DATA = b"\x09\x14\x05\x00" + b"\x5d\x00\x00\x80\x00" + b"\xff" * 32
# A zip64 extra field giving the local header's offset as 2**64 - 2.
ZIP64_OFFSET = struct.pack("<2HQ", 1, 8, 2**64 - 2)

# Each case's archive, and what zipfile raises for it.
CASES: dict[str, tuple[bytes, type[Exception]]] = {
    "encrypted": (stored(flags=0x1), RuntimeError),
    "unknown_method": (stored(method=99), NotImplementedError),
    "strong_encryption": (stored(flags=0x40), NotImplementedError),
    "patched_data": (stored(flags=0x20), NotImplementedError),
    "corrupt_lzma": (stored(LZMA_DATA, method=zipfile.ZIP_LZMA), lzma.LZMAError),
    "corrupt_bzip2": (
        stored(b"BZh9" + b"\xff" * 32, method=zipfile.ZIP_BZIP2),
        OSError,
    ),
    "name_not_utf8": (
        stored(name=b"demo-1.0.dist-info/sboms/\xff.json", flags=0x800),
        UnicodeDecodeError,
    ),
    "zip64_offset": (stored(offset=0xFFFFFFFF, extra=ZIP64_OFFSET), ValueError),
    # Cut before the local header, so the recorded offsets point before the
    # start of the file.
    "truncated": (stored()[10:], OSError),
}


@pytest.fixture(params=sorted(CASES))
def case(
    request: pytest.FixtureRequest, tmp_path: Path
) -> tuple[Path, type[Exception]]:
    data, raised = CASES[request.param]
    wheel = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"
    wheel.write_bytes(data)
    return wheel, raised


def test_the_unpatched_archive_is_valid(tmp_path: Path) -> None:
    wheel = tmp_path / "demo.whl"
    wheel.write_bytes(stored())
    [record] = sboms_wheel(wheel)
    assert (record["path"], record["format"]) == (MEMBER, "other")


def check(exc: Exception, raised: type[Exception]) -> None:
    """``exc`` was raised from ``raised``, and only OSError keeps its own
    message."""
    assert isinstance(exc.__cause__, raised)
    assert ("not a valid zip file" in str(exc)) is not issubclass(raised, OSError)


def test_readers_raise_their_errors(case: tuple[Path, type[Exception]]) -> None:
    wheel, raised = case
    for reader in (inspect_wheel, strings_wheel, sboms_wheel):
        with pytest.raises(WheelError) as info:
            reader(wheel)
        check(info.value, raised)
    with pytest.raises(MemberError) as member_info:
        read_members(wheel, {MEMBER: "0" * 64})
    check(member_info.value, raised)


def test_sbom_cli_exits_1(
    case: tuple[Path, type[Exception]], capsys: pytest.CaptureFixture[str]
) -> None:
    wheel, _ = case
    assert main(["sbom", str(wheel)]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("pypiscan sbom: error: ")


def test_phases_03_and_09_give_error_lines(case: tuple[Path, type[Exception]]) -> None:
    wheel, _ = case
    earlier: dict[str, Line] = {
        "01-resolve": {"sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()},
        "02-fetch": {"path": str(wheel)},
    }
    package = Package("demo", "1.0")
    for phase in (inspect_phase(), sboms_phase()):
        result = phase.run(package, earlier)
        assert result.status == "error"
        assert str(wheel) in str(result.reason)


def test_parsing_errors_arent_zip_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / "demo.whl"
    wheel.write_bytes(stored())

    def fails(data: bytes, record: SbomRecord) -> None:
        raise ValueError("from parsing")

    monkeypatch.setattr(wheel_sboms, "_read", fails)
    with pytest.raises(ValueError, match="from parsing") as info:
        sboms_wheel(wheel)
    assert type(info.value) is ValueError
