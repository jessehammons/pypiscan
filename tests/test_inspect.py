import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from pypiscan.cli import main
from pypiscan.wheel_inspect import (
    SCHEMA_VERSION,
    WheelError,
    inspect_wheel,
)

LIBS_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + b"libz payload"
EXT_ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + b"extension payload"


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
        },
        {
            "schema_version": SCHEMA_VERSION,
            "wheel": wheel.name,
            "path": "foo/_speedups.cpython-312-x86_64-linux-gnu.so",
            "size": len(EXT_ELF),
            "sha256": hashlib.sha256(EXT_ELF).hexdigest(),
            "in_libs_dir": False,
        },
    ]


def test_schema_version_is_1() -> None:
    assert SCHEMA_VERSION == 1


def test_large_member_is_hashed_in_full(tmp_path: Path) -> None:
    data = b"\x7fELF" + bytes(range(256)) * 10_000  # spans several read chunks
    whl = build_wheel(tmp_path / "big.whl", {"big.libs/libbig.so": data})

    (record,) = inspect_wheel(whl)

    assert record["size"] == len(data)
    assert record["sha256"] == hashlib.sha256(data).hexdigest()


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
