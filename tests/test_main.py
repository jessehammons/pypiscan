import os
import runpy
import sys
import zipfile
from pathlib import Path

import pytest

from elf_builder import build_elf


@pytest.fixture
def wheel(tmp_path: Path) -> Path:
    path = tmp_path / "foo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("foo/_ext.so", build_elf(["libc.so.6"]))
    return path


def run_entry_point(monkeypatch: pytest.MonkeyPatch, *args: str) -> int | None:
    monkeypatch.setattr(sys, "argv", ["pypiscan", *args])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("pypiscan", run_name="__main__")
    code = excinfo.value.code
    assert code is None or isinstance(code, int)
    return code


def test_exits_with_main_status(
    wheel: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_entry_point(monkeypatch, "inspect", str(wheel)) == 0
    assert '"path": "foo/_ext.so"' in capsys.readouterr().out


def test_broken_pipe_exits_1_quietly(
    wheel: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    stdout = os.fdopen(write_fd, "w")
    try:
        monkeypatch.setattr(sys, "stdout", stdout)
        assert run_entry_point(monkeypatch, "inspect", str(wheel)) == 1
        # stdout's descriptor now points at devnull, so a later flush succeeds.
        stdout.write("more")
        stdout.flush()
    finally:
        stdout.close()
    assert capsys.readouterr().err == ""
