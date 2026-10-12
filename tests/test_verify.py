import pytest

from pypiscan.cli import main, verify


def test_verify_prints_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert verify() == 0
    assert "nothing to do" in capsys.readouterr().out


def test_main_dispatches_verify(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify"]) == 0
    assert "nothing to do" in capsys.readouterr().out
