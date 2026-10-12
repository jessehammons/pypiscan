import socket
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

CONFTEST = Path(__file__).with_name("conftest.py")


def test_socket_is_blocked() -> None:
    # Canary: fails if pytest-socket stops being active for the suite.
    with (
        pytest.warns(UserWarning, match=r"socket\.socket"),
        pytest.raises(SocketBlockedError),
    ):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def run_with_policy(pytester: pytest.Pytester, body: str) -> pytest.RunResult:
    pytester.makeconftest(CONFTEST.read_text())
    pytester.makepyfile(body)
    return pytester.runpytest_inprocess("--disable-socket")


def test_guard_rejects_enable_socket_marker(pytester: pytest.Pytester) -> None:
    result = run_with_policy(
        pytester,
        """
        import pytest

        @pytest.mark.enable_socket
        def test_uses_network():
            pass
        """,
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*test_uses_network: enable_socket*"])


def test_guard_rejects_socket_enabled_fixture(pytester: pytest.Pytester) -> None:
    result = run_with_policy(
        pytester,
        """
        def test_uses_network(socket_enabled):
            pass
        """,
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*test_uses_network: socket_enabled*"])


def test_guard_allows_ordinary_tests(pytester: pytest.Pytester) -> None:
    result = run_with_policy(pytester, "def test_ok():\n    pass\n")
    result.assert_outcomes(passed=1)
