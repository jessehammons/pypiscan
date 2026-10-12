"""Suite-wide policy: tests never touch the network, with no per-test opt-out.

pytest-socket blocks sockets via ``--disable-socket`` in addopts. The hook
below rejects its per-test escape hatches so the block can't be bypassed.
"""

import pytest

pytest_plugins = ["pytester"]

FORBIDDEN_MARKERS = frozenset({"enable_socket"})
FORBIDDEN_FIXTURES = frozenset({"socket_enabled"})


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    offenders: list[str] = []
    for item in items:
        markers = {m.name for m in item.iter_markers()} & FORBIDDEN_MARKERS
        fixtures = set(getattr(item, "fixturenames", ())) & FORBIDDEN_FIXTURES
        offenders.extend(
            f"{item.nodeid}: {name}" for name in sorted(markers | fixtures)
        )
    if offenders:
        raise pytest.UsageError(
            "Tests must not enable network access; use recorded responses "
            "instead. Offending tests:\n  " + "\n  ".join(offenders)
        )
