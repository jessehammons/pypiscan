import hashlib
import json
from collections.abc import Iterator

import pytest

from pypiscan.package_list import Package
from pypiscan.pypi import PyPIError, project_versions
from pypiscan.top_packages import (
    SnapshotError,
    latest_final_release,
    read_snapshot,
    select_packages,
)

SIMPLE = "https://pypi.org/simple/{}/?format=application/vnd.pypi.simple.v1+json"
RELEASE = "https://pypi.org/pypi/{}/{}/json"
TARGET_TAG = "cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64"


def wheel(name: str, version: str, tag: str = TARGET_TAG, **extra: object) -> object:
    filename = f"{name}-{version}-{tag}.whl"
    return {
        "filename": filename,
        "packagetype": "bdist_wheel",
        "url": f"https://files.pythonhosted.org/{filename}",
        "digests": {"sha256": hashlib.sha256(filename.encode()).hexdigest()},
        "size": 1000,
        "upload_time_iso_8601": "2026-10-01T00:00:00.000000Z",
        "yanked": False,
        **extra,
    }


def sdist(name: str, version: str, **extra: object) -> object:
    return {"filename": f"{name}-{version}.tar.gz", "packagetype": "sdist", **extra}


class RecordedClient:
    """Serves PyPI's Simple API and per-release JSON from a dict of projects.

    ``projects`` maps a normalized name to its releases, each a list of the
    JSON API's ``urls`` entries.
    """

    def __init__(self, projects: dict[str, dict[str, list[object]]]) -> None:
        self.responses: dict[str, bytes] = {}
        self.requested: list[str] = []
        for name, releases in projects.items():
            simple = {"meta": {"api-version": "1.4"}, "name": name, "files": []}
            simple["versions"] = list(releases)
            self.responses[SIMPLE.format(name)] = json.dumps(simple).encode()
            for version, files in releases.items():
                body = json.dumps({"info": {}, "urls": files}).encode()
                self.responses[RELEASE.format(name, version)] = body

    def stream(self, url: str) -> Iterator[bytes]:
        self.requested.append(url)
        if url not in self.responses:
            raise PyPIError(f"{url}: HTTP 404")
        yield self.responses[url]


def test_latest_final_release_skips_pre_dev_and_yanked() -> None:
    client = RecordedClient(
        {
            "demo": {
                "1.9": [wheel("demo", "1.9")],
                "1.10": [sdist("demo", "1.10", yanked=True)],
                "1.10.post1": [wheel("demo", "1.10.post1", yanked=True)],
                "1.11": [],
                "2.0rc1": [wheel("demo", "2.0rc1")],
                "2.0.dev3": [wheel("demo", "2.0.dev3")],
                "not a version": [wheel("demo", "9")],
            }
        }
    )
    release = latest_final_release(client, "demo")
    assert release is not None
    assert release[0] == "1.9"
    # Final releases only, highest first, and nothing below the one chosen.
    assert client.requested[1:] == [
        RELEASE.format("demo", v) for v in ["1.11", "1.10.post1", "1.10", "1.9"]
    ]


def test_post_release_and_partly_yanked_release_count() -> None:
    files = [wheel("demo", "1.0.post1", yanked=True), sdist("demo", "1.0.post1")]
    client = RecordedClient(
        {"demo": {"1.0": [sdist("demo", "1.0")], "1.0.post1": files}}
    )
    assert latest_final_release(client, "demo") == ("1.0.post1", files)


def test_no_final_release() -> None:
    client = RecordedClient({"demo": {"1.0b1": [sdist("demo", "1.0b1")]}})
    assert latest_final_release(client, "demo") is None


def test_select_packages_in_rank_order() -> None:
    client = RecordedClient(
        {
            "binary": {"2.0": [wheel("binary", "2.0")]},
            "pure": {"1.0": [wheel("pure", "1.0", "py3-none-any")]},
            "prerelease-only": {"0.1a1": [wheel("prerelease_only", "0.1a1")]},
            "abi3": {"5.0": [wheel("abi3", "5.0", "cp39-abi3-manylinux_2_28_x86_64")]},
            "unreached": {"1.0": [wheel("unreached", "1.0")]},
        }
    )
    names = ["binary", "pure", "prerelease-only", "abi3", "unreached"]
    selection = select_packages(names, client, limit=2)
    assert selection.packages == [Package("binary", "2.0"), Package("abi3", "5.0")]
    assert selection.stop_rank == 4
    assert selection.no_target == ["pure"]
    assert selection.no_release == ["prerelease-only"]
    assert not any("unreached" in url for url in client.requested)


def test_select_packages_runs_out_of_names() -> None:
    client = RecordedClient({"pure": {"1.0": [sdist("pure", "1.0")]}})
    selection = select_packages(["pure"], client)
    assert selection.packages == []
    assert selection.stop_rank == 1
    assert selection.no_target == ["pure"]


def test_simple_api_uses_the_normalized_name() -> None:
    client = RecordedClient({"typing-extensions": {"4.16.0": []}})
    assert project_versions(client, "Typing_Extensions") == ["4.16.0"]
    assert client.requested == [SIMPLE.format("typing-extensions")]


@pytest.mark.parametrize(
    ("body", "message"),
    [(b"<html>", "not JSON"), (b'{"files": []}', "no 'versions' list")],
)
def test_bad_simple_api_response(body: bytes, message: str) -> None:
    client = RecordedClient({})
    client.responses[SIMPLE.format("demo")] = body
    with pytest.raises(PyPIError, match=message):
        project_versions(client, "demo")


def test_read_snapshot() -> None:
    body = json.dumps(
        {
            "last_update": "2026-10-01 12:40:51",
            "rows": [
                {"download_count": 3, "project": "boto3"},
                {"download_count": 2, "project": "packaging"},
            ],
        }
    ).encode()
    snapshot = read_snapshot(body)
    assert snapshot.last_update == "2026-10-01 12:40:51"
    assert snapshot.sha256 == hashlib.sha256(body).hexdigest()
    assert snapshot.names == ["boto3", "packaging"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json", "not JSON"),
        (b"[]", "not a JSON object"),
        (b'{"rows": []}', "no 'last_update' or 'rows'"),
        (b'{"last_update": "x", "rows": [{"project": 1}]}', "row 1 has no"),
        (b'{"last_update": "x", "rows": ["boto3"]}', "row 1 has no"),
    ],
)
def test_bad_snapshot(body: bytes, message: str) -> None:
    with pytest.raises(SnapshotError, match=message):
        read_snapshot(body)
