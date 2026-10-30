import hashlib
import importlib.util
import json
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from pypiscan.package_list import Package
from pypiscan.pypi import PyPIError, project_versions
from pypiscan.top_packages import (
    PassedOver,
    SnapshotError,
    latest_final_release,
    no_target_reason,
    read_snapshot,
    select_packages,
)

SIMPLE = "https://pypi.org/simple/{}/?format=application/vnd.pypi.simple.v1+json"
RELEASE = "https://pypi.org/pypi/{}/{}/json"
TARGET_TAG = "cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64"
SCRIPT = Path(__file__).parent.parent / "scripts" / "top_packages.py"


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
    assert selection.no_target == [PassedOver(2, "pure", "1.0", "pure_python")]
    assert selection.no_release == [
        PassedOver(3, "prerelease-only", "", "no_final_release")
    ]
    assert not any("unreached" in url for url in client.requested)


def test_select_packages_runs_out_of_names() -> None:
    client = RecordedClient({"pure": {"1.0": [sdist("pure", "1.0")]}})
    selection = select_packages(["pure"], client)
    assert selection.packages == []
    assert selection.stop_rank == 1
    assert selection.no_target == [PassedOver(1, "pure", "1.0", "sdist_only")]


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


def reason_for(*files: object) -> str:
    return no_target_reason([cast(dict[str, object], f) for f in files])


@pytest.mark.parametrize(
    ("tags", "reason"),
    [
        ([], "sdist_only"),
        (["py3-none-any", "py2.py3-none-any"], "pure_python"),
        (["cp312-cp312-win_amd64", "cp312-cp312-macosx_11_0_arm64"], "other_platforms"),
        (["cp312-cp312-musllinux_1_2_x86_64"], "other_platforms"),
        (["cp312-cp312-manylinux_2_28_aarch64"], "other_platforms"),
        (["cp312-cp312-manylinux_2_17_i686"], "other_platforms"),
        (["cp312-cp312-manylinux_2_34_x86_64"], "glibc_newer_than_2_28"),
        (["cp39-abi3-manylinux_2_31_x86_64"], "glibc_newer_than_2_28"),
        (["py3-none-manylinux_2_39_x86_64"], "glibc_newer_than_2_28"),
        # A cp312 wheel needing new glibc beside an older one for cp311.
        (
            ["cp312-cp312-manylinux_2_34_x86_64", "cp311-cp311-manylinux_2_17_x86_64"],
            "glibc_newer_than_2_28",
        ),
        (["cp313-cp313-manylinux_2_17_x86_64"], "no_cp312_or_abi3"),
        (["cp38-cp38-manylinux1_x86_64"], "no_cp312_or_abi3"),
        (["cp313-abi3-manylinux2014_x86_64"], "no_cp312_or_abi3"),
        # A cp312 wheel for macOS only isn't a glibc problem.
        (
            ["cp312-cp312-macosx_14_0_arm64", "cp313-cp313-manylinux_2_17_x86_64"],
            "no_cp312_or_abi3",
        ),
    ],
)
def test_no_target_reason(tags: list[str], reason: str) -> None:
    files = [sdist("demo", "1.0"), *(wheel("demo", "1.0", tag) for tag in tags)]
    assert reason_for(*files) == reason


def test_no_target_reason_other() -> None:
    # requires_python excludes 3.12 from a wheel the tags would accept.
    excluded = wheel("demo", "1.0", requires_python=">=3.13")
    assert reason_for(excluded) == "other"
    unparseable = {"filename": "demo.whl", "packagetype": "bdist_wheel"}
    assert reason_for(unparseable) == "other"


def test_no_target_reason_ignores_yanked_files() -> None:
    yanked = wheel("demo", "1.0", "cp313-cp313-manylinux_2_17_x86_64", yanked=True)
    assert reason_for(sdist("demo", "1.0"), yanked) == "sdist_only"
    assert reason_for(yanked, wheel("demo", "1.0", "py3-none-any")) == ("pure_python")


@pytest.fixture(scope="module")
def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("top_packages_script", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_reads_a_local_snapshot(
    script: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = json.dumps(
        {
            "last_update": "2026-10-01 12:40:51",
            "rows": [
                {"project": "binary"},
                {"project": "new-glibc"},
                {"project": "beta"},
                {"project": "pure"},
            ],
        }
    ).encode()
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_bytes(body)
    client = RecordedClient(
        {
            "binary": {"2.0": [wheel("binary", "2.0")]},
            "new-glibc": {
                "3.1": [wheel("new_glibc", "3.1", "cp312-cp312-manylinux_2_34_x86_64")]
            },
            "beta": {"0.1b1": [sdist("beta", "0.1b1")]},
            "pure": {"1.0": [wheel("pure", "1.0", "py3-none-any")]},
        }
    )
    output = tmp_path / "list.csv"
    argv = ["--snapshot", str(snapshot), "--output", str(output)]

    assert script.main(argv, client) == 0

    assert not any("hugovk" in url for url in client.requested)
    assert output.read_text() == "name,version\nbinary,2.0\n"
    assert (tmp_path / "list-no-target.csv").read_text() == (
        "rank,name,version,reason\n"
        "2,new-glibc,3.1,glibc_newer_than_2_28\n"
        "3,beta,,no_final_release\n"
        "4,pure,1.0,pure_python\n"
    )
    out = capsys.readouterr().out
    assert f"snapshot: {snapshot}\n" in out
    assert f"sha256: {hashlib.sha256(body).hexdigest()}\n" in out
    assert "stopped at rank: 4\n" in out
    assert "passed over, no target: 2\n" in out
    assert "  glibc_newer_than_2_28: 1\n" in out
    assert "  pure_python: 1\n" in out
    assert "  sdist_only: 0\n" in out
    assert "  sum of reasons: 2\n" in out
    assert "passed over, no_final_release: 1\n" in out
    assert f"reasons: {tmp_path / 'list-no-target.csv'}\n" in out
