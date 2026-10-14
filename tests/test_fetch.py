import hashlib
import io
import json
import urllib.error
import urllib.request
import urllib.response
from collections.abc import Iterator
from email.message import Message
from pathlib import Path

import pytest

from pypiscan.cli import main
from pypiscan.fetch import SCHEMA_VERSION, cache_path, download, fetch_release
from pypiscan.pypi import (
    PyPIError,
    UrllibClient,
    WheelFile,
    release_files,
    select_target,
    target_platforms,
    target_tags,
)

RECORDED = Path(__file__).with_name("pypi")


def wheel_body(filename: str) -> bytes:
    # The recorded responses' digests are of these bytes (see tests/pypi).
    return f"recorded wheel {filename}\n".encode()


class RecordedClient:
    """Serves PyPI's JSON API from tests/pypi and wheels from wheel_body()."""

    def __init__(self, overrides: dict[str, bytes] | None = None) -> None:
        self.requested: list[str] = []
        self.overrides = overrides or {}

    def stream(self, url: str) -> Iterator[bytes]:
        self.requested.append(url)
        if url in self.overrides:
            yield self.overrides[url]
            return
        prefix = "https://pypi.org/pypi/"
        if url.startswith(prefix) and url.endswith("/json"):
            name, version = url.removeprefix(prefix).split("/")[:2]
            path = RECORDED / f"{name}-{version}.json"
            if not path.is_file():
                raise PyPIError(f"{url}: HTTP 404")
            yield path.read_bytes()
            return
        body = wheel_body(url.rsplit("/", 1)[1])
        yield body[:5]
        yield body[5:]


def entries(name: str) -> list[dict[str, object]]:
    return release_files(RecordedClient(), *name.rsplit("-", 1))


def target_filename(name: str) -> str | None:
    wheel = select_target(entries(name))
    return wheel.filename if wheel else None


def test_platforms_follow_pips_order() -> None:
    platforms = target_platforms()
    assert platforms[:2] == ["manylinux_2_28_x86_64", "manylinux_2_27_x86_64"]
    assert platforms[-2:] == ["manylinux_2_5_x86_64", "manylinux1_x86_64"]
    i = platforms.index("manylinux_2_17_x86_64")
    assert platforms[i + 1] == "manylinux2014_x86_64"
    assert "manylinux2010_x86_64" in platforms


def test_tags_exclude_pure_python() -> None:
    tags = target_tags()
    assert str(tags[0]) == "cp312-cp312-manylinux_2_28_x86_64"
    assert all(tag.platform != "any" for tag in tags)
    assert not any(tag.interpreter == "cp313" for tag in tags)


@pytest.mark.parametrize(
    ("release", "expected"),
    [
        # Newest allowed glibc beats 2_17; the yanked build-2 wheel, 2_34,
        # musl, aarch64, macOS, Windows, cp313 and pure-Python files lose.
        ("demo-1.0", "demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"),
        # cp311-abi3 outranks cp39-abi3 even with older glibc, as in pip.
        (
            "abi3demo-2.0",
            "abi3demo-2.0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        ),
        (
            "bindemo-0.5",
            "bindemo-0.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        ),
        ("puredemo-3.1", None),
    ],
)
def test_select_target(release: str, expected: str | None) -> None:
    assert target_filename(release) == expected


def wheel_entry(filename: str, **fields: object) -> dict[str, object]:
    return {
        "filename": filename,
        "url": f"https://files.example/{filename}",
        "digests": {"sha256": "00" * 32},
        "size": 1,
        "upload_time_iso_8601": "2026-09-01T12:00:00Z",
        "packagetype": "bdist_wheel",
        "yanked": False,
        "requires_python": None,
        **fields,
    }


def test_select_target_prefers_highest_build_number() -> None:
    chosen = select_target(
        [
            wheel_entry("x-1-1-cp312-cp312-manylinux_2_28_x86_64.whl"),
            wheel_entry("x-1-3-cp312-cp312-manylinux_2_28_x86_64.whl"),
            wheel_entry("x-1-cp312-cp312-manylinux_2_28_x86_64.whl"),
        ]
    )
    assert chosen is not None
    assert chosen.filename == "x-1-3-cp312-cp312-manylinux_2_28_x86_64.whl"


def test_select_target_honours_requires_python() -> None:
    chosen = select_target(
        [
            wheel_entry(
                "x-1-cp312-cp312-manylinux_2_28_x86_64.whl", requires_python=">=3.13"
            ),
            wheel_entry(
                "x-1-cp312-abi3-manylinux_2_28_x86_64.whl", requires_python="  "
            ),
            wheel_entry(
                "x-1-cp311-abi3-manylinux_2_28_x86_64.whl", requires_python="bogus"
            ),
        ]
    )
    assert chosen is not None
    assert chosen.filename == "x-1-cp312-abi3-manylinux_2_28_x86_64.whl"


def test_select_target_ignores_bad_filenames() -> None:
    assert select_target([wheel_entry("not-a-wheel.whl"), {"packagetype": 1}]) is None


def test_select_target_rejects_malformed_entry() -> None:
    entry = wheel_entry("x-1-cp312-cp312-manylinux_2_28_x86_64.whl", size="1")
    with pytest.raises(PyPIError, match="malformed file entry"):
        select_target([entry])


@pytest.mark.parametrize(
    ("body", "message"),
    [(b"<html>", "not JSON"), (b"[]", "no 'urls' list"), (b"{}", "no 'urls' list")],
)
def test_release_files_rejects_bad_responses(body: bytes, message: str) -> None:
    client = RecordedClient({"https://pypi.org/pypi/x/1/json": body})
    with pytest.raises(PyPIError, match=message):
        release_files(client, "x", "1")


def test_fetch_downloads_and_verifies(tmp_path: Path) -> None:
    client = RecordedClient()
    record = fetch_release(client, "demo", "1.0", tmp_path)

    filename = "demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"
    body = wheel_body(filename)
    sha256 = hashlib.sha256(body).hexdigest()
    path = tmp_path / "wheels" / sha256 / filename
    assert record == {
        "schema_version": SCHEMA_VERSION,
        "name": "demo",
        "version": "1.0",
        "filename": filename,
        "url": client.requested[1],
        "sha256": sha256,
        "size": len(body),
        "upload_time": "2026-09-01T12:00:00.123456Z",
        "path": str(path),
    }
    assert client.requested[0] == "https://pypi.org/pypi/demo/1.0/json"
    assert path.read_bytes() == body
    assert [p.name for p in path.parent.iterdir()] == [filename]


def test_fetch_reuses_cached_wheel(tmp_path: Path) -> None:
    fetch_release(RecordedClient(), "demo", "1.0", tmp_path)
    client = RecordedClient()
    fetch_release(client, "demo", "1.0", tmp_path)
    assert client.requested == ["https://pypi.org/pypi/demo/1.0/json"]


def recorded_wheel(release: str) -> WheelFile:
    wheel = select_target(entries(release))
    assert wheel is not None
    return wheel


def test_download_replaces_corrupt_cache_entry(tmp_path: Path) -> None:
    wheel = recorded_wheel("demo-1.0")
    dest = cache_path(tmp_path, wheel)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"truncated")
    assert download(RecordedClient(), wheel, tmp_path).read_bytes() == wheel_body(
        wheel.filename
    )


def test_download_rejects_sha256_mismatch(tmp_path: Path) -> None:
    wheel = recorded_wheel("demo-1.0")
    client = RecordedClient({wheel.url: b"tampered"})
    with pytest.raises(PyPIError, match="does not match"):
        download(client, wheel, tmp_path)
    assert list(cache_path(tmp_path, wheel).parent.iterdir()) == []


def test_fetch_without_target(tmp_path: Path) -> None:
    with pytest.raises(PyPIError, match=r"puredemo==3\.1 has no target wheel"):
        fetch_release(RecordedClient(), "puredemo", "3.1", tmp_path)


def test_cli_fetch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["fetch", "abi3demo==2.0", "--cache-dir", str(tmp_path)]
    assert main(argv, client=RecordedClient()) == 0
    record = json.loads(capsys.readouterr().out)
    assert record["filename"].startswith("abi3demo-2.0-cp311-abi3-manylinux_2_17")
    assert Path(record["path"]).is_file()


def test_cli_fetch_reports_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["fetch", "missing==1.0", "--cache-dir", str(tmp_path)]
    assert main(argv, client=RecordedClient()) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "pypiscan fetch: error: https://pypi.org/pypi/missing/1.0/json: HTTP 404\n"
    )


@pytest.mark.parametrize("spec", ["demo", "demo>=1.0", "demo==", "==1.0", "demo==x!y"])
def test_cli_fetch_rejects_bad_release(
    spec: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["fetch", spec, "--cache-dir", str(tmp_path)], client=RecordedClient())
    assert exc.value.code == 2
    assert "expected <name>==<version>" in capsys.readouterr().err


class RecordedResponse(urllib.response.addinfourl):
    msg = "recorded"


class FakeHTTPS(urllib.request.BaseHandler):
    """Answers HTTPS requests in-process, standing in for the network."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def https_open(self, req: urllib.request.Request) -> RecordedResponse:
        if self.status < 0:
            raise urllib.error.URLError("connection refused")
        return RecordedResponse(
            io.BytesIO(self.body), Message(), req.full_url, self.status
        )


def urllib_client(status: int, body: bytes = b"") -> UrllibClient:
    opener = urllib.request.OpenerDirector()
    for handler in (
        FakeHTTPS(status, body),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return UrllibClient(opener)


def test_urllib_client_streams_body() -> None:
    body = b"x" * (3 << 20)
    assert b"".join(urllib_client(200, body).stream("https://h/x")) == body


@pytest.mark.parametrize(
    ("status", "message"), [(404, "HTTP 404"), (-1, "connection refused")]
)
def test_urllib_client_raises_pypi_error(status: int, message: str) -> None:
    with pytest.raises(PyPIError, match=message):
        list(urllib_client(status).stream("https://h/x"))


@pytest.mark.parametrize("url", ["http://pypi.org/x", "file:///etc/passwd"])
def test_urllib_client_refuses_non_https(url: str) -> None:
    with pytest.raises(PyPIError, match="refusing non-HTTPS URL"):
        list(UrllibClient().stream(url))
