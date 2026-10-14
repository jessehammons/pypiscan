"""Read a release from PyPI's JSON API and choose its target wheel.

The target is the wheel pip would choose for CPython 3.12 on manylinux
x86_64 with glibc 2.28 or older. Yanked files are never chosen, and
pure-Python (``-any``) wheels are not targets.
"""

import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import Tag, compatible_tags, cpython_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

PYPI_JSON = "https://pypi.org/pypi"
PYTHON_VERSION = (3, 12)
INTERPRETER = "cp312"
ARCH = "x86_64"
MAX_GLIBC_MINOR = 28
MIN_GLIBC_MINOR = 5
# PEP 600's aliases for the legacy manylinux tags.
LEGACY_MANYLINUX = {17: "manylinux2014", 12: "manylinux2010", 5: "manylinux1"}
CHUNK_SIZE = 1 << 20
TIMEOUT_SECONDS = 60
SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class PyPIError(Exception):
    """PyPI couldn't be read, or its response doesn't make sense."""


class HttpClient(Protocol):
    """Fetches an HTTPS URL. Tests replace it with recorded responses."""

    def stream(self, url: str) -> Iterator[bytes]:
        """Yield the response body in chunks; raise PyPIError on failure."""
        ...


def _https_opener() -> urllib.request.OpenerDirector:
    # No file, ftp or plain-http handlers: only HTTPS URLs can be opened, and
    # a redirect to anything else fails.
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


class UrllibClient:
    """The standard library's HTTP client, restricted to HTTPS."""

    def __init__(self, opener: urllib.request.OpenerDirector | None = None) -> None:
        self._opener = opener if opener is not None else _https_opener()

    def stream(self, url: str) -> Iterator[bytes]:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise PyPIError(f"refusing non-HTTPS URL: {url}")
        try:
            with self._opener.open(url, timeout=TIMEOUT_SECONDS) as response:
                while chunk := response.read(CHUNK_SIZE):
                    yield chunk
        except urllib.error.HTTPError as exc:
            raise PyPIError(f"{url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            raise PyPIError(f"{url}: {exc}") from exc


@dataclass(frozen=True)
class WheelFile:
    filename: str
    url: str
    sha256: str
    size: int
    upload_time: str


def target_platforms() -> list[str]:
    """Platform tags in pip's order: newest glibc first, aliases after."""
    platforms: list[str] = []
    for minor in range(MAX_GLIBC_MINOR, MIN_GLIBC_MINOR - 1, -1):
        platforms.append(f"manylinux_2_{minor}_{ARCH}")
        if minor in LEGACY_MANYLINUX:
            platforms.append(f"{LEGACY_MANYLINUX[minor]}_{ARCH}")
    return platforms


def target_tags() -> list[Tag]:
    """The target's supported tags, most preferred first, as pip ranks them."""
    platforms = target_platforms()
    supported = [
        *cpython_tags(PYTHON_VERSION, [INTERPRETER], platforms),
        *compatible_tags(PYTHON_VERSION, INTERPRETER, platforms),
    ]
    return [tag for tag in supported if tag.platform != "any"]


def _requires_python_ok(spec: object) -> bool:
    if not isinstance(spec, str) or not spec.strip():
        return True
    try:
        specifiers = SpecifierSet(spec)
    except InvalidSpecifier:
        # pip ignores a Requires-Python it can't parse.
        return True
    return specifiers.contains(".".join(map(str, PYTHON_VERSION)), prereleases=True)


def _object(value: object) -> dict[str, object]:
    return cast(dict[str, object], value) if isinstance(value, dict) else {}


def _wheel_file(entry: dict[str, object]) -> WheelFile:
    filename = entry.get("filename")
    url = entry.get("url")
    sha256 = _object(entry.get("digests")).get("sha256")
    size = entry.get("size")
    uploaded = entry.get("upload_time_iso_8601")
    if (
        not isinstance(filename, str)
        or not isinstance(url, str)
        or not isinstance(sha256, str)
        or not isinstance(size, int)
        or not isinstance(uploaded, str)
    ):
        raise PyPIError(f"malformed file entry: {filename!r}")
    # Both become cache path components, so neither may leave the cache.
    if not SHA256_HEX.fullmatch(sha256):
        raise PyPIError(f"{filename}: sha256 is not 64 lowercase hex digits")
    if Path(filename).name != filename or filename in ("", ".."):
        raise PyPIError(f"{filename!r}: filename is not a single path component")
    return WheelFile(filename, url, sha256, size, uploaded)


def select_target(entries: list[dict[str, object]]) -> WheelFile | None:
    """Choose the target wheel from a release's ``urls`` entries, or None."""
    priority = {tag: rank for rank, tag in enumerate(target_tags())}
    best: tuple[tuple[int, tuple[()] | tuple[int, str]], WheelFile] | None = None
    for entry in entries:
        filename = entry.get("filename")
        if (
            entry.get("packagetype") != "bdist_wheel"
            or entry.get("yanked") is True
            or not isinstance(filename, str)
            or not _requires_python_ok(entry.get("requires_python"))
        ):
            continue
        try:
            _, _, build, tags = parse_wheel_filename(filename)
        except InvalidWheelFilename:
            continue
        ranks = [priority[tag] for tag in tags if tag in priority]
        if not ranks:
            continue
        # pip prefers the most specific tag, then the highest build number.
        key = (-min(ranks), build)
        if best is None or key > best[0]:
            best = (key, _wheel_file(entry))
    return best[1] if best else None


def release_files(
    client: HttpClient, name: str, version: str
) -> list[dict[str, object]]:
    """The ``urls`` entries of one release from PyPI's JSON API."""
    url = f"{PYPI_JSON}/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json"
    body = b"".join(client.stream(url))
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise PyPIError(f"{url}: response is not JSON") from exc
    files = _object(data).get("urls")
    if not isinstance(files, list):
        raise PyPIError(f"{url}: response has no 'urls' list")
    return [_object(entry) for entry in cast(list[object], files)]
