"""Download a release's target wheel into the cache and verify its sha256."""

import hashlib
from pathlib import Path
from typing import TypedDict

from pypiscan.pypi import HttpClient, PyPIError, WheelFile, release_files, select_target

SCHEMA_VERSION = 1


class FetchRecord(TypedDict):
    schema_version: int
    name: str
    version: str
    filename: str
    url: str
    sha256: str
    size: int
    upload_time: str
    path: str


def cache_path(cache_dir: Path, wheel: WheelFile) -> Path:
    """Wheels are cached by sha256, keeping their filename inside."""
    return cache_dir / "wheels" / wheel.sha256 / wheel.filename


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def download(client: HttpClient, wheel: WheelFile, cache_dir: Path) -> Path:
    """Return the cached wheel, downloading it first unless it's already there.

    The download goes to a ``.partial`` file that is renamed only once its
    sha256 matches PyPI's, so the cache never holds an unverified wheel.
    """
    dest = cache_path(cache_dir, wheel)
    if dest.is_file() and _sha256(dest) == wheel.sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".partial")
    digest = hashlib.sha256()
    try:
        with partial.open("wb") as f:
            for chunk in client.stream(wheel.url):
                digest.update(chunk)
                f.write(chunk)
        if digest.hexdigest() != wheel.sha256:
            raise PyPIError(
                f"{wheel.filename}: sha256 {digest.hexdigest()} does not match "
                f"PyPI's {wheel.sha256}"
            )
        partial.replace(dest)
    finally:
        partial.unlink(missing_ok=True)
    return dest


def fetch_release(
    client: HttpClient, name: str, version: str, cache_dir: Path
) -> FetchRecord:
    """Resolve ``name==version``'s target wheel and download it into the cache."""
    wheel = select_target(release_files(client, name, version))
    if wheel is None:
        raise PyPIError(f"{name}=={version} has no target wheel")
    path = download(client, wheel, cache_dir)
    return {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "version": version,
        "filename": wheel.filename,
        "url": wheel.url,
        "sha256": wheel.sha256,
        "size": wheel.size,
        "upload_time": wheel.upload_time,
        "path": str(path),
    }
