"""Choose the full package list from a ranking of PyPI projects (roadmap 3.6).

Projects are walked in rank order. Each one's latest final release is the
highest version with no pre-release or dev part, skipping releases with no
unyanked file. A project is kept if ``pypi.select_target`` finds a target
wheel in that release's files, and the walk stops once ``limit`` are kept.
Wheel size isn't checked here: the size limit is applied when scanning.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import cast

from packaging.version import InvalidVersion, Version

from pypiscan.package_list import MAX_PACKAGES, Package
from pypiscan.pypi import (
    HttpClient,
    project_versions,
    release_files,
    select_target,
)


class SnapshotError(Exception):
    """The top-pypi-packages snapshot doesn't have the expected shape."""


@dataclass(frozen=True)
class Snapshot:
    last_update: str
    sha256: str
    names: list[str]


@dataclass
class Selection:
    packages: list[Package] = field(default_factory=list[Package])
    # The rank of the last project examined, counting from 1.
    stop_rank: int = 0
    # Projects passed over: no target wheel in the latest final release, or
    # no final release with an unyanked file at all.
    no_target: list[str] = field(default_factory=list[str])
    no_release: list[str] = field(default_factory=list[str])


def read_snapshot(body: bytes) -> Snapshot:
    """Parse a top-pypi-packages JSON snapshot; its rows are in rank order."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise SnapshotError("snapshot is not JSON") from exc
    if not isinstance(data, dict):
        raise SnapshotError("snapshot is not a JSON object")
    data = cast(dict[str, object], data)
    last_update = data.get("last_update")
    rows = data.get("rows")
    if not isinstance(last_update, str) or not isinstance(rows, list):
        raise SnapshotError("snapshot has no 'last_update' or 'rows'")
    names: list[str] = []
    for row in cast(list[object], rows):
        name = (
            cast(dict[str, object], row).get("project")
            if isinstance(row, dict)
            else None
        )
        if not isinstance(name, str):
            raise SnapshotError(f"row {len(names) + 1} has no project name")
        names.append(name)
    return Snapshot(last_update, hashlib.sha256(body).hexdigest(), names)


def _final(version: str) -> Version | None:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return None
    return parsed if parsed.pre is None and parsed.dev is None else None


def latest_final_release(
    client: HttpClient, name: str
) -> tuple[str, list[dict[str, object]]] | None:
    """The latest final release with an unyanked file, and its files."""
    finals = [
        (parsed, v)
        for v in project_versions(client, name)
        if (parsed := _final(v)) is not None
    ]
    for _, version in sorted(finals, reverse=True):
        files = release_files(client, name, version)
        if any(entry.get("yanked") is not True for entry in files):
            return version, files
    return None


def select_packages(
    names: Sequence[str], client: HttpClient, limit: int = MAX_PACKAGES
) -> Selection:
    """Walk ``names`` in rank order, keeping up to ``limit`` projects."""
    selection = Selection()
    for rank, name in enumerate(names, start=1):
        if len(selection.packages) >= limit:
            break
        selection.stop_rank = rank
        release = latest_final_release(client, name)
        if release is None:
            selection.no_release.append(name)
        elif select_target(release[1]) is None:
            selection.no_target.append(name)
        else:
            selection.packages.append(Package(name, release[0]))
    return selection
