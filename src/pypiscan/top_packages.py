"""Choose the full package list from a ranking of PyPI projects (roadmap 3.6).

Projects are walked in rank order. Each one's latest final release is the
highest version with no pre-release or dev part, skipping releases with no
unyanked file. A project is kept if ``pypi.select_target`` finds a target
wheel in that release's files, and the walk stops once ``limit`` are kept.
Wheel size isn't checked here: the size limit is applied when scanning.

A project passed over is recorded with its reason (roadmap C.7): from its
latest final release's unyanked files when it has one, or
``no_final_release`` when it doesn't.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import cast

from packaging.tags import Tag
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from pypiscan.package_list import MAX_PACKAGES, Package
from pypiscan.pypi import (
    ARCH,
    LEGACY_MANYLINUX,
    MAX_GLIBC_MINOR,
    HttpClient,
    project_versions,
    release_files,
    select_target,
    target_tags,
)

# Why a project with a final release has no target wheel, in the order
# ``no_target_reason`` decides them; the first that fits wins.
NO_TARGET_REASONS = (
    "sdist_only",
    "pure_python",
    "other_platforms",
    "glibc_newer_than_2_28",
    "no_cp312_or_abi3",
    "other",
)
NO_FINAL_RELEASE = "no_final_release"

_MANYLINUX = re.compile(rf"manylinux_2_(\d+)_{ARCH}")
_LEGACY_GLIBC = {f"{alias}_{ARCH}": minor for minor, alias in LEGACY_MANYLINUX.items()}


class SnapshotError(Exception):
    """The top-pypi-packages snapshot doesn't have the expected shape."""


@dataclass(frozen=True)
class Snapshot:
    last_update: str
    sha256: str
    names: list[str]


@dataclass(frozen=True)
class PassedOver:
    rank: int
    name: str
    # Empty for a project with no final release.
    version: str
    reason: str


@dataclass
class Selection:
    packages: list[Package] = field(default_factory=list[Package])
    # The rank of the last project examined, counting from 1.
    stop_rank: int = 0
    # Projects passed over: no target wheel in the latest final release,
    # with a reason from NO_TARGET_REASONS, or no final release with an
    # unyanked file at all, with reason NO_FINAL_RELEASE.
    no_target: list[PassedOver] = field(default_factory=list[PassedOver])
    no_release: list[PassedOver] = field(default_factory=list[PassedOver])


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


def _glibc_minor(platform: str) -> int | None:
    """The glibc 2.N a manylinux x86_64 platform tag needs, or None."""
    if match := _MANYLINUX.fullmatch(platform):
        return int(match.group(1))
    return _LEGACY_GLIBC.get(platform)


def no_target_reason(files: list[dict[str, object]]) -> str:
    """Why a release's files hold no target wheel: one of NO_TARGET_REASONS.

    Only unyanked files count. A wheel whose name doesn't parse adds no
    tags, so a release with only such wheels is ``other``.
    """
    unyanked = [f for f in files if f.get("yanked") is not True]
    names = [
        f.get("filename") for f in unyanked if f.get("packagetype") == "bdist_wheel"
    ]
    if not names:
        return "sdist_only"
    tags: set[Tag] = set()
    for name in names:
        try:
            tags |= parse_wheel_filename(name)[3] if isinstance(name, str) else set()
        except InvalidWheelFilename:
            continue
    if not tags:
        return "other"
    if all(tag.platform == "any" for tag in tags):
        return "pure_python"
    glibc = {tag: m for tag in tags if (m := _glibc_minor(tag.platform)) is not None}
    if not glibc:
        return "other_platforms"
    # Interpreter and ABI pairs the target accepts on some platform.
    accepted = {(t.interpreter, t.abi) for t in target_tags()}
    minors = [m for tag, m in glibc.items() if (tag.interpreter, tag.abi) in accepted]
    if not minors:
        return "no_cp312_or_abi3"
    if min(minors) > MAX_GLIBC_MINOR:
        return "glibc_newer_than_2_28"
    return "other"


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
            selection.no_release.append(PassedOver(rank, name, "", NO_FINAL_RELEASE))
        elif select_target(release[1]) is None:
            reason = no_target_reason(release[1])
            selection.no_target.append(PassedOver(rank, name, release[0], reason))
        else:
            selection.packages.append(Package(name, release[0]))
    return selection
