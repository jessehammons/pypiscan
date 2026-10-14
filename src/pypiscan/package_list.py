"""Load a package list: the pinned releases a scan runs over, in order.

A package list is a CSV file with the header ``name,version`` and one row
per release, at most ``MAX_PACKAGES`` rows. Names must not collide after
PEP 503 normalization.
"""

import csv
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import Version

MAX_PACKAGES = 100
COLUMNS = ["name", "version"]


class PackageListError(Exception):
    """The package list can't be read or breaks one of its rules."""


@dataclass(frozen=True)
class Package:
    name: str
    version: str


def check_release(name: str, version: str) -> None:
    """Raise ValueError unless ``name==version`` names a valid release.

    The name must be a valid project name and the version a PEP 440 version.
    Both are kept as given, not normalized.
    """
    canonicalize_name(name, validate=True)
    Version(version)


def load_package_list(path: Path) -> list[Package]:
    """Read and validate a package list, keeping its rows in order."""
    try:
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            rows = [(reader.line_num, row) for row in reader]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise PackageListError(f"{path}: {exc}") from exc
    if header != COLUMNS:
        raise PackageListError(
            f"{path}: header must be {','.join(COLUMNS)}, got {header!r}"
        )
    packages: list[Package] = []
    seen: dict[str, int] = {}
    for line, row in rows:
        where = f"{path}:{line}"
        if not row:
            continue
        if len(row) != len(COLUMNS) or not all(row):
            raise PackageListError(f"{where}: expected a name and a version")
        name, version = row
        try:
            check_release(name, version)
        except ValueError as exc:
            raise PackageListError(f"{where}: {exc}") from exc
        key = canonicalize_name(name)
        if key in seen:
            raise PackageListError(
                f"{where}: {name!r} is the same package as line {seen[key]}"
            )
        seen[key] = line
        packages.append(Package(name, version))
        if len(packages) > MAX_PACKAGES:
            raise PackageListError(f"{path}: more than {MAX_PACKAGES} packages")
    if not packages:
        raise PackageListError(f"{path}: no packages")
    return packages
