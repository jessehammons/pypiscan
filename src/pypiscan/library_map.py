"""Load the library map: which upstream library each `.libs/` prefix holds.

See README "The library map". The map is a CSV file with the columns in
``COLUMNS``, one row per prefix, library and way of identifying it. A
``skip`` row has every column empty except ``prefix``. A mapped row needs a
library, a known kind, a repo and an identity, plus an ``identity_file``
unless its kind is ``build_path``. ``cpe`` and ``osv`` may be empty until
the CVE table (roadmap 6.1) requires them.
"""

import csv
from dataclasses import dataclass
from pathlib import Path

COLUMNS = [
    "prefix",
    "library",
    "kind",
    "repo",
    "identity_file",
    "identity",
    "cpe",
    "osv",
]
KINDS = ("library_string", "build_path", "bare_version")
SKIP = "skip"


class LibraryMapError(Exception):
    """The library map can't be read or breaks one of its rules."""


@dataclass(frozen=True)
class MapRow:
    prefix: str
    library: str
    kind: str
    repo: str
    identity_file: str
    identity: str
    cpe: str
    osv: str


def _row_problem(row: dict[str, str]) -> str | None:
    """Why ``row`` doesn't fit its kind, or ``None`` if it's valid."""
    if not row["prefix"]:
        return "prefix is empty"
    if row["library"] == SKIP:
        filled = [name for name in COLUMNS[2:] if row[name]]
        if filled:
            return f"a skip row has only a prefix, but {', '.join(filled)} is set"
        return None
    missing = [
        name for name in ("library", "kind", "repo", "identity") if not row[name]
    ]
    if missing:
        return f"{', '.join(missing)} is empty"
    kind = row["kind"]
    if kind not in KINDS:
        return f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}"
    if kind == "build_path" and row["identity_file"]:
        return "a build_path row has no identity_file"
    if kind != "build_path" and not row["identity_file"]:
        return f"a {kind} row needs an identity_file"
    return None


def load_library_map(path: Path) -> list[MapRow]:
    """Read and validate a library map, keeping its rows in order."""
    try:
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            rows = [(reader.line_num, row) for row in reader]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise LibraryMapError(f"{path}: {exc}") from exc
    if header != COLUMNS:
        raise LibraryMapError(
            f"{path}: header must be {','.join(COLUMNS)}, got {header!r}"
        )
    result: list[MapRow] = []
    # Whether each prefix's first row was a skip row, and its line.
    first: dict[str, tuple[bool, int]] = {}
    for line, fields in rows:
        if not fields:
            continue
        where = f"{path}:{line}"
        if len(fields) != len(COLUMNS):
            raise LibraryMapError(
                f"{where}: expected {len(COLUMNS)} fields, got {len(fields)}"
            )
        values = dict(zip(COLUMNS, fields, strict=True))
        problem = _row_problem(values)
        if problem:
            raise LibraryMapError(f"{where}: {problem}")
        prefix, is_skip = values["prefix"], values["library"] == SKIP
        was_skip, first_line = first.setdefault(prefix, (is_skip, line))
        if was_skip != is_skip:
            raise LibraryMapError(
                f"{where}: prefix {prefix!r} is both skip and mapped "
                f"(see line {first_line})"
            )
        result.append(MapRow(**values))
    return result
