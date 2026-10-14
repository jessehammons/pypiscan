"""Load the library map: which upstream library each `.libs/` prefix holds.

See README "The library map". The map is a CSV file with the columns in
``COLUMNS``, one row per prefix, library and way of identifying it. A
``skip`` row has every column empty except ``prefix`` and ``library``. A
mapped row needs a repo and tags, which ``tag_matcher`` compiles, and no
identity in version 1. A row with a kind is a recognizer: its pattern
compiles with ``matcher``, and a ``library_string`` or ``bare_version``
row cites an ``identity_file``. A row with no kind marks a library that is
identified but has no recognizer yet. ``cpe`` and ``osv`` may be empty
until the CVE table (roadmap 6.1) requires them.
"""

import csv
import re
from dataclasses import dataclass
from pathlib import Path

COLUMNS = [
    "prefix",
    "library",
    "repo",
    "tags",
    "kind",
    "pattern",
    "identity_file",
    "identity",
    "cpe",
    "osv",
]
KINDS = ("library_string", "build_path", "bare_version")
SKIP = "skip"
# Columns every row for one library agrees on.
SHARED = ("repo", "tags", "cpe", "osv")

PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
# A digit followed by letters, digits, ".", "+", "~" or "-".
VERSION = r"\d[0-9A-Za-z.+~-]*"
# Nothing around a bare version anchors it: three or more numbers.
BARE_VERSION = r"\d+(?:\.\d+){2,}"
# In tags, a version can also be spelled with "_" (REL_18_6).
TAG_VERSION = r"\d[0-9A-Za-z._+~-]*"


class LibraryMapError(Exception):
    """The library map can't be read or breaks one of its rules."""


@dataclass(frozen=True)
class MapRow:
    prefix: str
    library: str
    repo: str
    tags: str
    kind: str
    pattern: str
    identity_file: str
    identity: str
    cpe: str
    osv: str


def _split(column: str, text: str, allowed: set[str]) -> list[str]:
    """Split ``text`` into literals and placeholder names, alternating.

    Raises ``ValueError`` unless it has exactly one ``{version}`` and only
    ``allowed`` placeholders.
    """
    parts = PLACEHOLDER.split(text)
    names = parts[1::2]
    unknown = sorted(set(names) - allowed)
    if unknown:
        raise ValueError(f"{column} has an unknown placeholder {{{unknown[0]}}}")
    if names.count("version") != 1:
        raise ValueError(f"{column} needs exactly one {{version}}")
    return parts


def matcher(pattern: str, kind: str) -> re.Pattern[str]:
    """Compile ``pattern`` for ``fullmatch``, with the version as group 1.

    ``{version}`` captures the version, ``{any}`` matches any text, including
    none, and everything else matches literally. Raises ``ValueError`` for
    a pattern a ``kind`` row can't have.
    """
    parts = _split("pattern", pattern, {"version", "any"})
    if kind == "bare_version" and pattern != "{version}":
        raise ValueError("a bare_version pattern is {version}")
    version = BARE_VERSION if kind == "bare_version" else VERSION
    regex = "".join(
        re.escape(part)
        if i % 2 == 0
        else (f"({version})" if part == "version" else ".*?")
        for i, part in enumerate(parts)
    )
    return re.compile(regex, re.DOTALL)


def tag_matcher(tags: str) -> re.Pattern[str]:
    """Compile a tags value for ``fullmatch``, with the version as group 1."""
    parts = _split("tags", tags, {"version"})
    return re.compile(f"{re.escape(parts[0])}({TAG_VERSION}){re.escape(parts[2])}")


def tag_version(text: str) -> str:
    """A version as a tag spells it, with "_" or "-" between digits as "."."""
    return re.sub(r"(?<=\d)[_-](?=\d)", ".", text)


def _row_problem(row: dict[str, str]) -> str | None:
    """Why ``row`` doesn't fit its kind, or ``None`` if it's valid."""
    missing = [name for name in ("prefix", "library") if not row[name]]
    if missing:
        return f"{', '.join(missing)} is empty"
    if row["library"] == SKIP:
        filled = [name for name in COLUMNS[2:] if row[name]]
        if filled:
            return f"a skip row has only a prefix and library, but {filled[0]} is set"
        return None
    missing = [name for name in ("repo", "tags") if not row[name]]
    if missing:
        return f"{', '.join(missing)} is empty"
    if row["identity"]:
        return "identity is empty in version 1"
    try:
        # A typo here would make phase 06 match no tags.
        _split("tags", row["tags"], {"version"})
    except ValueError as exc:
        return str(exc)
    kind = row["kind"]
    if not kind:
        filled = [n for n in ("pattern", "identity_file") if row[n]]
        if filled:
            return f"a row with no kind has no {', '.join(filled)}"
        return None
    if kind not in KINDS:
        return f"unknown kind {kind!r}; expected one of {', '.join(KINDS)}"
    if not row["pattern"]:
        return "pattern is empty"
    if kind == "build_path" and row["identity_file"]:
        return "a build_path row has no identity_file"
    if kind != "build_path" and not row["identity_file"]:
        return f"a {kind} row needs an identity_file"
    try:
        matcher(row["pattern"], kind)
    except ValueError as exc:
        return str(exc)
    return None


def _clash(row: MapRow, earlier: list[tuple[int, MapRow]]) -> str | None:
    """Why ``row`` can't follow the ``earlier`` rows, with their lines."""
    for line, other in earlier:
        if other.prefix == row.prefix and (other.library == SKIP) != (
            row.library == SKIP
        ):
            return f"prefix {row.prefix!r} is both skip and mapped (see line {line})"
        if row.library == SKIP or other.library != row.library:
            continue
        if other.prefix == row.prefix and not (other.kind and row.kind):
            return (
                f"library {row.library!r} under prefix {row.prefix!r} has a row "
                f"with no kind, which must be its only row (see line {line})"
            )
        differ = [n for n in SHARED if getattr(other, n) != getattr(row, n)]
        if differ:
            return (
                f"library {row.library!r} has another {', '.join(differ)} "
                f"(see line {line})"
            )
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
    result: list[tuple[int, MapRow]] = []
    for line, fields in rows:
        if not fields:
            continue
        where = f"{path}:{line}"
        if len(fields) != len(COLUMNS):
            raise LibraryMapError(
                f"{where}: expected {len(COLUMNS)} fields, got {len(fields)}"
            )
        values = dict(zip(COLUMNS, fields, strict=True))
        row = MapRow(**values)
        problem = _row_problem(values) or _clash(row, result)
        if problem:
            raise LibraryMapError(f"{where}: {problem}")
        result.append((line, row))
    return [row for _, row in result]
