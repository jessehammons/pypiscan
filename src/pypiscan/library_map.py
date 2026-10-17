"""Load the library map: which upstream library each `.libs/` prefix holds.

See README "The library map". The map is a CSV file with the columns in
``COLUMNS``, one row per prefix, library and way of identifying it. A
``skip`` row has every column empty except ``prefix`` and ``library``. A
mapped row needs a repo and tags, which ``tag_matcher`` compiles, and no
identity in version 1. A row with a kind is a recognizer: its pattern
compiles with ``matcher``, or ``parse_version_function`` for a
``version_function_machine_code`` row, and every kind but ``build_path``
cites an ``identity_file``. A row with no kind marks a library that is
identified but has no recognizer yet. A ``bare_version`` row's prefix maps
to no other library. ``cpe`` and ``osv`` may be empty
until the CVE table (roadmap 6.1) requires them.
"""

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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
VERSION_FUNCTION = "version_function_machine_code"
KINDS = ("library_string", "build_path", VERSION_FUNCTION, "bare_version")
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
C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NUMBER = re.compile(r"\d+")


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


type Encoding = Literal["bits", "decimal", "out", "string"]


@dataclass(frozen=True)
class VersionFunction:
    """A ``version_function_machine_code`` pattern: the function's name and
    how its result gives the version (README "Version function machine
    code"). ``widths`` are the fields below the top one, most significant
    first, in bits or decimal digits; ``minimum`` is a decimal encoding's
    ``from``; ``pattern`` is a string encoding's recognizer pattern."""

    function: str
    encoding: Encoding
    widths: tuple[int, ...] = ()
    minimum: int = 0
    pattern: str = ""


def _widths(text: str) -> tuple[int, ...]:
    fields = text.split(".")
    if len(fields) < 2 or fields[0] != "*":
        raise ValueError("widths need a * and at least one more field")
    if not all(NUMBER.fullmatch(f) and int(f) > 0 for f in fields[1:]):
        raise ValueError("widths after the * are positive integers")
    return tuple(int(f) for f in fields[1:])


def parse_version_function(pattern: str) -> VersionFunction:
    """Parse a ``version_function_machine_code`` pattern. Raises
    ``ValueError`` for one that isn't ``<function> -> bits <widths>``,
    ``-> decimal <widths> from <n>``, ``-> out`` or ``-> string <pattern>``.
    """
    function, arrow, rest = pattern.partition(" -> ")
    if not arrow:
        raise ValueError("pattern is <function> -> <encoding>")
    if not C_IDENTIFIER.fullmatch(function):
        raise ValueError(f"{function!r} isn't a C identifier")
    encoding, space, rest = rest.partition(" ")
    if encoding == "bits":
        widths = _widths(rest)
        if sum(widths) > 31:
            raise ValueError("bits widths after the * total more than 31")
        return VersionFunction(function, "bits", widths)
    if encoding == "decimal":
        widths, _, minimum = rest.partition(" from ")
        if not NUMBER.fullmatch(minimum):
            raise ValueError("a decimal pattern ends with from and an integer")
        return VersionFunction(function, "decimal", _widths(widths), int(minimum))
    if encoding == "out":
        if space:
            raise ValueError("nothing follows out")
        return VersionFunction(function, "out")
    if encoding == "string":
        matcher(rest, VERSION_FUNCTION)
        return VersionFunction(function, "string", pattern=rest)
    raise ValueError(
        f"unknown encoding {encoding!r}; expected bits, decimal, out or string"
    )


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
        if kind == VERSION_FUNCTION:
            parse_version_function(row["pattern"])
        else:
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
        if (
            other.prefix == row.prefix
            and other.library != row.library
            and "bare_version" in (other.kind, row.kind)
        ):
            return (
                f"prefix {row.prefix!r} maps to {other.library!r} and "
                f"{row.library!r}, so it can't have a bare_version row: a bare "
                f"version doesn't choose between libraries (see line {line})"
            )
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
