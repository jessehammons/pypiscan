"""Load the library map: which upstream library each `.libs/` prefix holds.

See README "The library map". The map is a CSV file with the columns in
``COLUMNS``, one row per prefix, library and way of identifying it. A
``skip`` row has every column empty except ``prefix`` and ``library``. A
mapped row needs a repo and tags, one or more patterns separated by single
spaces, which ``tag_matcher`` compiles, and no identity in version 1. Its
``not_release``, if set, is a regex; ``is_release`` applies it. A row with a
kind is a recognizer: its pattern compiles with ``matcher``, or
``parse_version_function`` for a ``version_function_machine_code`` row, and
every kind but ``build_path`` cites an ``identity_file``. A row with no kind
marks a library that is identified but has no recognizer yet. A
``bare_version`` row's prefix maps to no other library. ``cpe`` is required
on a mapped row: the vendor and product of each of the library's CPE names
in NVD, joined by ``:`` and separated by single spaces, or ``none``
(``cpe_names``). ``osv`` isn't used in version 1. ``line``, required on a
mapped row, is how many leading components of a version name its line of
releases, or ``single_line``; ``load_line_eol`` reads when each line reached
its end of life.
``static_lib_detection`` (roadmap T.3) is ``pattern`` on a ``library_string``
or ``build_path`` row whose matches outside `.libs/` become static_lib
records, ``detector`` on a row with no prefix and no kind whose library a
hand-written detector finds, or empty. Only a ``detector`` row has an empty
prefix, and a library's rows agree on being one.
``load_ambiguous_versions`` reads the list of ambiguous versions against the
map's rows.
"""

import csv
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from pypiscan.detectors import DETECTOR_LIBRARIES

COLUMNS = [
    "prefix",
    "library",
    "repo",
    "tags",
    "not_release",
    "line",
    "kind",
    "pattern",
    "identity_file",
    "identity",
    "static_lib_detection",
    "cpe",
    "osv",
]
VERSION_FUNCTION = "version_function_machine_code"
KINDS = ("library_string", "build_path", VERSION_FUNCTION, "bare_version")
SKIP = "skip"
# Columns every row for one library agrees on.
SHARED = ("repo", "tags", "not_release", "line", "cpe", "osv")
# The line of a library that maintains one line of releases.
SINGLE_LINE = "single_line"
# static_lib_detection: the row's pattern, or the library's hand-written
# detector, shows that a binary outside `.libs/` contains the library.
PATTERN = "pattern"
DETECTOR = "detector"
# The kinds whose pattern can qualify for static_lib detection.
STATIC_KINDS = ("library_string", "build_path")

PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
# A digit followed by letters, digits, ".", "+", "~" or "-".
VERSION = r"\d[0-9A-Za-z.+~-]*"
# Nothing around a bare version anchors it: three or more numbers.
BARE_VERSION = r"\d+(?:\.\d+){2,}"
# In tags, a version can also be spelled with "_" (REL_18_6).
TAG_VERSION = r"\d[0-9A-Za-z._+~-]*"
# The only versions that can be releases.
DOTTED = re.compile(r"\d+(?:\.\d+)*")
C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NUMBER = re.compile(r"\d+")
# A CPE's vendor and product, joined by ":".
CPE = re.compile(r"[a-z0-9_.+~-]+:[a-z0-9_.+~-]+")
# The cpe of a library NVD has no CPE name for.
NO_CPE = "none"


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
    # Last, with defaults, so rows built in code needn't name them.
    not_release: str = ""
    line: str = SINGLE_LINE
    static_lib_detection: str = ""


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
    first, in bits or decimal digits; ``minimum`` is the encoding's
    ``from``, 0 when a bits pattern has none; ``pattern`` is a string
    encoding's recognizer pattern."""

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
    optionally with ``from <n>``, ``-> decimal <widths> from <n>``,
    ``-> out`` or ``-> string <pattern>``.
    """
    function, arrow, rest = pattern.partition(" -> ")
    if not arrow:
        raise ValueError("pattern is <function> -> <encoding>")
    if not C_IDENTIFIER.fullmatch(function):
        raise ValueError(f"{function!r} isn't a C identifier")
    encoding, space, rest = rest.partition(" ")
    if encoding == "bits":
        text, sep, minimum = rest.partition(" from")
        if sep and not (minimum[:1] == " " and NUMBER.fullmatch(minimum[1:])):
            raise ValueError("from in a bits pattern takes an integer")
        widths = _widths(text)
        if sum(widths) > 31:
            raise ValueError("bits widths after the * total more than 31")
        return VersionFunction(function, "bits", widths, int(minimum or 0))
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


def _tag_patterns(tags: str) -> list[re.Pattern[str]]:
    """Compile each of a tags value's patterns for ``fullmatch``, with the
    version as group 1. Raises ``ValueError`` for a pattern a tags value
    can't have."""
    compiled: list[re.Pattern[str]] = []
    for pattern in tags.split(" "):
        if not pattern:
            raise ValueError(
                f"tags {tags!r} has an empty pattern; patterns are separated "
                "by single spaces"
            )
        parts = _split("tags", pattern, {"version"})
        compiled.append(
            re.compile(f"{re.escape(parts[0])}({TAG_VERSION}){re.escape(parts[2])}")
        )
    return compiled


def tag_matcher(tags: str) -> Callable[[str], str | None]:
    """A function that gives a tag's version from the first of ``tags``'s
    patterns that matches it, or ``None`` when none does."""
    patterns = _tag_patterns(tags)

    def version(tag: str) -> str | None:
        for pattern in patterns:
            if match := pattern.fullmatch(tag):
                return tag_version(match[1])
        return None

    return version


def tag_version(text: str) -> str:
    """A version as a tag spells it, with "_" or "-" between digits as "."."""
    return re.sub(r"(?<=\d)[_-](?=\d)", ".", text)


def is_release(version: str, not_release: str) -> bool:
    """Whether a listed version is a release: digits separated by dots, and
    not a full match of the library's ``not_release`` regex, if it has one."""
    return bool(DOTTED.fullmatch(version)) and not (
        not_release and re.fullmatch(not_release, version)
    )


def cpe_names(cpe: str) -> list[str]:
    """A mapped row's ``cpe`` as its names, none for ``none``."""
    return [] if cpe == NO_CPE else cpe.split(" ")


def _cpe_problem(cpe: str) -> str | None:
    if not cpe:
        return "cpe is empty; use none for a library NVD has no CPE name for"
    names = cpe_names(cpe)
    if "" in names:
        return f"cpe {cpe!r} has an empty name; names are separated by single spaces"
    for name in names:
        if not CPE.fullmatch(name):
            return (
                f"cpe {cpe!r}: {name!r} isn't none or a vendor and product joined "
                "by ':', each in lowercase letters, digits, _, ., -, + and ~"
            )
    if len(set(names)) != len(names):
        return f"cpe {cpe!r} lists a name twice"
    return None


def _row_problem(row: dict[str, str]) -> str | None:
    """Why ``row`` doesn't fit its kind, or ``None`` if it's valid."""
    detection = row["static_lib_detection"]
    if not row["prefix"] and detection != DETECTOR:
        return f"prefix is empty, which only a {DETECTOR} row can be"
    if not row["library"]:
        return "library is empty"
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
    if not row["line"]:
        return f"line is empty; use {SINGLE_LINE} for a library with one line"
    if row["line"] != SINGLE_LINE and not (
        NUMBER.fullmatch(row["line"]) and int(row["line"]) > 0
    ):
        return f"line {row['line']!r} isn't a positive integer or {SINGLE_LINE}"
    if problem := _cpe_problem(row["cpe"]):
        return problem
    try:
        # A typo here would make phase 06 match no tags.
        _tag_patterns(row["tags"])
    except ValueError as exc:
        return str(exc)
    try:
        re.compile(row["not_release"])
    except re.error as exc:
        return f"not_release {row['not_release']!r} isn't a regex: {exc}"
    kind = row["kind"]
    if detection not in ("", PATTERN, DETECTOR):
        return (
            f"unknown static_lib_detection {detection!r}; expected {PATTERN}, "
            f"{DETECTOR} or empty"
        )
    if detection == PATTERN and kind not in STATIC_KINDS:
        return f"a {PATTERN} row is a {' or '.join(STATIC_KINDS)} row"
    if detection == DETECTOR and (kind or row["prefix"]):
        return f"a {DETECTOR} row has no prefix and no kind"
    if detection == DETECTOR and row["library"] not in DETECTOR_LIBRARIES:
        return f"library {row['library']!r} has no hand-written detector"
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
        if (other.static_lib_detection == DETECTOR) != (
            row.static_lib_detection == DETECTOR
        ):
            differ.append(f"static_lib_detection ({DETECTOR} or not)")
        if differ:
            return (
                f"library {row.library!r} has another {', '.join(differ)} "
                f"(see line {line})"
            )
    return None


def _read(path: Path, columns: list[str]) -> list[tuple[int, dict[str, str]]]:
    """Each non-empty row of a CSV file with ``columns`` as its header, with
    its line number."""
    try:
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            rows = [(reader.line_num, row) for row in reader]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise LibraryMapError(f"{path}: {exc}") from exc
    if header != columns:
        raise LibraryMapError(
            f"{path}: header must be {','.join(columns)}, got {header!r}"
        )
    result: list[tuple[int, dict[str, str]]] = []
    for line, fields in rows:
        if not fields:
            continue
        where = f"{path}:{line}"
        if len(fields) != len(columns):
            raise LibraryMapError(
                f"{where}: expected {len(columns)} fields, got {len(fields)}"
            )
        result.append((line, dict(zip(columns, fields, strict=True))))
    return result


def load_library_map(path: Path) -> list[MapRow]:
    """Read and validate a library map, keeping its rows in order."""
    result: list[tuple[int, MapRow]] = []
    for line, values in _read(path, COLUMNS):
        row = MapRow(**values)
        problem = _row_problem(values) or _clash(row, result)
        if problem:
            raise LibraryMapError(f"{path}:{line}: {problem}")
        result.append((line, row))
    return [row for _, row in result]


AMBIGUOUS_COLUMNS = ["library", "version", "ambiguous_with"]
# For each library, each version as read and the releases it may also be.
type Ambiguous = dict[str, dict[str, list[str]]]


def load_ambiguous_versions(path: Path, rows: list[MapRow]) -> Ambiguous:
    """Read and validate the list of ambiguous versions (README "Ambiguous
    versions") against the loaded map's rows."""
    mapped = {row.library for row in rows if row.library != SKIP}
    result: Ambiguous = {}
    for line, values in _read(path, AMBIGUOUS_COLUMNS):
        library, version, other = (values[c] for c in AMBIGUOUS_COLUMNS)
        empty = [c for c in AMBIGUOUS_COLUMNS if not values[c]]
        if empty:
            problem = f"{', '.join(empty)} is empty"
        elif library not in mapped:
            problem = f"library {library!r} isn't mapped in the library map"
        elif bad := [v for v in (version, other) if not re.fullmatch(VERSION, v)]:
            problem = f"{bad[0]!r} isn't a version"
        elif version == other:
            problem = "version and ambiguous_with are the same"
        elif other in result.get(library, {}).get(version, []):
            problem = f"{library} {version} {other} is listed twice"
        else:
            result.setdefault(library, {}).setdefault(version, []).append(other)
            continue
        raise LibraryMapError(f"{path}:{line}: {problem}")
    return result


def release_line(version: str, line: str) -> str | None:
    """The line of releases a dotted ``version`` is on, given its library's
    ``line``: its first N components, or ``None`` for a single-line library."""
    return None if line == SINGLE_LINE else ".".join(version.split(".")[: int(line)])


LINE_EOL_COLUMNS = ["library", "line", "eol", "source"]
# The eol of a line that is still maintained.
MAINTAINED = "maintained"
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# For each library, each line's eol: an ISO date or ``maintained``.
type LineEol = dict[str, dict[str, str]]


def _eol_problem(eol: str) -> str | None:
    if eol == MAINTAINED:
        return None
    try:
        if ISO_DATE.fullmatch(eol):
            date.fromisoformat(eol)
            return None
    except ValueError:
        pass
    return f"eol {eol!r} isn't an ISO date or {MAINTAINED}"


def load_line_eol(path: Path, rows: list[MapRow]) -> LineEol:
    """Read and validate the list of lines' ends of life (README "Lines'
    ends of life") against the loaded map's rows."""
    lines = {row.library: row.line for row in rows if row.library != SKIP}
    result: LineEol = {}
    for line_num, values in _read(path, LINE_EOL_COLUMNS):
        library, line, eol = values["library"], values["line"], values["eol"]
        empty = [c for c in LINE_EOL_COLUMNS if not values[c]]
        if empty:
            problem = f"{', '.join(empty)} is empty"
        elif library not in lines:
            problem = f"library {library!r} isn't mapped in the library map"
        elif lines[library] == SINGLE_LINE:
            problem = f"library {library!r} has a single line"
        elif not (
            DOTTED.fullmatch(line) and line.count(".") + 1 == int(lines[library])
        ):
            problem = (
                f"line {line!r} isn't {lines[library]} numbers separated by "
                f"dots, as library {library!r}'s line column says"
            )
        elif eol_problem := _eol_problem(eol):
            problem = eol_problem
        elif line in result.get(library, {}):
            problem = f"{library} {line} is listed twice"
        else:
            result.setdefault(library, {})[line] = eol
            continue
        raise LibraryMapError(f"{path}:{line_num}: {problem}")
    return result
