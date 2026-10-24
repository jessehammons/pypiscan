"""Run a package list through the scan's phases, one finished phase at a time.

See README "How a scan runs". Each phase writes ``NN-<phase>.jsonl.partial``
with one line per package, or in phases 06, 07 and 10 per library, and renames
it when every one is done, so an episode directory only ever holds whole phase
files plus at most one ``.partial`` left by an interrupted run.
"""

import hashlib
import importlib.metadata
import json
import re
import signal
import time
import zipfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol, TextIO, cast
from urllib.parse import urlsplit

from elftools.common.exceptions import ELFError

from pypiscan import fingerprint, version_function
from pypiscan.cve_table import CveTableError, load_cve_table
from pypiscan.fetch import download
from pypiscan.fingerprint_report import report as fingerprint_report
from pypiscan.git import GitError, clone_or_fetch, tags
from pypiscan.library_map import (
    SKIP,
    VERSION_FUNCTION,
    Ambiguous,
    LibraryMapError,
    MapRow,
    VersionFunction,
    cpe_names,
    load_ambiguous_versions,
    load_library_map,
    matcher,
    parse_version_function,
    tag_matcher,
    tag_version,
)
from pypiscan.library_report import libraries, report, todo, write_todo
from pypiscan.noise import usable
from pypiscan.nvd import NvdError, Pacer, candidates
from pypiscan.package_list import Package, PackageListError, load_package_list
from pypiscan.pypi import (
    ARCH,
    INTERPRETER,
    MAX_GLIBC_MINOR,
    HttpClient,
    PyPIError,
    WheelFile,
    release_files,
    select_target,
)
from pypiscan.sbom_report import report as sbom_report
from pypiscan.staleness_report import report as staleness_report
from pypiscan.wheel_inspect import (
    ZIP_ERRORS,
    SkippedMember,
    WheelError,
    inspect_wheel,
)
from pypiscan.wheel_sboms import sboms_wheel
from pypiscan.wheel_strings import BinaryStrings, strings_wheel

SCHEMA_VERSION = 1
# Phase 06's lines gained each tag's date (roadmap S.1).
UPSTREAM_SCHEMA_VERSION = 2
EPISODE_SCHEMA_VERSION = 2
MB = 1_000_000
WHEEL_SIZE_LIMIT = 100 * MB
ZIP_MEMBER_SIZE_LIMIT = 512 * MB
TARGET = f"{INTERPRETER}-manylinux_2_{MAX_GLIBC_MINOR}_{ARCH}"
STATUSES = ("ok", "skipped", "error")
EXIT_PREFLIGHT = 2
EXIT_MANUAL_STEP = 3
EXIT_INTERRUPTED = 130
# Version 1 clones only from GitHub; see README "Conventions".
UPSTREAM_HOST = "github.com"
PHASE_FILE = re.compile(r"(\d\d)-[a-z0-9-]+\.jsonl(\.partial)?")

Line = dict[str, object]
# Each package's lines, keyed by package name and then by phase name.
Lines = Mapping[str, Mapping[str, Line]]


@dataclass
class Stop:
    """Set by the SIGINT handler; the runner checks it between items."""

    requested: bool = False


@dataclass(frozen=True)
class Result:
    status: str
    reason: str | None = None
    data: Line = field(default_factory=Line)


class Named(Protocol):
    @property
    def name(self) -> str: ...


@dataclass(frozen=True)
class Library:
    """A library the map names, the item of the per-library phases."""

    name: str
    repo: str
    tags: str
    cpe: str = ""


@dataclass(frozen=True)
class Phase[T: Named]:
    """A per-package or per-library phase.

    ``run`` gets each item and its lines from every earlier phase of its
    kind, keyed by phase name. With ``skip_not_ok`` set, as for per-package
    phases, ``run`` is only called when the previous phase's line is ok, and
    an item whose line isn't gets a ``skipped`` line instead. Per-library
    phases clear it and run every library; one that needs an earlier
    phase's result reads that line itself. ``finish``, if set, gets every
    item's lines, this phase's included, once every item is done and before
    the phase file is finished. ``schema_version`` is its lines'.
    """

    name: str
    run: Callable[[T, Mapping[str, Line]], Result]
    finish: Callable[[Sequence[str], Lines], None] | None = None
    skip_not_ok: bool = True
    schema_version: int = SCHEMA_VERSION


def resolve_phase(client: HttpClient) -> Phase[Package]:
    """Phase 01: the target wheel of each release, from PyPI's JSON API."""

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        data: Line = {"version": package.version}
        try:
            wheel = select_target(release_files(client, package.name, package.version))
        except PyPIError as exc:
            return Result("error", str(exc), data)
        if wheel is None:
            return Result("skipped", "no_target", data)
        return Result("ok", None, data | asdict(wheel))

    return Phase("01-resolve", run)


def fetch_phase(client: HttpClient, cache_dir: Path) -> Phase[Package]:
    """Phase 02: download each wheel into the cache, verifying its sha256.

    Builds the ``WheelFile`` from phase 01's line instead of calling PyPI
    again. A wheel whose reported size is over the wheel size limit is
    recorded as ``skipped`` with reason ``too_large`` and never downloaded.
    """

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        line = earlier["01-resolve"]
        if cast(int, line["size"]) > WHEEL_SIZE_LIMIT:
            return Result("skipped", "too_large")
        wheel = WheelFile(
            filename=cast(str, line["filename"]),
            url=cast(str, line["url"]),
            sha256=cast(str, line["sha256"]),
            size=cast(int, line["size"]),
            upload_time=cast(str, line["upload_time"]),
        )
        try:
            path = download(client, wheel, cache_dir)
        except PyPIError as exc:
            return Result("error", str(exc))
        return Result("ok", None, {"path": str(path)})

    return Phase("02-fetch", run)


def inspect_phase() -> Phase[Package]:
    """Phase 03: ``inspect`` records for each wheel's ELF members.

    Zip members whose declared uncompressed size is over the zip-member
    limit are listed in ``skipped_members`` instead of being read.
    """

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        wheel_path = Path(cast(str, earlier["02-fetch"]["path"]))
        skipped: list[SkippedMember] = []
        try:
            records = inspect_wheel(wheel_path, ZIP_MEMBER_SIZE_LIMIT, skipped)
        except WheelError as exc:
            return Result("error", str(exc))
        return Result(
            "ok",
            None,
            {
                "wheel": wheel_path.name,
                "records": cast(list[object], records),
                "skipped_members": [asdict(member) for member in skipped],
            },
        )

    return Phase("03-inspect", run)


def strings_phase() -> Phase[Package]:
    """Phase 04: ``strings`` records for each wheel's ELF members.

    Reads the wheel's path from phase 02's line, and skips oversized zip
    members as phase 03 does.
    """

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        wheel_path = Path(cast(str, earlier["02-fetch"]["path"]))
        skipped: list[SkippedMember] = []
        try:
            records = strings_wheel(wheel_path, ZIP_MEMBER_SIZE_LIMIT, skipped)
        except WheelError as exc:
            return Result("error", str(exc))
        return Result(
            "ok",
            None,
            {
                "wheel": wheel_path.name,
                "records": cast(list[object], records),
                "skipped_members": [asdict(member) for member in skipped],
            },
        )

    return Phase("04-strings", run)


def libraries_phase(episode: Path) -> Phase[Package]:
    """Phase 05: each `.libs/` shared library in phase 03's records, with its
    prefix. When every package is done, writes ``library-report.md``.
    """

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        records = cast(list[Line], earlier["03-inspect"]["records"])
        return Result("ok", None, {"libraries": libraries(records)})

    def finish(packages: Sequence[str], lines: Lines) -> None:
        text = report(packages, lines)
        (episode / "library-report.md").write_text(text, encoding="utf-8")

    return Phase("05-libraries", run, finish)


# A compiled recognizer: its library, kind, and whole-string matcher or
# parsed version function.
type Recognizer = tuple[str, fingerprint.Kind, re.Pattern[str] | VersionFunction]
# What pyelftools raises on malformed input; see wheel_inspect._needed.
ELF_ERRORS = (ELFError, AssertionError, ValueError, OverflowError)


class MemberError(Exception):
    """A `.libs/` file can't be read from the wheel as phase 04 saw it."""


def read_members(wheel: Path, expected: Mapping[str, str]) -> dict[str, bytes]:
    """Each member in ``expected``, which maps paths to their sha256 in
    phase 04's records, read from ``wheel`` and checked against it."""
    if not wheel.is_file():
        raise MemberError(f"wheel {wheel} is missing")
    found: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(wheel) as zf:
            for path in expected:
                try:
                    found[path] = zf.read(path)
                except KeyError:
                    raise MemberError(f"{path} is missing from {wheel.name}") from None
    except ZIP_ERRORS as exc:
        raise MemberError(f"{wheel}: not a valid zip file ({exc})") from exc
    except OSError as exc:
        raise MemberError(f"{wheel}: {exc}") from exc
    for path, sha256 in expected.items():
        if hashlib.sha256(found[path]).hexdigest() != sha256:
            raise MemberError(f"{path}'s sha256 differs from phase 04's")
    return found


def _code_matches(
    path: str, data: bytes, library: str, function: VersionFunction
) -> list[fingerprint.Match]:
    try:
        found = version_function.match(data, library, function)
    except ELF_ERRORS as exc:
        raise MemberError(f"{path}: pyelftools can't parse it ({exc})") from exc
    return [] if found is None else [found]


def fingerprint_phase(recognizer_lines: Sequence[Line]) -> Phase[Package]:
    """Phase 08: run the recognizers in phase 07's ``ok`` lines on each
    `.libs/` file whose prefix they're listed under, over the file's strings
    in phase 04's records that pass the noise filter.

    A recognizer must match a string's whole text. A version function
    recognizer reads the file from the wheel at phase 02's path instead, and
    its matches join the file's string matches. Records follow phase 05's
    file order, then the libraries' order in phase 07's lines.
    """
    by_prefix: dict[str, list[Recognizer]] = {}
    for line in recognizer_lines:
        if line["status"] != "ok":
            continue
        for entry in cast(list[dict[str, str]], line["recognizers"]):
            kind = cast(fingerprint.Kind, entry["kind"])
            pattern = entry["pattern"]
            by_prefix.setdefault(entry["prefix"], []).append(
                (
                    str(line["library"]),
                    kind,
                    parse_version_function(pattern)
                    if kind == VERSION_FUNCTION
                    else matcher(pattern, kind),
                )
            )

    def file_matches(
        prefix: str, binary: BinaryStrings, data: bytes | None
    ) -> dict[str, list[fingerprint.Match]]:
        strings = [s for s in binary["strings"] if usable(s)]
        matches: dict[str, list[fingerprint.Match]] = {}
        for library, kind, recognizer in by_prefix.get(prefix, []):
            found = matches.setdefault(library, [])
            if isinstance(recognizer, VersionFunction):
                found += _code_matches(
                    binary["path"], cast(bytes, data), library, recognizer
                )
                continue
            found += [
                fingerprint.Match(
                    library, kind, s["text"], s["offset"], m[1], s["section"]
                )
                for s in strings
                if (m := recognizer.fullmatch(s["text"]))
            ]
        return matches

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        strings_line = earlier["04-strings"]
        wheel = cast(str, strings_line["wheel"])
        binaries = {
            b["path"]: b for b in cast(list[BinaryStrings], strings_line["records"])
        }
        files = cast(list[dict[str, str]], earlier["05-libraries"]["libraries"])
        # Only files with a version function recognizer are read again.
        expected = {
            f["path"]: binaries[f["path"]]["sha256"]
            for f in files
            if any(
                kind == VERSION_FUNCTION
                for _, kind, _ in by_prefix.get(f["prefix"], [])
            )
        }
        records: list[object] = []
        try:
            members = {}
            if expected:
                fetched = Path(cast(str, earlier["02-fetch"]["path"]))
                members = read_members(fetched, expected)
            for found in files:
                binary = binaries[found["path"]]
                data = members.get(found["path"])
                for library, matches in file_matches(
                    found["prefix"], binary, data
                ).items():
                    matches.sort(key=lambda m: cast(int, m.offset))
                    record = fingerprint.record(
                        wheel, binary["path"], binary["sha256"], library, matches
                    )
                    if record is not None:
                        records.append(record)
        except MemberError as exc:
            return Result("error", str(exc))
        return Result("ok", None, {"wheel": wheel, "records": records})

    return Phase("08-fingerprint", run)


def sboms_phase() -> Phase[Package]:
    """Phase 09: ``sbom`` records for each wheel, read from phase 02's path
    once its sha256 matches phase 01's. Files over the zip-member size limit
    aren't read."""

    def run(package: Package, earlier: Mapping[str, Line]) -> Result:
        wheel_path = Path(cast(str, earlier["02-fetch"]["path"]))
        try:
            if not wheel_path.is_file():
                return Result("error", f"wheel {wheel_path} is missing")
            if _sha256(wheel_path) != earlier["01-resolve"]["sha256"]:
                reason = f"wheel {wheel_path}'s sha256 differs from phase 01's"
                return Result("error", reason)
            records = sboms_wheel(wheel_path, ZIP_MEMBER_SIZE_LIMIT)
        except (OSError, WheelError) as exc:
            return Result("error", str(exc))
        return Result(
            "ok",
            None,
            {"wheel": wheel_path.name, "records": cast(list[object], records)},
        )

    return Phase("09-sboms", run)


def phases(client: HttpClient, cache_dir: Path, episode: Path) -> list[Phase[Package]]:
    return [
        resolve_phase(client),
        fetch_phase(client, cache_dir),
        inspect_phase(),
        strings_phase(),
        libraries_phase(episode),
    ]


def upstream_libraries(rows: Sequence[MapRow]) -> list[Library]:
    """Each library the map names, in order of first appearance."""
    found: dict[str, Library] = {}
    for row in rows:
        if row.library != SKIP:
            found.setdefault(
                row.library, Library(row.library, row.repo, row.tags, row.cpe)
            )
    return list(found.values())


def on_host(repo: str, host: str) -> bool:
    """Whether ``repo`` is an https URL on ``host``."""
    url = urlsplit(repo)
    return url.scheme == "https" and url.hostname == host


def upstream_phase(
    cache_dir: Path, episode: Path, map_sha256: str, host: str | None
) -> Phase[Library]:
    """Phase 06: clone or fetch each library, and list the tags its tags matches.

    With ``host`` set, a repository that isn't an https URL on it gets a
    ``skipped`` line with reason ``not_github`` and is never cloned; tests
    pass ``None`` to clone local repositories. When every library is done,
    records the map's sha256 in episode.json for pre-flight check 5.
    """

    def run(library: Library, earlier: Mapping[str, Line]) -> Result:
        data: Line = {"repo": library.repo}
        if host is not None and not on_host(library.repo, host):
            return Result("skipped", "not_github", data)
        directory = cache_dir / "upstream" / f"{library.name}.git"
        directory.parent.mkdir(parents=True, exist_ok=True)
        try:
            clone_or_fetch(library.repo, directory)
            names = tags(directory)
        except GitError as exc:
            return Result("error", str(exc), data)
        matcher = tag_matcher(library.tags)
        found = [
            {"tag": name, "version": tag_version(match[1]), "date": date}
            for name, date in names.items()
            if (match := matcher.fullmatch(name))
        ]
        if not found:
            return Result(
                "error",
                f"tags {library.tags!r} matches none of the {len(names)} tags",
                data,
            )
        return Result("ok", None, data | {"tags": cast(list[object], found)})

    def finish(names: Sequence[str], lines: Lines) -> None:
        record = episode / "episode.json"
        recorded = json.loads(record.read_text(encoding="utf-8"))
        recorded["schema_version"] = EPISODE_SCHEMA_VERSION
        recorded["library_map_sha256"] = map_sha256
        write_json(record, recorded)

    return Phase(
        "06-upstream",
        run,
        finish,
        skip_not_ok=False,
        schema_version=UPSTREAM_SCHEMA_VERSION,
    )


def recognizers_phase(rows: Sequence[MapRow]) -> Phase[Library]:
    """Phase 07: each library's recognizers, from its map rows with a kind.

    Each entry holds what ``library_map.matcher`` compiles. A library with
    no such row is ``skipped`` with reason ``no_recognizer``. Doesn't read
    phase 06's line: recognizers come from the map, so a library whose
    clone was skipped or failed still gets them.
    """
    found: dict[str, list[object]] = {}
    for row in rows:
        if row.kind:
            found.setdefault(row.library, []).append(
                {
                    "prefix": row.prefix,
                    "kind": row.kind,
                    "pattern": row.pattern,
                    "identity_file": row.identity_file or None,
                }
            )

    def run(library: Library, earlier: Mapping[str, Line]) -> Result:
        if library.name not in found:
            return Result("skipped", "no_recognizer")
        return Result("ok", None, {"recognizers": found[library.name]})

    return Phase("07-recognizers", run, skip_not_ok=False)


def library_phases(
    cache_dir: Path, episode: Path, map_sha256: str, rows: Sequence[MapRow]
) -> list[Phase[Library]]:
    return [
        upstream_phase(cache_dir, episode, map_sha256, UPSTREAM_HOST),
        recognizers_phase(rows),
    ]


def cves_phase(client: HttpClient, sleep: Callable[[float], None]) -> Phase[Library]:
    """Phase 10: candidate CVEs from NVD, by each of the library's CPE names.

    One pacer serves the whole phase, so requests are paced across
    libraries too. A library whose cpe is ``none`` is ``skipped`` with
    reason ``no_cpe``; any failure makes its line ``error`` with no
    candidates. Reads neither the CVE table nor phase 06's clone.
    """
    pace = Pacer(sleep)

    def run(library: Library, earlier: Mapping[str, Line]) -> Result:
        names = cpe_names(library.cpe)
        if not names:
            return Result("skipped", "no_cpe", {"cpe": []})
        try:
            return Result("ok", None, candidates(client, names, pace))
        except NvdError as exc:
            return Result("error", str(exc), {"cpe": cast(object, names)})

    return Phase("10-cves", run, skip_not_ok=False)


def write_json(path: Path, value: object) -> None:
    """Write ``path`` whole or not at all, through a ``.partial`` file and a
    rename, as phase files are written."""
    partial = path.with_name(path.name + ".partial")
    partial.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    partial.replace(path)


def _sha256(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def git_work_tree(path: Path) -> Path | None:
    """The working tree containing ``path`` (or its nearest existing ancestor).

    Looks for a ``.git`` entry without running git.
    """
    path = path.resolve()
    for directory in (path, *path.parents):
        if (directory / ".git").exists():
            return directory
    return None


def _phase_file_problems(episode: Path) -> list[str]:
    """Check 3: finished phase files form a run 01, 02, … with no .partial."""
    if not episode.is_dir():
        return []
    finished: dict[str, int] = {}
    problems: list[str] = []
    for path in sorted(episode.iterdir()):
        match = PHASE_FILE.fullmatch(path.name)
        if not match:
            continue
        number = match[1]
        if match[2]:
            problems.append(
                f"{path.name} exists; an earlier run stopped in phase {number}. "
                f"Delete it to rerun phase {number}."
            )
        else:
            finished[path.name] = int(number)
    gap = 1
    while gap in finished.values():
        gap += 1
    problems.extend(
        f"{name} exists but phase {gap:02d} is not finished. Delete {name}."
        for name, number in finished.items()
        if number > gap
    )
    return problems


def episode_inputs(package_list: Path, count: int) -> Line:
    """The inputs a rerun must match; the code version is recorded, not matched."""
    return {
        "package_list_sha256": _sha256(package_list),
        "count": count,
        "target": TARGET,
        "wheel_size_limit": WHEEL_SIZE_LIMIT,
        "zip_member_size_limit": ZIP_MEMBER_SIZE_LIMIT,
    }


def _episode_problems(episode: Path, inputs: Line) -> list[str]:
    """Check 4: episode.json matches this run's inputs, if it or phase files exist."""
    path = episode / "episode.json"
    if not path.is_file():
        paths: list[Path] = list(episode.iterdir()) if episode.is_dir() else []
        names = sorted(p.name for p in paths if PHASE_FILE.fullmatch(p.name))
        if not names:
            return []
        return [
            f"{path} is missing, so the inputs of the phase files already there "
            f"can't be checked. Delete {', '.join(names)}, or use a separate "
            "episode directory."
        ]
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        return [f"{path}: {exc}"]
    if not isinstance(recorded, dict):
        return [f"{path}: not a JSON object"]
    recorded = cast(Line, recorded)
    return [
        f"{path}: {key} is {recorded.get(key)!r}, but this run's is {value!r}; "
        "use a separate episode directory"
        for key, value in inputs.items()
        if recorded.get(key) != value
    ]


def _map_problems(episode: Path, library_map: Path) -> list[str]:
    """Check 5: the map hasn't changed since phase 06 recorded its sha256."""
    if not (episode / "06-upstream.jsonl").is_file():
        return []
    try:
        recorded = json.loads((episode / "episode.json").read_text("utf-8"))
        changed = recorded["library_map_sha256"] != _sha256(library_map)
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError):
        changed = True
    if not changed:
        return []
    later = sorted(
        path.name
        for path in episode.iterdir()
        if (match := PHASE_FILE.fullmatch(path.name)) and int(match[1]) >= 6
    )
    return [
        f"the library map has changed since phase 06 ran. Delete "
        f"{', '.join(later)} to rerun phase 06 and every later phase."
    ]


def preflight(
    package_list: Path,
    library_map: Path,
    ambiguous_versions: Path,
    cve_table: Path,
    episode: Path,
    cache: Path,
    count: int,
) -> tuple[list[Package], list[MapRow], Ambiguous, int, list[str]]:
    """Checks 1 to 5. Returns the packages, map rows, ambiguous versions,
    clamped count and problems. The CVE table is only checked: nothing uses
    it yet."""
    problems: list[str] = []
    for label, directory in (("episode", episode), ("cache", cache)):
        root = git_work_tree(directory)
        if root is not None:
            problems.append(
                f"{label} directory {directory} is inside the git working tree "
                f"at {root}; use a directory outside it"
            )
    rows: list[MapRow] = []
    ambiguous: Ambiguous = {}
    try:
        rows = load_library_map(library_map)
        problems += _map_problems(episode, library_map)
        ambiguous = load_ambiguous_versions(ambiguous_versions, rows)
        load_cve_table(cve_table, rows)
    except (LibraryMapError, CveTableError) as exc:
        problems.append(str(exc))
    try:
        packages = load_package_list(package_list)
    except PackageListError as exc:
        return [], rows, ambiguous, 0, [*problems, str(exc)]
    count = min(count, len(packages))
    problems += _phase_file_problems(episode)
    problems += _episode_problems(episode, episode_inputs(package_list, count))
    return packages[:count], rows, ambiguous, count, problems


def _read_lines(path: Path, key: str = "name") -> dict[str, Line]:
    lines = (json.loads(text) for text in path.read_text("utf-8").splitlines())
    return {str(line[key]): line for line in cast(list[Line], list(lines))}


def _line[T: Named](
    phase: Phase[T], item: T, earlier: dict[str, Line], key: str
) -> Line:
    """Run ``phase`` for ``item``, or skip it if the phase skips items whose
    previous line isn't ok and this one's isn't."""
    previous = next(reversed(earlier.values()), None)
    if phase.skip_not_ok and previous is not None and previous["status"] != "ok":
        reason = previous["reason"]
        # Keep the phase where the package's line first wasn't ok.
        if previous["status"] != "skipped" or reason not in earlier:
            reason = next(reversed(earlier))
        result = Result("skipped", cast(str, reason))
    else:
        result = phase.run(item, earlier)
    return {
        "schema_version": phase.schema_version,
        key: item.name,
        "status": result.status,
        "reason": result.reason,
        **result.data,
    }


def run_phases[T: Named](
    episode: Path,
    items: Sequence[T],
    phase_list: Sequence[Phase[T]],
    stop: Stop,
    err: TextIO,
    key: str = "name",
    finished: Sequence[str] = (),
) -> int:
    """Run each unfinished phase over every item; skip finished ones.

    ``key`` names the item in each line: ``name`` for a package, ``library``
    for a library. ``finished`` names phases an earlier call ran over the
    same items, in order; their lines are loaded first, without being
    listed on ``err``, so the skip rule and its reason see them.
    """
    # Each item's lines from the finished phases, keyed by phase name.
    earlier: dict[str, dict[str, Line]] = {item.name: {} for item in items}
    for name in finished:
        for item_name, line in _read_lines(episode / f"{name}.jsonl", key).items():
            earlier[item_name][name] = line
    for phase in phase_list:
        if stop.requested:
            print(f"interrupted before {phase.name}", file=err)
            return EXIT_INTERRUPTED
        done = episode / f"{phase.name}.jsonl"
        if done.is_file():
            print(f"{phase.name}: already finished, skipped", file=err)
        else:
            partial = done.with_name(done.name + ".partial")
            counts: Counter[object] = Counter()
            current: dict[str, Line] = {}
            with partial.open("x", encoding="utf-8") as f:
                for item in items:
                    if stop.requested:
                        print(
                            f"{phase.name}: interrupted; {partial.name} is left "
                            "in place and must be deleted before the next run",
                            file=err,
                        )
                        return EXIT_INTERRUPTED
                    line = _line(phase, item, earlier[item.name], key)
                    f.write(json.dumps(line) + "\n")
                    f.flush()
                    counts[line["status"]] += 1
                    current[item.name] = line
            if phase.finish is not None:
                names = [item.name for item in items]
                phase.finish(
                    names,
                    {n: earlier[n] | {phase.name: current[n]} for n in names},
                )
            partial.replace(done)
            summary = ", ".join(f"{counts[status]} {status}" for status in STATUSES)
            print(f"{phase.name}: {summary}", file=err)
        for name, line in _read_lines(done, key).items():
            earlier[name][phase.name] = line
    if stop.requested:
        print("interrupted after the last phase finished", file=err)
        return EXIT_INTERRUPTED
    return 0


def manual_step(episode: Path, rows: Sequence[MapRow], err: TextIO) -> int:
    """Rewrite library-map-todo.csv from phase 05; stop if it has rows."""
    lines = _read_lines(episode / "05-libraries.jsonl")
    names = list(lines)
    found = {name: {"05-libraries": line} for name, line in lines.items()}
    missing = todo(names, found, {row.prefix for row in rows})
    write_todo(episode / "library-map-todo.csv", missing)
    if not missing:
        return 0
    print(
        f"library-map-todo.csv lists {len(missing)} prefixes the library map "
        "doesn't; add rows for them, or mark them skip, and rerun:",
        file=err,
    )
    for prefix in missing:
        print(f"  {prefix}", file=err)
    return EXIT_MANUAL_STEP


def write_fingerprint_report(
    episode: Path,
    packages: Sequence[Package],
    part_1: Sequence[str],
    recognizers: Mapping[str, Line],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
) -> None:
    """Rewrite fingerprint-report.md from part 1's phases (01 to 05), 07 and
    08; ``part_1`` names part 1's phases."""
    text = fingerprint_report(
        packages,
        {name: _read_lines(episode / f"{name}.jsonl") for name in part_1},
        recognizers,
        _read_lines(episode / "08-fingerprint.jsonl"),
        rows,
        ambiguous,
    )
    (episode / "fingerprint-report.md").write_text(text, encoding="utf-8")


def write_sbom_report(
    episode: Path,
    packages: Sequence[Package],
    part_1: Sequence[str],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
) -> None:
    """Rewrite sbom-report.md from part 1's phases (01 to 05), 08 and 09;
    ``part_1`` names part 1's phases."""
    text = sbom_report(
        packages,
        {name: _read_lines(episode / f"{name}.jsonl") for name in part_1},
        _read_lines(episode / "08-fingerprint.jsonl"),
        _read_lines(episode / "09-sboms.jsonl"),
        rows,
        ambiguous,
    )
    (episode / "sbom-report.md").write_text(text, encoding="utf-8")


def write_staleness_report(
    episode: Path,
    packages: Sequence[Package],
    part_1: Sequence[str],
    rows: Sequence[MapRow],
    ambiguous: Ambiguous,
) -> None:
    """Rewrite staleness-report.md from part 1's phases (01 to 05), 06 and
    08; ``part_1`` names part 1's phases."""
    text = staleness_report(
        packages,
        {name: _read_lines(episode / f"{name}.jsonl") for name in part_1},
        _read_lines(episode / "06-upstream.jsonl", "library"),
        _read_lines(episode / "08-fingerprint.jsonl"),
        rows,
        ambiguous,
    )
    (episode / "staleness-report.md").write_text(text, encoding="utf-8")


def scan(
    package_list: Path,
    library_map: Path,
    ambiguous_versions: Path,
    cve_table: Path,
    episode: Path,
    cache: Path,
    count: int,
    client: HttpClient,
    err: TextIO,
    stop: Stop | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Pre-flight, then create the directories, record episode.json and run.
    ``sleep`` paces phase 10's requests to NVD."""
    packages, rows, ambiguous, count, problems = preflight(
        package_list,
        library_map,
        ambiguous_versions,
        cve_table,
        episode,
        cache,
        count,
    )
    for problem in problems:
        print(f"pypiscan scan: error: {problem}", file=err)
    if problems:
        return EXIT_PREFLIGHT
    episode.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    record = episode / "episode.json"
    if not record.is_file():
        inputs = episode_inputs(package_list, count)
        write_json(
            record,
            {
                "schema_version": EPISODE_SCHEMA_VERSION,
                **inputs,
                "code_version": importlib.metadata.version("pypiscan"),
            },
        )
    stop = stop or Stop()

    def on_sigint(signum: int, frame: object) -> None:
        stop.requested = True

    handler = signal.signal(signal.SIGINT, on_sigint)
    try:
        part_1 = phases(client, cache, episode)
        status = run_phases(episode, packages, part_1, stop, err)
        # The manual step comes between phases 05 and 06.
        status = status or manual_step(episode, rows, err)
        if status:
            return status
        part_2 = library_phases(cache, episode, _sha256(library_map), rows)
        libraries = upstream_libraries(rows)
        status = run_phases(episode, libraries, part_2, stop, err, key="library")
        if status:
            return status
        # Phases 08 and 09 are per package again, after the per-library
        # phases: 08 runs the recognizers phase 07 recorded, and its skip
        # rule looks at part 1's lines.
        recognizers = _read_lines(episode / "07-recognizers.jsonl", "library")
        part_3 = [fingerprint_phase(list(recognizers.values())), sboms_phase()]
        names = [phase.name for phase in part_1]
        status = run_phases(episode, packages, part_3, stop, err, finished=names)
        if (episode / "08-fingerprint.jsonl").is_file():
            write_fingerprint_report(
                episode, packages, names, recognizers, rows, ambiguous
            )
            write_staleness_report(episode, packages, names, rows, ambiguous)
        if (episode / "09-sboms.jsonl").is_file():
            write_sbom_report(episode, packages, names, rows, ambiguous)
        if status:
            return status
        # Phase 10 is per library again, and reads no earlier phase.
        part_4 = [cves_phase(client, sleep)]
        return run_phases(episode, libraries, part_4, stop, err, key="library")
    finally:
        signal.signal(signal.SIGINT, handler)
