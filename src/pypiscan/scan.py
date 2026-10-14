"""Run a package list through the scan's phases, one finished phase at a time.

See README "How a scan runs". Each phase writes ``NN-<phase>.jsonl.partial``
with one line per package and renames it when every package is done, so an
episode directory only ever holds whole phase files plus at most one
``.partial`` left by an interrupted run.
"""

import hashlib
import importlib.metadata
import json
import re
import signal
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TextIO, cast

from pypiscan.package_list import Package, PackageListError, load_package_list
from pypiscan.pypi import (
    ARCH,
    INTERPRETER,
    MAX_GLIBC_MINOR,
    HttpClient,
    PyPIError,
    release_files,
    select_target,
)

SCHEMA_VERSION = 1
EPISODE_SCHEMA_VERSION = 1
MB = 1_000_000
WHEEL_SIZE_LIMIT = 100 * MB
ZIP_MEMBER_SIZE_LIMIT = 512 * MB
TARGET = f"{INTERPRETER}-manylinux_2_{MAX_GLIBC_MINOR}_{ARCH}"
STATUSES = ("ok", "skipped", "error")
EXIT_PREFLIGHT = 2
EXIT_INTERRUPTED = 130
PHASE_FILE = re.compile(r"(\d\d)-[a-z0-9-]+\.jsonl(\.partial)?")

Line = dict[str, object]


@dataclass
class Stop:
    """Set by the SIGINT handler; the runner checks it between packages."""

    requested: bool = False


@dataclass(frozen=True)
class Result:
    status: str
    reason: str | None = None
    data: Line = field(default_factory=Line)


@dataclass(frozen=True)
class Phase:
    """A per-package phase: gets each package and its previous phase line."""

    name: str
    run: Callable[[Package, Line | None], Result]


def resolve_phase(client: HttpClient) -> Phase:
    """Phase 01: the target wheel of each release, from PyPI's JSON API."""

    def run(package: Package, previous: Line | None) -> Result:
        data: Line = {"version": package.version}
        try:
            wheel = select_target(release_files(client, package.name, package.version))
        except PyPIError as exc:
            return Result("error", str(exc), data)
        if wheel is None:
            return Result("skipped", "no_target", data)
        return Result("ok", None, data | asdict(wheel))

    return Phase("01-resolve", run)


def phases(client: HttpClient) -> list[Phase]:
    return [resolve_phase(client)]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    """Check 4: an existing episode.json matches this run's inputs."""
    path = episode / "episode.json"
    if not path.is_file():
        return []
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


def preflight(
    package_list: Path, episode: Path, cache: Path, count: int
) -> tuple[list[Package], int, list[str]]:
    """Checks 1 to 4. Returns the packages, clamped count and any problems."""
    problems: list[str] = []
    for label, directory in (("episode", episode), ("cache", cache)):
        root = git_work_tree(directory)
        if root is not None:
            problems.append(
                f"{label} directory {directory} is inside the git working tree "
                f"at {root}; use a directory outside it"
            )
    try:
        packages = load_package_list(package_list)
    except PackageListError as exc:
        return [], 0, [*problems, str(exc)]
    count = min(count, len(packages))
    problems += _phase_file_problems(episode)
    problems += _episode_problems(episode, episode_inputs(package_list, count))
    return packages[:count], count, problems


def _read_lines(path: Path) -> dict[str, Line]:
    lines = (json.loads(text) for text in path.read_text("utf-8").splitlines())
    return {str(line["name"]): line for line in cast(list[Line], list(lines))}


def _line(
    phase: Phase, package: Package, previous: Line | None, earlier: list[str]
) -> Line:
    if previous is not None and previous["status"] != "ok":
        reason = previous["reason"]
        # Keep the phase where the package's line first wasn't ok.
        if previous["status"] != "skipped" or reason not in earlier:
            reason = earlier[-1]
        result = Result("skipped", cast(str, reason))
    else:
        result = phase.run(package, previous)
    return {
        "schema_version": SCHEMA_VERSION,
        "name": package.name,
        "status": result.status,
        "reason": result.reason,
        **result.data,
    }


def run_phases(
    episode: Path,
    packages: Sequence[Package],
    phase_list: Sequence[Phase],
    stop: Stop,
    err: TextIO,
) -> int:
    """Run each unfinished phase over every package; skip finished ones."""
    previous: dict[str, Line] | None = None
    earlier: list[str] = []
    for phase in phase_list:
        done = episode / f"{phase.name}.jsonl"
        if done.is_file():
            print(f"{phase.name}: already finished, skipped", file=err)
        else:
            partial = done.with_name(done.name + ".partial")
            counts: Counter[object] = Counter()
            with partial.open("x", encoding="utf-8") as f:
                for package in packages:
                    if stop.requested:
                        print(
                            f"{phase.name}: interrupted; {partial.name} is left "
                            "in place and must be deleted before the next run",
                            file=err,
                        )
                        return EXIT_INTERRUPTED
                    before = previous[package.name] if previous is not None else None
                    line = _line(phase, package, before, earlier)
                    f.write(json.dumps(line) + "\n")
                    f.flush()
                    counts[line["status"]] += 1
            partial.replace(done)
            summary = ", ".join(f"{counts[status]} {status}" for status in STATUSES)
            print(f"{phase.name}: {summary}", file=err)
        previous = _read_lines(done)
        earlier.append(phase.name)
    return 0


def scan(
    package_list: Path,
    episode: Path,
    cache: Path,
    count: int,
    client: HttpClient,
    err: TextIO,
    stop: Stop | None = None,
) -> int:
    """Pre-flight, then create the directories, record episode.json and run."""
    packages, count, problems = preflight(package_list, episode, cache, count)
    for problem in problems:
        print(f"pypiscan scan: error: {problem}", file=err)
    if problems:
        return EXIT_PREFLIGHT
    episode.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    record = episode / "episode.json"
    if not record.is_file():
        inputs = episode_inputs(package_list, count)
        record.write_text(
            json.dumps(
                {
                    "schema_version": EPISODE_SCHEMA_VERSION,
                    **inputs,
                    "code_version": importlib.metadata.version("pypiscan"),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    stop = stop or Stop()

    def on_sigint(signum: int, frame: object) -> None:
        stop.requested = True

    handler = signal.signal(signal.SIGINT, on_sigint)
    try:
        return run_phases(episode, packages, phases(client), stop, err)
    finally:
        signal.signal(signal.SIGINT, handler)
