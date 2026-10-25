import hashlib
import io
import json
import signal
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from elf_builder import build_elf
from git_repo import make_repo
from pypiscan import scan as scan_module
from pypiscan.cli import main
from pypiscan.git import GitError, clone_or_fetch, git, tags
from pypiscan.library_map import (
    AMBIGUOUS_COLUMNS,
    COLUMNS,
    LINE_EOL_COLUMNS,
    load_library_map,
    matcher,
)
from pypiscan.package_list import Package
from pypiscan.scan import (
    EPISODE_SCHEMA_VERSION,
    EXIT_INTERRUPTED,
    TARGET,
    WHEEL_SIZE_LIMIT,
    ZIP_MEMBER_SIZE_LIMIT,
    Library,
    Line,
    Lines,
    Phase,
    Result,
    Stop,
    episode_inputs,
    fetch_phase,
    git_work_tree,
    inspect_phase,
    libraries_phase,
    library_phases,
    recognizers_phase,
    run_phases,
    scan,
    strings_phase,
    upstream_libraries,
    upstream_phase,
)
from test_fetch import RecordedClient
from test_inspect import LIBS_ELF, build_wheel

DEMO_TARGET = "demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"


def write_list(path: Path, *rows: str) -> Path:
    path.write_text("name,version\n" + "".join(f"{row}\n" for row in rows))
    return path


class Dirs:
    def __init__(self, tmp_path: Path) -> None:
        self.list = write_list(
            tmp_path / "list.csv", "demo,1.0", "puredemo,3.1", "missing,9.9"
        )
        self.map = tmp_path / "libraries.csv"
        self.map.write_text(",".join(COLUMNS) + "\n")
        self.ambiguous = tmp_path / "ambiguous_versions.csv"
        self.ambiguous.write_text(",".join(AMBIGUOUS_COLUMNS) + "\n")
        self.cves = tmp_path / "cves.toml"
        self.cves.write_text("")
        self.line_eol = tmp_path / "line_eol.csv"
        self.line_eol.write_text(",".join(LINE_EOL_COLUMNS) + "\n")
        self.episode = tmp_path / "episode"
        self.cache = tmp_path / "cache"

    def argv(self, *extra: str) -> list[str]:
        return [
            "scan",
            str(self.list),
            "--library-map",
            str(self.map),
            "--ambiguous-versions",
            str(self.ambiguous),
            "--cve-table",
            str(self.cves),
            "--line-eol",
            str(self.line_eol),
            "--episode-dir",
            str(self.episode),
            "--cache-dir",
            str(self.cache),
            *extra,
        ]

    def lines(self, phase: str = "01-resolve") -> list[Line]:
        text = (self.episode / f"{phase}.jsonl").read_text()
        return [json.loads(line) for line in text.splitlines()]


@pytest.fixture
def dirs(tmp_path: Path) -> Dirs:
    return Dirs(tmp_path)


def run(dirs: Dirs, *extra: str) -> int:
    return main(dirs.argv(*extra), client=RecordedClient())


def test_scan_runs_every_phase(dirs: Dirs, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "01-resolve: 1 ok, 1 skipped, 1 error" in err
    # demo downloads; pure and missing never leave phase 01's status.
    assert "02-fetch: 1 ok, 2 skipped, 0 error" in err
    # The recorded wheel body isn't a real zip, so phase 03 reports it.
    assert "03-inspect: 0 ok, 2 skipped, 1 error" in err
    assert "04-strings: 0 ok, 3 skipped, 0 error" in err
    assert "05-libraries: 0 ok, 3 skipped, 0 error" in err
    assert "08-fingerprint: 0 ok, 3 skipped, 0 error" in err
    assert "09-sboms: 0 ok, 3 skipped, 0 error" in err
    # The map names no library, so phases 06 and 07 have no lines.
    assert "06-upstream: 0 ok, 0 skipped, 0 error" in err
    assert "07-recognizers: 0 ok, 0 skipped, 0 error" in err
    assert (dirs.episode / "06-upstream.jsonl").read_text() == ""
    assert (dirs.episode / "07-recognizers.jsonl").read_text() == ""
    # No prefixes, so nothing to map: the todo has only its header.
    todo = (dirs.episode / "library-map-todo.csv").read_text()
    assert todo == ",".join(COLUMNS) + "\n"
    assert (dirs.episode / "library-report.md").is_file()
    demo, pure, missing = dirs.lines()
    assert demo["name"] == "demo"
    assert demo["status"] == "ok"
    assert demo["reason"] is None
    assert demo["version"] == "1.0"
    assert demo["filename"] == DEMO_TARGET
    assert set(demo) >= {"url", "sha256", "size", "upload_time"}
    assert demo["schema_version"] == 1
    assert pure["status"] == "skipped"
    assert pure["reason"] == "no_target"
    assert pure["version"] == "3.1"
    assert missing["status"] == "error"
    assert "HTTP 404" in str(missing["reason"])
    assert (dirs.cache / "wheels").is_dir()


def test_episode_json(dirs: Dirs) -> None:
    assert run(dirs, "--count", "50") == 0
    episode = json.loads((dirs.episode / "episode.json").read_text())
    assert episode["count"] == 3
    assert episode["target"] == TARGET == "cp312-manylinux_2_28_x86_64"
    assert episode["wheel_size_limit"] == WHEEL_SIZE_LIMIT
    assert episode["zip_member_size_limit"] == ZIP_MEMBER_SIZE_LIMIT
    assert episode["code_version"] == "0.0.0"
    assert episode["schema_version"] == EPISODE_SCHEMA_VERSION == 2
    assert len(episode["package_list_sha256"]) == 64


def test_rerun_skips_finished_phase(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(dirs, "--count", "2") == 0
    before = (dirs.episode / "01-resolve.jsonl").read_bytes()
    capsys.readouterr()
    client = RecordedClient()
    assert main(dirs.argv("--count", "2"), client=client) == 0
    assert client.requested == []
    assert "01-resolve: already finished, skipped" in capsys.readouterr().err
    assert (dirs.episode / "01-resolve.jsonl").read_bytes() == before


def test_count_is_clamped_and_matches_episode(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(dirs, "--count", "1") == 0
    assert [line["name"] for line in dirs.lines()] == ["demo"]
    capsys.readouterr()
    assert run(dirs, "--count", "2") == 2
    err = capsys.readouterr().err
    assert "count is 1, but this run's is 2" in err
    # A count above the list's length clamps to the same episode as 3.
    assert run(dirs, "--count", "3") == 2
    other = Dirs(dirs.episode.parent)
    other.episode = dirs.episode.parent / "big"
    assert run(other, "--count", "3") == 0
    assert run(other, "--count", "99") == 0


def test_changed_package_list_is_rejected(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(dirs, "--count", "1") == 0
    write_list(dirs.list, "demo,1.0", "other,2.0")
    assert run(dirs, "--count", "1") == 2
    assert "package_list_sha256" in capsys.readouterr().err


def test_bad_episode_json(dirs: Dirs, capsys: pytest.CaptureFixture[str]) -> None:
    dirs.episode.mkdir()
    (dirs.episode / "episode.json").write_text("[]")
    assert run(dirs, "--count", "1") == 2
    assert "not a JSON object" in capsys.readouterr().err
    (dirs.episode / "episode.json").write_text("{")
    assert run(dirs, "--count", "1") == 2


def test_missing_count_prints_full_help(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(dirs) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--episode-dir" in captured.err
    assert "Required. Scan the first N packages" in captured.err
    assert not dirs.episode.exists()


@pytest.mark.parametrize("count", ["0", "-1"])
def test_count_below_one(
    dirs: Dirs, count: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        run(dirs, "--count", count)
    assert exc.value.code == 2
    assert "--count must be at least 1" in capsys.readouterr().err


def test_directories_inside_git_tree(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    dirs = Dirs(tmp_path)
    dirs.episode = repo / "not" / "yet" / "episode"
    dirs.cache = repo / "cache"
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert f"episode directory {dirs.episode} is inside" in err
    assert f"cache directory {dirs.cache} is inside" in err
    # Pre-flight writes nothing.
    assert sorted(p.name for p in repo.iterdir()) == [".git"]


def test_git_work_tree_accepts_a_git_file(tmp_path: Path) -> None:
    # Worktrees and submodules have a .git file, not a directory.
    (tmp_path / ".git").write_text("gitdir: elsewhere\n")
    assert git_work_tree(tmp_path / "a" / "b") == tmp_path


def test_bad_package_list(dirs: Dirs, capsys: pytest.CaptureFixture[str]) -> None:
    dirs.list.write_text("name,version\n")
    assert run(dirs, "--count", "1") == 2
    assert "no packages" in capsys.readouterr().err
    assert not dirs.episode.exists()


def test_partial_file_stops_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    dirs.episode.mkdir()
    (dirs.episode / "01-resolve.jsonl.partial").write_text("")
    assert run(dirs, "--count", "1") == 2
    assert (
        "01-resolve.jsonl.partial exists; an earlier run stopped in phase 01. "
        "Delete it to rerun phase 01." in capsys.readouterr().err
    )


def test_gap_in_phase_files_names_files_to_delete(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    dirs.episode.mkdir()
    for name in ("01-resolve.jsonl", "03-inspect.jsonl", "04-strings.jsonl"):
        (dirs.episode / name).write_text("")
    (dirs.episode / "notes.txt").write_text("")
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert "03-inspect.jsonl exists but phase 02 is not finished" in err
    assert "Delete 04-strings.jsonl." in err
    assert "01-resolve.jsonl exists" not in err


def phase(name: str, status: str = "ok", reason: str | None = None) -> Phase:
    def go(package: Package, earlier: Mapping[str, Line]) -> Result:
        return Result(status, reason, {"seen": list(earlier)})

    return Phase(name, go)


PACKAGES = [Package("a", "1"), Package("b", "2")]


def test_lines_after_a_non_ok_line_are_skipped(tmp_path: Path) -> None:
    phases = [
        phase("01-one", "error", "boom"),
        phase("02-two"),
        phase("03-three"),
    ]
    assert run_phases(tmp_path, PACKAGES, phases, Stop(), io.StringIO()) == 0
    two = [json.loads(s) for s in (tmp_path / "02-two.jsonl").read_text().splitlines()]
    three = (tmp_path / "03-three.jsonl").read_text().splitlines()
    assert [(line["status"], line["reason"]) for line in two] == [
        ("skipped", "01-one")
    ] * 2
    assert [json.loads(s)["reason"] for s in three] == ["01-one"] * 2

    # A phase's own skip reason isn't a phase name, so the next phase names
    # the phase that skipped.
    (tmp_path / "skip").mkdir()
    phases = [phase("01-one", "skipped", "no_target"), phase("02-two")]
    assert run_phases(tmp_path / "skip", PACKAGES, phases, Stop(), io.StringIO()) == 0
    text = (tmp_path / "skip" / "02-two.jsonl").read_text()
    assert json.loads(text.splitlines()[0])["reason"] == "01-one"


def test_ok_lines_reach_the_next_phase(tmp_path: Path) -> None:
    phases = [phase("01-one"), phase("02-two")]
    assert run_phases(tmp_path, PACKAGES, phases, Stop(), io.StringIO()) == 0
    lines = (tmp_path / "02-two.jsonl").read_text().splitlines()
    assert [json.loads(s)["seen"] for s in lines] == [["01-one"]] * 2


def test_stop_between_packages(tmp_path: Path) -> None:
    stop = Stop()

    def go(package: Package, earlier: Mapping[str, Line]) -> Result:
        stop.requested = True
        return Result("ok")

    err = io.StringIO()
    status = run_phases(tmp_path, PACKAGES, [Phase("01-one", go)], stop, err)
    assert status == EXIT_INTERRUPTED
    partial = tmp_path / "01-one.jsonl.partial"
    # The current package finished; the next one never started.
    assert [json.loads(s)["name"] for s in partial.read_text().splitlines()] == ["a"]
    assert not (tmp_path / "01-one.jsonl").exists()
    assert "interrupted" in err.getvalue()


def test_sigint_sets_the_stop_flag(tmp_path: Path, dirs: Dirs) -> None:
    stop = Stop()

    class Interrupting(RecordedClient):
        def stream(self, url: str) -> Iterator[bytes]:
            # Call the installed handler directly instead of raising a signal.
            handler = signal.getsignal(signal.SIGINT)
            assert callable(handler)
            handler(signal.SIGINT, None)
            return super().stream(url)

    original = signal.getsignal(signal.SIGINT)
    status = scan(
        dirs.list,
        dirs.map,
        dirs.ambiguous,
        dirs.cves,
        dirs.line_eol,
        dirs.episode,
        dirs.cache,
        3,
        Interrupting(),
        io.StringIO(),
        stop,
    )
    assert status == EXIT_INTERRUPTED
    assert stop.requested
    assert signal.getsignal(signal.SIGINT) is original
    assert (dirs.episode / "01-resolve.jsonl.partial").read_text().count("\n") == 1


@pytest.mark.parametrize("name", ["01-resolve.jsonl", "01-resolve.jsonl.partial"])
def test_phase_files_without_episode_json(
    dirs: Dirs, name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    dirs.episode.mkdir()
    (dirs.episode / name).write_text("")
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert "episode.json is missing" in err
    assert f"Delete {name}, or use a separate episode directory." in err
    assert not (dirs.episode / "episode.json").exists()


def test_stop_between_phases_leaves_no_partial(tmp_path: Path) -> None:
    stop = Stop()

    def go(package: Package, earlier: Mapping[str, Line]) -> Result:
        if package.name == PACKAGES[-1].name:
            stop.requested = True
        return Result("ok")

    err = io.StringIO()
    phases = [Phase("01-one", go), phase("02-two")]
    assert run_phases(tmp_path, PACKAGES, phases, stop, err) == EXIT_INTERRUPTED
    assert sorted(p.name for p in tmp_path.iterdir()) == ["01-one.jsonl"]
    assert "interrupted before 02-two" in err.getvalue()


def test_stop_during_the_last_phase_exits_130(tmp_path: Path) -> None:
    stop = Stop()

    def go(package: Package, earlier: Mapping[str, Line]) -> Result:
        if package.name == PACKAGES[-1].name:
            stop.requested = True
        return Result("ok")

    err = io.StringIO()
    assert run_phases(tmp_path, PACKAGES, [Phase("01-one", go)], stop, err) == 130
    assert sorted(p.name for p in tmp_path.iterdir()) == ["01-one.jsonl"]
    assert "interrupted after the last phase finished" in err.getvalue()


def resolved_line(**overrides: object) -> Line:
    line: Line = {
        "status": "ok",
        "filename": "foo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        "url": "https://files.example/foo.whl",
        "sha256": "ab" * 32,
        "size": 1,
        "upload_time": "2026-09-01T12:00:00Z",
    }
    line.update(overrides)
    return line


def test_phase_02_downloads_ok_wheel_and_records_path(dirs: Dirs) -> None:
    assert run(dirs, "--count", "3") == 0
    [demo, pure, missing] = dirs.lines("02-fetch")
    assert demo["status"] == "ok"
    assert demo["reason"] is None
    cached = Path(str(demo["path"]))
    assert cached.is_file()
    assert cached.name == DEMO_TARGET
    assert cached.parent.parent == dirs.cache / "wheels"
    # A skipped phase 01 line turns into a skipped phase 02 line whose reason
    # is the phase where it first wasn't ok.
    assert pure["status"] == "skipped" and pure["reason"] == "01-resolve"
    assert missing["status"] == "skipped" and missing["reason"] == "01-resolve"
    assert "path" not in pure and "path" not in missing


def test_phase_02_too_large_is_skipped_without_downloading(tmp_path: Path) -> None:
    client = RecordedClient()
    phase = fetch_phase(client, tmp_path)
    previous = resolved_line(size=WHEEL_SIZE_LIMIT + 1)
    result = phase.run(Package("foo", "1"), {"01-resolve": previous})
    assert result == Result("skipped", "too_large")
    assert client.requested == []
    assert not (tmp_path / "wheels").exists()


def test_phase_02_at_the_limit_downloads(tmp_path: Path) -> None:
    phase = fetch_phase(RecordedClient(), tmp_path)
    previous = resolved_line(size=WHEEL_SIZE_LIMIT)
    # The limit itself isn't "over the limit"; the download attempt proceeds
    # and the recorded body's sha256 won't match, so phase 02 records an
    # error rather than a too_large skip.
    result = phase.run(Package("foo", "1"), {"01-resolve": previous})
    assert result.status == "error"
    assert "does not match" in (result.reason or "")


def test_phase_02_download_error(tmp_path: Path) -> None:
    client = RecordedClient({"https://files.example/foo.whl": b"wrong"})
    phase = fetch_phase(client, tmp_path)
    previous = resolved_line(size=5)
    result = phase.run(Package("foo", "1"), {"01-resolve": previous})
    assert result.status == "error"
    assert "does not match" in (result.reason or "")


def test_phase_02_is_skipped_when_phase_01_skipped(dirs: Dirs) -> None:
    # Smoke the chained-skip behaviour by driving a two-phase run_phases
    # with phase 01 returning skipped and no_target, then phase 02 fails if
    # it runs. puredemo never produces a WheelFile.
    err = io.StringIO()
    status = scan(
        dirs.list,
        dirs.map,
        dirs.ambiguous,
        dirs.cves,
        dirs.line_eol,
        dirs.episode,
        dirs.cache,
        2,
        RecordedClient(),
        err,
    )
    assert status == 0
    [demo, pure] = dirs.lines("02-fetch")
    assert pure["status"] == "skipped" and pure["reason"] == "01-resolve"
    assert demo["status"] == "ok"


def inspect_previous(path: Path) -> dict[str, Line]:
    return {"02-fetch": {"status": "ok", "path": str(path)}}


def test_phase_03_inspects_wheel(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "foo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        {"foo.libs/libz-abc123.so.1.3.1": LIBS_ELF},
    )
    phase = inspect_phase()
    result = phase.run(Package("foo", "1"), inspect_previous(wheel))
    assert result.status == "ok"
    assert result.data["wheel"] == wheel.name
    records = result.data["records"]
    assert isinstance(records, list) and len(records) == 1
    assert records[0]["path"] == "foo.libs/libz-abc123.so.1.3.1"
    assert records[0]["needed"] == ["libc.so.6"]
    assert result.data["skipped_members"] == []


def test_phase_03_reports_bad_zip_as_error(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip at all")
    result = inspect_phase().run(Package("x", "1"), inspect_previous(bogus))
    assert result.status == "error"
    assert "not a valid zip" in (result.reason or "")


def test_phase_03_reports_missing_file_as_error(tmp_path: Path) -> None:
    result = inspect_phase().run(
        Package("x", "1"), inspect_previous(tmp_path / "missing.whl")
    )
    assert result.status == "error"
    assert "no such file" in (result.reason or "")


def test_phase_03_skips_oversized_zip_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = build_wheel(
        tmp_path / "big.whl",
        {
            "big.libs/libsmall.so": LIBS_ELF,
            "big.libs/libhuge.so": b"\x7fELF" + b"\x00" * 1000,
        },
    )
    monkeypatch.setattr(scan_module, "ZIP_MEMBER_SIZE_LIMIT", 100)
    result = inspect_phase().run(Package("big", "1"), inspect_previous(wheel))
    assert result.status == "ok"
    records = result.data["records"]
    assert isinstance(records, list) and len(records) == 0
    skipped = result.data["skipped_members"]
    assert isinstance(skipped, list)
    paths = {m["path"] for m in skipped}
    assert paths == {"big.libs/libsmall.so", "big.libs/libhuge.so"}


def test_phase_03_is_skipped_when_phase_02_too_large(tmp_path: Path) -> None:
    # Drive a mini three-phase run through run_phases with hand-crafted
    # phases; phase 02 returns too_large and phase 03 must auto-skip with
    # reason "02-fetch" (not "too_large").
    def phase_01(_: Package, _e: Mapping[str, Line]) -> Result:
        return Result("ok", None, {"size": 1})

    def phase_02(_: Package, _e: Mapping[str, Line]) -> Result:
        return Result("skipped", "too_large")

    def phase_03_fail(_: Package, _e: Mapping[str, Line]) -> Result:
        raise AssertionError("phase 03 ran despite too_large")

    phases = [
        Phase("01-resolve", phase_01),
        Phase("02-fetch", phase_02),
        Phase("03-inspect", phase_03_fail),
    ]
    err = io.StringIO()
    assert run_phases(tmp_path, [Package("x", "1")], phases, Stop(), err) == 0
    [line] = [
        json.loads(s) for s in (tmp_path / "03-inspect.jsonl").read_text().splitlines()
    ]
    assert line["status"] == "skipped"
    assert line["reason"] == "02-fetch"


def test_phases_get_every_earlier_line_and_skip_on_the_previous(
    tmp_path: Path,
) -> None:
    seen: list[dict[str, object]] = []

    def record(earlier: Mapping[str, Line]) -> Result:
        seen.append({name: line["status"] for name, line in earlier.items()})
        return Result("ok")

    def three(package: Package, earlier: Mapping[str, Line]) -> Result:
        record(earlier)
        return Result("ok" if package.name == "a" else "error", "boom")

    def four(package: Package, earlier: Mapping[str, Line]) -> Result:
        return record(earlier)

    first = [phase("01-one"), phase("02-two"), Phase("03-three", three)]
    assert run_phases(tmp_path, PACKAGES, first, Stop(), io.StringIO()) == 0
    # A later run with one more phase reads the finished phases from disk.
    later = [*first, Phase("04-four", four)]
    assert run_phases(tmp_path, PACKAGES, later, Stop(), io.StringIO()) == 0
    ok = {"01-one": "ok", "02-two": "ok"}
    assert seen == [ok, ok, ok | {"03-three": "ok"}]
    lines = (tmp_path / "04-four.jsonl").read_text().splitlines()
    assert [(json.loads(s)["status"], json.loads(s)["reason"]) for s in lines] == [
        ("ok", None),
        ("skipped", "03-three"),
    ]


def strings_earlier(path: Path) -> dict[str, Line]:
    # Phase 03's line doesn't carry the wheel's path; phase 02's does.
    ok: Line = {"status": "ok"}
    return inspect_previous(path) | {"03-inspect": ok}


def test_phase_04_lists_strings(tmp_path: Path) -> None:
    banner = b"\0 deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly \0"
    wheel = build_wheel(
        tmp_path / "foo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        {"foo/etree.so": build_elf(["libc.so.6"], rodata=banner)},
    )
    result = strings_phase().run(Package("foo", "1"), strings_earlier(wheel))
    assert result.status == "ok"
    assert result.data["wheel"] == wheel.name
    assert result.data["skipped_members"] == []
    [record] = cast(list[dict[str, Any]], result.data["records"])
    assert record["path"] == "foo/etree.so"
    [string] = record["strings"]
    assert string["template"] == " deflate #.#.# Copyright #-# Jean-loup Gailly "
    assert string["section"] == ".rodata"


def test_phase_04_reports_bad_zip_as_error(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip at all")
    result = strings_phase().run(Package("x", "1"), strings_earlier(bogus))
    assert result.status == "error"
    assert "not a valid zip" in (result.reason or "")


def test_phase_04_skips_oversized_zip_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = build_wheel(tmp_path / "big.whl", {"big.libs/libbig.so": LIBS_ELF})
    monkeypatch.setattr(scan_module, "ZIP_MEMBER_SIZE_LIMIT", 100)
    result = strings_phase().run(Package("big", "1"), strings_earlier(wheel))
    assert result.status == "ok"
    assert result.data["records"] == []
    assert result.data["skipped_members"] == [
        {"path": "big.libs/libbig.so", "size": len(LIBS_ELF)}
    ]


def test_missing_library_map_is_a_usage_error(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = dirs.argv("--count", "1")
    i = argv.index("--library-map")
    del argv[i : i + 2]
    with pytest.raises(SystemExit) as exc:
        main(argv, client=RecordedClient())
    assert exc.value.code == 2
    assert "--library-map" in capsys.readouterr().err
    assert not dirs.episode.exists()


def test_bad_library_map_fails_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    dirs.map.write_text(
        ",".join(COLUMNS)
        + "\nlibz,zlib,r,v{version},,single_line,header_string,{version},f,,none,\n"
    )
    assert run(dirs, "--count", "1") == 2
    assert f"{dirs.map}:2: unknown kind 'header_string'" in capsys.readouterr().err
    assert not dirs.episode.exists()
    # Both inputs are checked, so one run names both problems.
    dirs.list.write_text("name,version\n")
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert "unknown kind" in err and "no packages" in err
    dirs.map.unlink()
    assert run(dirs, "--count", "1") == 2
    assert "No such file" in capsys.readouterr().err


def test_phase_05_lists_libs_files_with_their_prefixes(tmp_path: Path) -> None:
    records: list[object] = [
        {"path": "foo.libs/libjpeg-1a2b3c4d.so.62.4.0", "in_libs_dir": True},
        {"path": "foo/_imaging.so", "in_libs_dir": False},
        {"path": "foo.libs/libfoo.so.1", "in_libs_dir": True},
    ]
    earlier: dict[str, Line] = {
        "03-inspect": {"status": "ok", "records": records},
        "04-strings": {"status": "ok", "records": []},
    }
    phase = libraries_phase(tmp_path)
    assert phase.name == "05-libraries"
    result = phase.run(Package("foo", "1"), earlier)
    assert result == Result(
        "ok",
        None,
        {
            "libraries": [
                {"path": "foo.libs/libjpeg-1a2b3c4d.so.62.4.0", "prefix": "libjpeg"},
                {"path": "foo.libs/libfoo.so.1", "prefix": "libfoo"},
            ]
        },
    )


def test_finish_runs_before_the_phase_file_is_finished(tmp_path: Path) -> None:
    seen: list[object] = []

    def finish(names: Sequence[str], lines: Lines) -> None:
        seen.append(list(names))
        seen.append({n: list(lines[n]) for n in names})
        seen.append(sorted(p.name for p in tmp_path.iterdir()))

    phases = [phase("01-one", "error", "boom"), Phase("02-two", phase("x").run, finish)]
    assert run_phases(tmp_path, PACKAGES, phases, Stop(), io.StringIO()) == 0
    assert seen == [
        ["a", "b"],
        {"a": ["01-one", "02-two"], "b": ["01-one", "02-two"]},
        ["01-one.jsonl", "02-two.jsonl.partial"],
    ]
    # A rerun skips the finished phase, and its finish with it.
    assert run_phases(tmp_path, PACKAGES, phases, Stop(), io.StringIO()) == 0
    assert len(seen) == 3


def test_a_failed_finish_leaves_the_partial_file(tmp_path: Path) -> None:
    def finish(names: Sequence[str], lines: Lines) -> None:
        raise OSError("disk full")

    phases = [Phase("01-one", phase("x").run, finish)]
    with pytest.raises(OSError, match="disk full"):
        run_phases(tmp_path, PACKAGES, phases, Stop(), io.StringIO())
    assert sorted(p.name for p in tmp_path.iterdir()) == ["01-one.jsonl.partial"]


def test_interrupted_phase_skips_finish(tmp_path: Path) -> None:
    stop = Stop()

    def go(package: Package, earlier: Mapping[str, Line]) -> Result:
        stop.requested = True
        return Result("ok")

    def finish(names: Sequence[str], lines: Lines) -> None:
        raise AssertionError("finish ran for an unfinished phase")

    phases = [Phase("01-one", go, finish)]
    assert run_phases(tmp_path, PACKAGES, phases, stop, io.StringIO()) == 130


LIBS = {
    "demo": [
        ("demo.libs/libpng16-1a2b3c4d.so.16.58.0", "libpng version 1.6.58"),
        ("demo.libs/libgfortran-040039e1.so.5.0.0", "GNU Fortran 14.2.1"),
        ("demo/_ext.so", "deflate 1.3.1 Copyright"),
    ],
    "puredemo": [("puredemo.libs/libpng16.so.16", "libpng version 1.6.50")],
}


def stub_phases(client: object, cache_dir: Path, episode: Path) -> list[Phase]:
    """Phases 01 to 04 as stubs over LIBS, then the real phase 05."""

    def resolve(package: Package, earlier: Mapping[str, Line]) -> Result:
        if package.name not in LIBS:
            return Result("error", "HTTP 404")
        # demo's wheel carries an SBOM for phase 09; puredemo's doesn't.
        members = {"demo-1.0.dist-info/sboms/x.json": b"{}"}
        wheel = build_wheel(
            cache_dir / f"{package.name}.whl",
            members if package.name == "demo" else {},
        )
        sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
        uploaded = "2026-01-01T23:30:00-02:00"
        return Result("ok", None, {"sha256": sha256, "upload_time": uploaded})

    def fetch(package: Package, earlier: Mapping[str, Line]) -> Result:
        return Result("ok", None, {"path": str(cache_dir / f"{package.name}.whl")})

    def inspect(package: Package, earlier: Mapping[str, Line]) -> Result:
        records: list[object] = [
            {"path": path, "in_libs_dir": ".libs/" in path}
            for path, _ in LIBS[package.name]
        ]
        return Result("ok", None, {"records": records})

    def strings(package: Package, earlier: Mapping[str, Line]) -> Result:
        records: list[object] = [
            {
                "path": path,
                "sha256": f"sha-{path}",
                "strings": [
                    {
                        "offset": 16,
                        "section": ".rodata",
                        "text": text,
                        "template": "T " + text,
                    },
                    {
                        "offset": 64,
                        "section": ".comment",
                        "text": "GCC: (GNU) 14.2.1",
                        "template": "G",
                    },
                ],
            }
            for path, text in LIBS[package.name]
        ]
        wheel = f"{package.name}.whl"
        return Result("ok", None, {"wheel": wheel, "records": records})

    return [
        Phase("01-resolve", resolve),
        Phase("02-fetch", fetch),
        Phase("03-inspect", inspect),
        Phase("04-strings", strings),
        scan_module.libraries_phase(episode),
    ]


def test_scan_stops_for_the_manual_step(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "phases", stub_phases)
    assert run(dirs, "--count", "3") == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err
    assert "05-libraries: 2 ok, 1 skipped, 0 error" in err
    assert err.endswith(
        "library-map-todo.csv lists 2 prefixes the library map doesn't; add rows "
        "for them, or mark them skip, and rerun:\n  libpng16\n  libgfortran\n"
    )
    [demo, pure, missing] = dirs.lines("05-libraries")
    demo_libs = cast(list[dict[str, str]], demo["libraries"])
    assert [lib["prefix"] for lib in demo_libs] == ["libpng16", "libgfortran"]
    assert pure["libraries"] == [
        {"path": "puredemo.libs/libpng16.so.16", "prefix": "libpng16"}
    ]
    assert missing["status"] == "skipped" and missing["reason"] == "01-resolve"
    todo = dirs.episode / "library-map-todo.csv"
    header = ",".join(COLUMNS)
    assert (
        todo.read_text() == f"{header}\nlibpng16,,,,,,,,,,,\nlibgfortran,,,,,,,,,,,\n"
    )
    text = (dirs.episode / "library-report.md").read_text()
    assert "1. ` libpng16 `: 2 wheels, 2 files\n2. ` libgfortran `: 1 wheel" in text
    assert "2 wheels, 2 files: demo, puredemo" in text
    assert "   - e.g. ` libpng version 1.6.58 `" in text
    assert "GCC" not in text and "deflate" not in text

    # A rerun skips every phase but still rewrites the todo.
    todo.unlink()
    report_before = (dirs.episode / "library-report.md").read_bytes()
    assert run(dirs, "--count", "3") == 3
    assert "05-libraries: already finished, skipped" in capsys.readouterr().err
    assert todo.read_text().count("\n") == 3
    assert (dirs.episode / "library-report.md").read_bytes() == report_before

    # Mapping one prefix leaves the other, and phase 06 doesn't run.
    repo = make_repo(dirs.episode.parent / "libpng", {"v1.6.58": {}})
    png = f"libpng16,libpng,{repo},v{{version}},,single_line,library_string,"
    png += "libpng version {version},p.c,,none,"
    dirs.map.write_text(f"{header}\n{png}\n")
    assert run(dirs, "--count", "3") == 3
    assert "\n  libgfortran\n" in capsys.readouterr().err
    assert todo.read_text() == f"{header}\nlibgfortran,,,,,,,,,,,\n"
    assert not list(dirs.episode.glob("06-*"))
    # Stopping at the manual step writes no fingerprint report.
    assert not (dirs.episode / "fingerprint-report.md").exists()

    # Once every prefix is listed, the todo is empty and phase 06 runs.
    dirs.map.write_text(f"{header}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "library-map-todo" not in err
    assert "06-upstream: 1 ok, 0 skipped, 0 error" in err
    assert "07-recognizers: 1 ok, 0 skipped, 0 error" in err
    assert "08-fingerprint: 2 ok, 1 skipped, 0 error" in err
    assert "09-sboms: 2 ok, 1 skipped, 0 error" in err
    # libpng's cpe is none, so phase 10 asks NVD nothing.
    assert err.endswith("10-cves: 0 ok, 1 skipped, 0 error\n")
    assert todo.read_text() == f"{header}\n"
    [libpng] = dirs.lines("06-upstream")
    assert libpng["library"] == "libpng"
    assert libpng["schema_version"] == 3
    tag = {"tag": "v1.6.58", "version": "1.6.58", "date": "1970-01-12", "release": True}
    assert libpng["tags"] == [tag]
    demo, pure, missing = dirs.lines("08-fingerprint")
    path = "demo.libs/libpng16-1a2b3c4d.so.16.58.0"
    assert demo["wheel"] == "demo.whl"
    assert demo["records"] == [
        {
            "schema_version": 3,
            "wheel": "demo.whl",
            "path": path,
            "sha256": f"sha-{path}",
            "library": "libpng",
            "relation": "contains",
            "basis": "library_string",
            "version": "1.6.58",
            "conflict": False,
            "evidence": [
                {
                    "kind": "library_string",
                    "text": "libpng version 1.6.58",
                    "offset": 16,
                    "section": ".rodata",
                }
            ],
        }
    ]
    [record] = cast(list[Line], pure["records"])
    assert (record["library"], record["version"]) == ("libpng", "1.6.50")
    assert (missing["status"], missing["reason"]) == ("skipped", "01-resolve")

    demo, pure, missing = dirs.lines("09-sboms")
    [sbom] = cast(list[Line], demo["records"])
    assert (sbom["path"], sbom["format"]) == (
        "demo-1.0.dist-info/sboms/x.json",
        "other",
    )
    assert (pure["status"], pure["records"]) == ("ok", [])
    assert (missing["status"], missing["reason"]) == ("skipped", "01-resolve")

    # A rerun skips every phase, phases 08 and 09 included, and lists each
    # once.
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "08-fingerprint: already finished, skipped" in err
    assert "09-sboms: already finished, skipped\n" in err
    assert err.endswith("10-cves: already finished, skipped\n")
    assert err.count("05-libraries: already finished, skipped") == 1

    # An episode finished through phase 08 before phase 09 existed runs only
    # phases 09 and 10, with no file deleted.
    lines_09 = dirs.lines("09-sboms")
    (dirs.episode / "10-cves.jsonl").unlink()
    (dirs.episode / "09-sboms.jsonl").unlink()
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    *finished, last, cves = err.splitlines()
    assert finished == [
        f"{name}: already finished, skipped"
        for name in [
            "01-resolve",
            "02-fetch",
            "03-inspect",
            "04-strings",
            "05-libraries",
            "06-upstream",
            "07-recognizers",
            "08-fingerprint",
        ]
    ]
    assert last == "09-sboms: 2 ok, 1 skipped, 0 error"
    assert cves == "10-cves: 0 ok, 1 skipped, 0 error"
    assert dirs.lines("09-sboms") == lines_09

    # Every run with phase 08 finished rewrites the fingerprint report.
    report = dirs.episode / "fingerprint-report.md"
    text = report.read_text()
    assert "## demo 1.0\n\n`demo.whl`\n" in text
    row = "| libpng16-1a2b3c4d.so.16.58.0 | libpng | 1.6.58 | library_string |  |"
    assert row in text
    assert "| libgfortran-040039e1.so.5.0.0 | skip | — | — | not tracked |" in text
    assert "## missing 9.9\n\nerror at 01-resolve: HTTP 404\n" in text
    report.write_text("stale")
    assert run(dirs, "--count", "3") == 0
    assert report.read_text() == text
    report.unlink()
    assert run(dirs, "--count", "3") == 0
    assert report.read_text() == text

    # And the staleness report, from phases 01, 05, 06 and 08.
    report = dirs.episode / "staleness-report.md"
    text = report.read_text()
    # The upload time is read in UTC: the next day.
    assert "## demo 1.0\n\n`demo.whl`, uploaded 2026-01-02\n" in text
    row = (
        "| libpng16-1a2b3c4d.so.16.58.0 | libpng | 1.6.58 | library_string |  "
        "| 1.6.58 (1970-01-12) | 0 | 0 |"
    )
    assert row in text
    assert "| libpng | 1.6.50 | library_string |  | not compared: no release" in text
    assert "## missing 9.9\n\nerror at 01-resolve: HTTP 404\n" in text
    report.unlink()
    assert run(dirs, "--count", "3") == 0
    assert report.read_text() == text


def test_report_shows_why_a_package_stopped_at_phase_02(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    def with_too_large(client: object, cache_dir: Path, episode: Path) -> list[Phase]:
        stubs = stub_phases(client, cache_dir, episode)

        def too_large(package: Package, earlier: Mapping[str, Line]) -> Result:
            if package.name == "puredemo":
                return Result("skipped", "too_large")
            return stubs[1].run(package, earlier)

        return [stubs[0], Phase("02-fetch", too_large), *stubs[2:]]

    monkeypatch.setattr(scan_module, "phases", with_too_large)
    repo = make_repo(dirs.episode.parent / "libpng", {"v1.6.58": {}})
    png = f"libpng16,libpng,{repo},v{{version}},,single_line,library_string,"
    png += "libpng version {version},p.c,,none,"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == 0
    [_, pure, _] = dirs.lines("08-fingerprint")
    assert (pure["status"], pure["reason"]) == ("skipped", "02-fetch")
    text = (dirs.episode / "fingerprint-report.md").read_text()
    assert "## puredemo 3.1\n\nskipped at 02-fetch: too_large\n" in text


# Phase 06, against synthetic repositories built in tmp_path.


def upstream(tmp_path: Path, library: Library) -> Result:
    phase = upstream_phase(tmp_path / "cache", tmp_path, "sha")
    assert phase.name == "06-upstream"
    return phase.run(library, {})


def test_upstream_libraries_in_order_of_first_appearance(tmp_path: Path) -> None:
    path = tmp_path / "m.csv"
    path.write_text(
        ",".join(COLUMNS)
        + "\nlibz,zlib,r,v{version},,single_line,,,,,none,"
        + "\nlibgfortran,skip,,,,,,,,,,"
        + "\nlibpng16,libpng,p,v{version},,single_line,,,,,none,"
        + "\nlibz2,zlib,r,v{version},,single_line,,,,,none,\n"
    )
    assert upstream_libraries(load_library_map(path)) == [
        Library("zlib", "r", "v{version}", "none"),
        Library("libpng", "p", "v{version}", "none"),
    ]


def test_phase_06_clones_then_fetches(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "zlib", {"v1.3.1": {}, "v1.3.2-pre": {}, "x": {}})
    library = Library("zlib", str(repo), "v{version}")
    result = upstream(tmp_path, library)
    assert result == Result(
        "ok",
        None,
        {
            "repo": str(repo),
            "tags": [
                {
                    "tag": "v1.3.1",
                    "version": "1.3.1",
                    "date": "1970-01-12",
                    "release": True,
                },
                {
                    "tag": "v1.3.2-pre",
                    "version": "1.3.2-pre",
                    "date": "1970-01-12",
                    "release": False,
                },
            ],
        },
    )
    clone = tmp_path / "cache" / "upstream" / "zlib.git"
    assert (clone / "HEAD").is_file() and not (clone / ".git").exists()

    # A later run fetches into the clone, so it sees a new tag.
    make_repo(repo, {"v1.3.3": {}})
    result = upstream(tmp_path, library)
    tags = cast(list[dict[str, str]], result.data["tags"])
    assert [tag["tag"] for tag in tags] == ["v1.3.1", "v1.3.2-pre", "v1.3.3"]
    assert clone_or_fetch(str(repo), clone) == "fetch"

    # A failed fetch is an error line too.
    (repo / ".git").rename(tmp_path / "moved")
    result = upstream(tmp_path, library)
    assert result.status == "error"
    assert str(result.reason).startswith("git fetch failed: ")


def test_tags_have_their_creator_dates(tmp_path: Path) -> None:
    """A lightweight tag's date is its commit's, an annotated tag's its
    tagger's, each in its own time zone."""
    repo = tmp_path / "r"
    git("init", "--quiet", str(repo))
    user = ("-c", "user.name=t", "-c", "user.email=t@example.com")
    # 23:00 at -05:00 is the next day in UTC; the date keeps its own zone.
    commit = "2024-03-01T23:00:00-05:00"
    env = {"GIT_AUTHOR_DATE": commit, "GIT_COMMITTER_DATE": commit}
    git("-C", str(repo), *user, "commit", "-qm", "c", "--allow-empty", env=env)
    git("-C", str(repo), *user, "tag", "light", env=env)
    later = {"GIT_COMMITTER_DATE": "2024-05-10T12:00:00+00:00"}
    git("-C", str(repo), *user, "tag", "-a", "-m", "r", "annotated", env=later)
    assert tags(repo) == {"annotated": "2024-05-10", "light": "2024-03-01"}
    assert tags(make_repo(tmp_path / "empty", {})) == {}


def test_phase_06_lists_versions_spelled_with_underscores(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "pg", {"REL_18_6": {}, "REL_18_BETA1": {}})
    result = upstream(tmp_path, Library("postgresql", str(repo), "REL_{version}"))
    assert result.data["tags"] == [
        {"tag": "REL_18_6", "version": "18.6", "date": "1970-01-12", "release": True},
        {
            "tag": "REL_18_BETA1",
            "version": "18_BETA1",
            "date": "1970-01-12",
            "release": False,
        },
    ]


def test_phase_06_takes_each_version_from_the_first_pattern(tmp_path: Path) -> None:
    """lcms2's tags: lcms2-2.7, lcms2.19 and a bare 2.11 (roadmap S.3)."""
    names = ["lcms2-2.7", "lcms2.19", "lcms2.19rc1", "2.11", "lcm2.16rc1"]
    repo = make_repo(tmp_path / "lcms2", {name: {} for name in names})
    tags = "lcms2-{version} lcms{version} {version}"
    result = upstream(tmp_path, Library("lcms2", str(repo), tags))
    listed = cast(list[dict[str, object]], result.data["tags"])
    assert [(t["tag"], t["version"], t["release"]) for t in listed] == [
        ("2.11", "2.11", True),
        ("lcms2-2.7", "2.7", True),
        ("lcms2.19", "2.19", True),
        ("lcms2.19rc1", "2.19rc1", False),
    ]


def test_phase_06_marks_not_release_versions(tmp_path: Path) -> None:
    names = ["3.1.4.1", "3.1.90", "3.2.0", "2.0.7-esr"]
    repo = make_repo(tmp_path / "ljt", {name: {} for name in names})
    library = Library("libjpeg-turbo", str(repo), "{version}", "", r"\d+\.\d+\.9\d")
    listed = cast(list[dict[str, object]], upstream(tmp_path, library).data["tags"])
    assert [(t["version"], t["release"]) for t in listed] == [
        ("2.0.7-esr", False),
        ("3.1.4.1", True),
        ("3.1.90", False),
        ("3.2.0", True),
    ]


def test_phase_06_no_matching_tag_is_an_error(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "zlib", {"1.3.1": {}, "1.3.2": {}})
    result = upstream(tmp_path, Library("zlib", str(repo), "v{version}"))
    assert result == Result(
        "error", "tags 'v{version}' matches none of the 2 tags", {"repo": str(repo)}
    )


def test_phase_06_failed_clone_is_an_error(tmp_path: Path) -> None:
    missing = str(tmp_path / "missing")
    result = upstream(tmp_path, Library("zlib", missing, "v{version}"))
    assert result.status == "error"
    assert str(result.reason).startswith("git clone failed: ")
    assert result.data == {"repo": missing}
    assert not (tmp_path / "cache" / "upstream" / "zlib.git").exists()


@pytest.mark.parametrize(
    "repo",
    [
        "https://gitlab.com/libtiff/libtiff",
        "https://chromium.googlesource.com/webm/libwebp",
        "https://github.com/madler/zlib",
    ],
)
def test_phase_06_clones_from_any_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, repo: str
) -> None:
    cloned: list[str] = []
    monkeypatch.setattr(scan_module, "clone_or_fetch", lambda r, d: cloned.append(r))
    monkeypatch.setattr(scan_module, "tags", lambda d: {"v1.3.1": "2024-01-22"})
    result = upstream(tmp_path, Library("zlib", repo, "v{version}"))
    assert result.status == "ok"
    assert cloned == [repo]


def test_phase_06_clones_from_a_host_that_refuses_filters(tmp_path: Path) -> None:
    """A server that refuses --filter gives a full clone, not an error."""
    repo = make_repo(tmp_path / "zlib", {"v1.3.1": {}})
    git("-C", str(repo), "config", "uploadpack.allowFilter", "false")
    url = (tmp_path / "zlib").as_uri()
    result = upstream(tmp_path, Library("zlib", url, "v{version}"))
    assert result.status == "ok"
    assert [t["tag"] for t in cast(list[Line], result.data["tags"])] == ["v1.3.1"]
    clone = tmp_path / "cache" / "upstream" / "zlib.git"
    assert clone_or_fetch(url, clone) == "fetch"


def test_clone_reads_a_leading_dash_as_a_repo(tmp_path: Path) -> None:
    clone = tmp_path / "zlib.git"
    with pytest.raises(GitError, match="repository '-q' does not exist"):
        clone_or_fetch("-q", clone)
    result = upstream(tmp_path, Library("zlib", "--template=x", "v{version}"))
    assert result.status == "error"
    assert "repository '--template=x' does not exist" in str(result.reason)
    assert not clone.exists()


def test_phase_06_refuses_a_clone_of_another_repo(tmp_path: Path) -> None:
    zlib = make_repo(tmp_path / "zlib", {"v1.3.1": {}})
    ng = make_repo(tmp_path / "zlib-ng", {"2.3.3": {}})
    assert upstream(tmp_path, Library("zlib", str(zlib), "v{version}")).status == "ok"
    result = upstream(tmp_path, Library("zlib", str(ng), "{version}"))
    clone = tmp_path / "cache" / "upstream" / "zlib.git"
    assert result.status == "error"
    assert result.reason == f"{clone} is a clone of {zlib}, not {ng}; delete it"


def test_phase_06_refuses_a_directory_that_isnt_a_clone(tmp_path: Path) -> None:
    clone = tmp_path / "cache" / "upstream" / "zlib.git"
    clone.mkdir(parents=True)
    result = upstream(tmp_path, Library("zlib", "r", "v{version}"))
    assert result.status == "error"
    assert str(result.reason).startswith(f"{clone} isn't a clone (git config failed")
    assert str(result.reason).endswith("; delete it")


def test_phase_06_without_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = upstream(tmp_path, Library("zlib", "r", "v{version}"))
    assert result == Result("error", "git is not installed", {"repo": "r"})


def test_stop_between_libraries(tmp_path: Path) -> None:
    stop = Stop()

    def go(library: Library, earlier: Mapping[str, Line]) -> Result:
        stop.requested = True
        return Result("ok")

    libraries = [Library("zlib", "r", "v{version}"), Library("xz", "x", "v{version}")]
    phases = [Phase("06-upstream", go)]
    status = run_phases(tmp_path, libraries, phases, stop, io.StringIO(), "library")
    assert status == EXIT_INTERRUPTED
    partial = (tmp_path / "06-upstream.jsonl.partial").read_text().splitlines()
    assert [json.loads(line)["library"] for line in partial] == ["zlib"]


def test_changed_map_after_phase_06_fails_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = make_repo(dirs.episode.parent / "zlib", {"v1.3.1": {}})
    row = f"libz,zlib,{repo},v{{version}},,single_line,,,,,none,"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{row}\n")
    assert run(dirs, "--count", "3") == 0
    recorded = json.loads((dirs.episode / "episode.json").read_text())
    assert recorded["library_map_sha256"] == scan_module._sha256(dirs.map)
    capsys.readouterr()
    # An unchanged map reruns nothing.
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "06-upstream: already finished, skipped" in err
    assert "07-recognizers: already finished, skipped" in err

    dirs.map.write_text(f"{','.join(COLUMNS)}\n{row}\nlibfoo,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == 2
    assert capsys.readouterr().err == (
        "pypiscan scan: error: the library map has changed since phase 06 ran. "
        "Delete 06-upstream.jsonl, 07-recognizers.jsonl, 08-fingerprint.jsonl, "
        "09-sboms.jsonl, 10-cves.jsonl to rerun phase 06 and every later phase.\n"
    )

    # Without a recorded sha256, the map can't be checked either.
    del recorded["library_map_sha256"]
    (dirs.episode / "episode.json").write_text(json.dumps(recorded))
    assert run(dirs, "--count", "3") == 2
    assert "Delete 06-upstream.jsonl, 07-recognizers.jsonl, 08-fingerprint.jsonl" in (
        capsys.readouterr().err
    )


def test_version_1_episode_passes_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    """An episode.json from before phase 06 has schema_version 1 and no map
    sha256; pre-flight accepts it, and phase 06 upgrades it to version 2."""
    repo = make_repo(dirs.episode.parent / "zlib", {"v1.3.1": {}})
    dirs.map.write_text(
        f"{','.join(COLUMNS)}\nlibz,zlib,{repo},v{{version}},,single_line,,,,,none,\n"
    )
    dirs.episode.mkdir()
    v1 = {"schema_version": 1, **episode_inputs(dirs.list, 3), "code_version": "0"}
    (dirs.episode / "episode.json").write_text(json.dumps(v1))

    assert run(dirs, "--count", "3") == 0
    assert "pypiscan scan: error" not in capsys.readouterr().err
    recorded = json.loads((dirs.episode / "episode.json").read_text())
    assert recorded == v1 | {
        "schema_version": 2,
        "library_map_sha256": scan_module._sha256(dirs.map),
    }


def test_phase_06_writes_episode_json_whole_or_not_at_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = tmp_path / "episode.json"
    record.write_text('{"schema_version": 1}')
    phase = upstream_phase(tmp_path / "cache", tmp_path, "sha")
    assert phase.finish is not None
    write_text = Path.write_text

    def interrupted(path: Path, text: str, encoding: str | None = None) -> int:
        write_text(path, text[:5], encoding=encoding)
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", interrupted)
    with pytest.raises(OSError, match="disk full"):
        phase.finish([], {})
    monkeypatch.undo()
    assert record.read_text() == '{"schema_version": 1}'

    phase.finish([], {})
    assert json.loads(record.read_text()) == {
        "schema_version": 2,
        "library_map_sha256": "sha",
    }
    assert [p.name for p in tmp_path.iterdir() if p.is_file()] == ["episode.json"]


# Phase 07 and the per-library runner rule.


def test_per_library_phases_run_every_library(tmp_path: Path) -> None:
    """A per-library phase runs a library whatever its earlier lines say;
    a per-package phase still skips one whose previous line isn't ok."""
    first = {"zlib": Result("skipped", "x"), "xz": Result("error", "x")}
    ran: list[str] = []

    def go(library: Library, earlier: Mapping[str, Line]) -> Result:
        ran.append(library.name)
        return Result("ok")

    libraries = [Library("zlib", "r", "v{version}"), Library("xz", "x", "v{version}")]
    phases = [
        Phase("06-upstream", lambda lib, e: first[lib.name], skip_not_ok=False),
        Phase("07-recognizers", go, skip_not_ok=False),
    ]
    status = run_phases(tmp_path, libraries, phases, Stop(), io.StringIO(), "library")
    assert status == 0
    assert ran == ["zlib", "xz"]
    text = (tmp_path / "07-recognizers.jsonl").read_text()
    assert [json.loads(line)["status"] for line in text.splitlines()] == ["ok", "ok"]

    # The same items in a phase that keeps the default do get skipped.
    ran.clear()
    phases = [
        Phase("01-a", lambda lib, e: first[lib.name]),
        Phase("02-b", go),
    ]
    status = run_phases(tmp_path, libraries, phases, Stop(), io.StringIO(), "library")
    assert status == 0
    assert ran == []


RECOGNIZER_MAP = [
    "libpng16,libpng,P,v{version},,single_line,library_string,"
    "libpng version {version},png.c,,none,",
    "libpng16d,libpng,P,v{version},,single_line,bare_version,{version},png.h,,none,",
    "libcrypto,openssl,O,openssl-{version},,single_line,library_string,"
    "OpenSSL {version} {any},include/openssl/opensslv.h.in,,none,",
    "libssl,openssl,O,openssl-{version},,single_line,,,,,none,",
    "libwebp,libwebp,W,v{version},,single_line,,,,,none,",
    "libopenjp2,openjpeg,J,v{version},,single_line,build_path,{any}/openjpeg-{version}/{any},,,none,",
]


def recognizers(tmp_path: Path, name: str) -> Result:
    path = tmp_path / "m.csv"
    path.write_text("\n".join([",".join(COLUMNS), *RECOGNIZER_MAP]) + "\n")
    rows = load_library_map(path)
    by_name = {lib.name: lib for lib in upstream_libraries(rows)}
    phase = recognizers_phase(rows)
    assert phase.name == "07-recognizers" and not phase.skip_not_ok
    return phase.run(by_name[name], {})


def test_phase_07_lists_recognizers_under_every_prefix(tmp_path: Path) -> None:
    result = recognizers(tmp_path, "libpng")
    assert result == Result(
        "ok",
        None,
        {
            "recognizers": [
                {
                    "prefix": "libpng16",
                    "kind": "library_string",
                    "pattern": "libpng version {version}",
                    "identity_file": "png.c",
                },
                {
                    "prefix": "libpng16d",
                    "kind": "bare_version",
                    "pattern": "{version}",
                    "identity_file": "png.h",
                },
            ]
        },
    )
    entries = cast(list[dict[str, str]], result.data["recognizers"])
    found = [matcher(e["pattern"], e["kind"]) for e in entries]
    png = found[0].fullmatch("libpng version 1.6.58")
    assert png is not None and png[1] == "1.6.58"
    assert found[1].fullmatch("1.6.58") is not None


def test_phase_07_leaves_out_rows_with_no_kind(tmp_path: Path) -> None:
    result = recognizers(tmp_path, "openssl")
    assert result.status == "ok"
    assert result.data["recognizers"] == [
        {
            "prefix": "libcrypto",
            "kind": "library_string",
            "pattern": "OpenSSL {version} {any}",
            "identity_file": "include/openssl/opensslv.h.in",
        }
    ]


def test_phase_07_library_with_no_recognizer_is_skipped(tmp_path: Path) -> None:
    assert recognizers(tmp_path, "libwebp") == Result("skipped", "no_recognizer")


def test_phase_07_build_path_has_no_identity_file(tmp_path: Path) -> None:
    result = recognizers(tmp_path, "openjpeg")
    assert result.data["recognizers"] == [
        {
            "prefix": "libopenjp2",
            "kind": "build_path",
            "pattern": "{any}/openjpeg-{version}/{any}",
            "identity_file": None,
        }
    ]


def test_phase_07_runs_whatever_phase_06_said(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = str(dirs.episode.parent / "missing")
    row = f"libtiff,libtiff,{repo},v{{version}},,single_line,library_string,"
    row += '"LIBTIFF, Version {version}",libtiff/tiffvers.h.in,,none,'
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{row}\n")
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "07-recognizers: 1 ok, 0 skipped, 0 error" in err
    [upstream_line] = dirs.lines("06-upstream")
    assert upstream_line["status"] == "error"
    [line] = dirs.lines("07-recognizers")
    assert line == {
        "schema_version": 1,
        "library": "libtiff",
        "status": "ok",
        "reason": None,
        "recognizers": [
            {
                "prefix": "libtiff",
                "kind": "library_string",
                "pattern": "LIBTIFF, Version {version}",
                "identity_file": "libtiff/tiffvers.h.in",
            }
        ],
    }


def test_every_per_library_phase_runs_every_library(tmp_path: Path) -> None:
    """Phase's skip_not_ok defaults to the per-package rule, so a phase
    added to library_phases without clearing it would skip libraries."""
    phases = library_phases(tmp_path / "cache", tmp_path, "sha", [])
    assert [phase.name for phase in phases] == ["06-upstream", "07-recognizers"]
    assert [phase.name for phase in phases if phase.skip_not_ok] == []


def test_stop_during_part_2_leaves_no_phase_08(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "phases", stub_phases)

    def interrupt(library: Library, earlier: Mapping[str, Line]) -> Result:
        # Call the installed handler directly instead of raising a signal.
        handler = signal.getsignal(signal.SIGINT)
        assert callable(handler)
        handler(signal.SIGINT, None)
        return Result("ok")

    def part_2(*args: object) -> list[Phase[Library]]:
        return [Phase("06-upstream", interrupt, skip_not_ok=False)]

    monkeypatch.setattr(scan_module, "library_phases", part_2)
    header = ",".join(COLUMNS)
    png = "libpng16,libpng,r,v{version},,single_line,,,,,none,"
    dirs.map.write_text(f"{header}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == EXIT_INTERRUPTED
    assert "interrupted after the last phase finished" in capsys.readouterr().err
    assert not list(dirs.episode.glob("08-*"))
    assert not (dirs.episode / "fingerprint-report.md").exists()


# The list of ambiguous versions (roadmap 4.7).


def test_missing_ambiguous_versions_prints_full_help(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = dirs.argv("--count", "1")
    i = argv.index("--ambiguous-versions")
    del argv[i : i + 2]
    assert main(argv, client=RecordedClient()) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Required. List of ambiguous versions" in captured.err
    assert "--episode-dir" in captured.err
    assert not dirs.episode.exists()


def test_bad_ambiguous_list_fails_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    dirs.ambiguous.write_text(",".join(AMBIGUOUS_COLUMNS) + "\nzlib,1.3,1.3.1\n")
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert f"{dirs.ambiguous}:2: library 'zlib' isn't mapped" in err
    assert not dirs.episode.exists()


def test_editing_the_ambiguous_list_rewrites_the_report(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "phases", stub_phases)
    repo = make_repo(dirs.episode.parent / "libpng", {"v1.6.58": {}})
    png = f"libpng16,libpng,{repo},v{{version}},,single_line,library_string,"
    png += "libpng version {version},p.c,,none,"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == 0
    report = dirs.episode / "fingerprint-report.md"
    row = "| libpng16-1a2b3c4d.so.16.58.0 | libpng | 1.6.58 | library_string |"
    assert f"{row}  |" in report.read_text()
    capsys.readouterr()

    header = ",".join(AMBIGUOUS_COLUMNS)
    dirs.ambiguous.write_text(f"{header}\nlibpng,1.6.58,1.6.59\n")
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "08-fingerprint: already finished, skipped" in err
    assert "pypiscan scan: error" not in err
    assert f"{row} ambiguous: may also be 1.6.59 |" in report.read_text()


def test_editing_line_eol_rewrites_the_staleness_report(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "phases", stub_phases)
    repo = make_repo(dirs.episode.parent / "libpng", {"v1.6.58": {}})
    png = f"libpng16,libpng,{repo},v{{version}},,2,library_string,"
    png += "libpng version {version},p.c,,none,"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == 0
    report = dirs.episode / "staleness-report.md"
    row = "| libpng16-1a2b3c4d.so.16.58.0 | libpng | 1.6.58 | library_string |"
    assert "| 0 | 0 | 1.6 | unknown | 1.6.58 (" in report.read_text()
    assert row in report.read_text()
    capsys.readouterr()

    header = ",".join(LINE_EOL_COLUMNS)
    dirs.line_eol.write_text(f"{header}\nlibpng,1.6,maintained,https://e.org\n")
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "08-fingerprint: already finished, skipped" in err
    assert "pypiscan scan: error" not in err
    assert "| 1.6 | maintained |" in report.read_text()
    # The list isn't an episode input.
    assert "line" not in (dirs.episode / "episode.json").read_text()


def test_bad_line_eol_fails_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    # The test map tracks no library, so no line can name one.
    header = ",".join(LINE_EOL_COLUMNS)
    dirs.line_eol.write_text(f"{header}\nopenssl,3.5,maintained,https://e.org\n")
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert f"{dirs.line_eol}:2: library 'openssl' isn't mapped" in err
    assert not dirs.episode.exists()


def test_missing_line_eol_prints_full_help(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = dirs.argv("--count", "1")
    i = argv.index("--line-eol")
    del argv[i : i + 2]
    assert main(argv, client=RecordedClient()) == 2
    captured = capsys.readouterr()
    assert "Required. Lines' ends of life" in captured.err
    assert not dirs.episode.exists()


# The SBOM report (roadmap 5.2).

PNG_PURL = "pkg:rpm/almalinux/libpng@1.6.58-1.el8"
PNG_REF = hashlib.sha256(b"/lib64/libpng16.so.16.58.0").hexdigest()
AUDITWHEEL_SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {"tools": [{"name": "auditwheel", "version": "6.8.2"}]},
        "components": [
            {
                "type": "library",
                "bom-ref": f"{PNG_PURL}#{PNG_REF}",
                "name": "libpng",
                "version": "1.6.58-1.el8",
                "purl": PNG_PURL,
            }
        ],
    }
).encode()


def with_auditwheel_sbom(client: object, cache_dir: Path, episode: Path) -> list[Phase]:
    """The stub phases, with an auditwheel SBOM in demo's wheel."""
    stubs = stub_phases(client, cache_dir, episode)

    def resolve(package: Package, earlier: Mapping[str, Line]) -> Result:
        result = stubs[0].run(package, earlier)
        if package.name != "demo":
            return result
        sboms = {"demo-1.0.dist-info/sboms/auditwheel.cdx.json": AUDITWHEEL_SBOM}
        wheel = build_wheel(cache_dir / "demo.whl", sboms)
        sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
        return Result("ok", None, result.data | {"sha256": sha256})

    return [Phase("01-resolve", resolve), *stubs[1:]]


def test_sbom_report_is_rewritten_once_phase_09_is_finished(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_module, "phases", with_auditwheel_sbom)
    repo = make_repo(dirs.episode.parent / "libpng", {"v1.6.58": {}})
    png = f"libpng16,libpng,{repo},v{{version}},,single_line,library_string,"
    png += "libpng version {version},p.c,,none,"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    sboms_phase = scan_module.sboms_phase

    def interrupt(package: Package, earlier: Mapping[str, Line]) -> Result:
        handler = signal.getsignal(signal.SIGINT)
        assert callable(handler)
        handler(signal.SIGINT, None)
        return Result("ok", None, {"records": []})

    # Stopped in phase 09: the fingerprint report is written, the SBOM
    # report isn't.
    monkeypatch.setattr(
        scan_module, "sboms_phase", lambda: Phase("09-sboms", interrupt)
    )
    assert run(dirs, "--count", "3") == EXIT_INTERRUPTED
    fingerprints = (dirs.episode / "fingerprint-report.md").read_bytes()
    report = dirs.episode / "sbom-report.md"
    assert not report.exists()

    # Once phase 09 finishes, the SBOM report is written, and the
    # fingerprint report doesn't change.
    (dirs.episode / "09-sboms.jsonl.partial").unlink()
    monkeypatch.setattr(scan_module, "sboms_phase", sboms_phase)
    assert run(dirs, "--count", "3") == 0
    assert (dirs.episode / "fingerprint-report.md").read_bytes() == fingerprints
    text = report.read_text()
    assert "- Tied files that agree: 1 (library_string 1).\n" in text
    assert (
        f"| libpng16-1a2b3c4d.so.16.58.0 | libpng 1.6.58-1.el8 ({PNG_PURL}) | libpng "
        "| 1.6.58 | library_string |  | agrees |\n"
    ) in text
    assert "## puredemo 3.1\n\n`puredemo.whl`\n\nNo SBOM files.\n" in text
    assert "## missing 9.9\n\nerror at 01-resolve: HTTP 404\n" in text

    # A run where every phase was already finished rewrites it.
    report.write_text("stale")
    assert run(dirs, "--count", "3") == 0
    assert report.read_text() == text
    report.unlink()
    assert run(dirs, "--count", "3") == 0
    assert report.read_text() == text
    assert (dirs.episode / "fingerprint-report.md").read_bytes() == fingerprints


# The CVE table (roadmap 6.1).


def test_missing_cve_table_prints_full_help(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = dirs.argv("--count", "1")
    i = argv.index("--cve-table")
    del argv[i : i + 2]
    assert main(argv, client=RecordedClient()) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Required. CVE table, normally data/cves.toml." in captured.err
    assert "--episode-dir" in captured.err
    assert not dirs.episode.exists()


def test_bad_cve_table_fails_preflight(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    # The test map tracks no library, so no CVE can name one.
    dirs.cves.write_text('[[cve]]\nid = "CVE-2023-4863"\nlibrary = "libwebp"\n')
    assert run(dirs, "--count", "1") == 2
    err = capsys.readouterr().err
    assert f"{dirs.cves}: CVE-2023-4863 libwebp: published: missing" in err
    assert not dirs.episode.exists()
    dirs.cves.write_text("[[cve]\n")
    assert run(dirs, "--count", "1") == 2
    assert f"pypiscan scan: error: {dirs.cves}: " in capsys.readouterr().err
    assert not dirs.episode.exists()


def test_cve_table_is_checked_against_the_map(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    table = (Path(__file__).parent.parent / "data" / "cves.toml").read_text()
    dirs.cves.write_text(table)
    assert run(dirs, "--count", "1") == 2
    assert "library: 'libwebp' isn't a library the map tracks" in (
        capsys.readouterr().err
    )
    webp = "libwebp,libwebp,https://chromium.googlesource.com/webm/libwebp,v{version},,single_line"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{webp},,,,,none,\n")
    assert run(dirs, "--count", "1") == 2
    assert "library: 'libwebp' has cpe none in the library map" in (
        capsys.readouterr().err
    )
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{webp},,,,,webmproject:libwebp,\n")
    assert run(dirs, "--count", "1") == 0
    # The table isn't an episode input, so editing it needs no file deleted.
    assert "cve" not in (dirs.episode / "episode.json").read_text()


# Phase 10, candidate CVEs from NVD (roadmap 6.2).


def test_phase_10_runs_last_once_per_library(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    webp = "libwebp,libwebp,https://chromium.googlesource.com/webm/libwebp,v{version},,single_line"
    geos = "libgeos_c,geos,https://github.com/libgeos/geos,{version},,single_line"
    dirs.map.write_text(
        f"{','.join(COLUMNS)}\n{webp},,,,,webmproject:libwebp,\n{geos},,,,,none,\n"
    )
    query = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString="
        "cpe:2.3:a:webmproject:libwebp&resultsPerPage=2000&startIndex=0"
    )
    recorded = (Path(__file__).with_name("nvd") / "CVE-2023-4863.json").read_bytes()
    client = RecordedClient({query: recorded})
    assert main(dirs.argv("--count", "1"), client=client) == 0
    assert capsys.readouterr().err.endswith("10-cves: 1 ok, 1 skipped, 0 error\n")
    assert [url for url in client.requested if "nvd" in url] == [query]
    webp_line, geos_line = dirs.lines("10-cves")
    assert (webp_line["library"], webp_line["status"]) == ("libwebp", "ok")
    [found] = cast(list[Line], webp_line["candidates"])
    assert (found["id"], found["scope"]) == ("CVE-2023-4863", "in")
    assert geos_line == {
        "schema_version": 1,
        "library": "geos",
        "status": "skipped",
        "reason": "no_cpe",
        "cpe": [],
    }


def test_phase_10_waits_between_requests_across_libraries(dirs: Dirs) -> None:
    rows = [
        f"lib{name},{name},https://example.org/{name},v{{version}},,single_line,,,,,{name}:{name},"
        for name in ("a", "b")
    ]
    dirs.map.write_text("\n".join([",".join(COLUMNS), *rows]) + "\n")
    slept: list[float] = []
    status = scan(
        dirs.list,
        dirs.map,
        dirs.ambiguous,
        dirs.cves,
        dirs.line_eol,
        dirs.episode,
        dirs.cache,
        1,
        RecordedClient(),
        io.StringIO(),
        sleep=slept.append,
    )
    assert status == 0
    # The recorded client answers NVD's URLs with a wheel's bytes.
    assert [line["status"] for line in dirs.lines("10-cves")] == ["error", "error"]
    assert "response is not JSON" in str(dirs.lines("10-cves")[0]["reason"])
    assert slept == [6]


def test_stop_during_part_3_leaves_no_phase_10(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupting_sboms() -> Phase[Package]:
        def interrupt(package: Package, earlier: Mapping[str, Line]) -> Result:
            handler = signal.getsignal(signal.SIGINT)
            assert callable(handler)
            handler(signal.SIGINT, None)
            return Result("ok", None, {"wheel": "w", "records": []})

        return Phase("09-sboms", interrupt)

    monkeypatch.setattr(scan_module, "phases", stub_phases)
    monkeypatch.setattr(scan_module, "sboms_phase", interrupting_sboms)
    png = "libpng16,libpng,r,v{version},,single_line,,,,,png:png,"
    dirs.map.write_text(f"{','.join(COLUMNS)}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")
    assert run(dirs, "--count", "3") == EXIT_INTERRUPTED
    assert (dirs.episode / "09-sboms.jsonl.partial").is_file()
    assert not list(dirs.episode.glob("10-*"))


@pytest.mark.parametrize("value", ["9", "00", "11", "ab"])
def test_stop_after_takes_only_a_phase_number(
    dirs: Dirs, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        run(dirs, "--count", "3", "--stop-after", value)
    assert exc.value.code == 2
    assert "--stop-after: invalid choice" in capsys.readouterr().err
    assert not dirs.episode.exists()


def test_stop_after_a_part_1_phase_then_carry_on(
    dirs: Dirs, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(dirs, "--count", "3", "--stop-after", "02") == 0
    err = capsys.readouterr().err
    assert err.endswith("02-fetch: 1 ok, 2 skipped, 0 error\nstopped after 02-fetch\n")
    files = sorted(path.name for path in dirs.episode.iterdir())
    assert files == ["01-resolve.jsonl", "02-fetch.jsonl", "episode.json"]

    # Phase 02 is already finished: no phase runs.
    assert run(dirs, "--count", "3", "--stop-after", "02") == 0
    err = capsys.readouterr().err
    assert err.endswith("02-fetch: already finished, skipped\nstopped after 02-fetch\n")
    assert not (dirs.episode / "03-inspect.jsonl").exists()

    # --stop-after isn't in episode.json, so a run without it carries on.
    assert run(dirs, "--count", "3") == 0
    err = capsys.readouterr().err
    assert "03-inspect: 0 ok, 2 skipped, 1 error" in err
    assert "stopped" not in err
    assert err.endswith("10-cves: 0 ok, 0 skipped, 0 error\n")


def test_manual_step_before_stop_after_still_exits_3(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "phases", stub_phases)
    assert run(dirs, "--count", "3", "--stop-after", "09") == 3
    err = capsys.readouterr().err
    assert err.endswith("  libpng16\n  libgfortran\n")
    assert "stopped" not in err
    assert not list(dirs.episode.glob("06-*"))


def test_stop_after_writes_the_reports_finished_phases_allow(
    dirs: Dirs, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_module, "phases", stub_phases)
    repo = make_repo(dirs.episode.parent / "libpng", {"v1.6.58": {}})
    png = f"libpng16,libpng,{repo},v{{version}},,single_line,library_string,"
    png += "libpng version {version},p.c,,none,"
    header = ",".join(COLUMNS)
    dirs.map.write_text(f"{header}\n{png}\nlibgfortran,skip,,,,,,,,,,\n")

    assert run(dirs, "--count", "3", "--stop-after", "08") == 0
    err = capsys.readouterr().err
    assert err.endswith(
        "08-fingerprint: 2 ok, 1 skipped, 0 error\nstopped after 08-fingerprint\n"
    )
    assert (dirs.episode / "fingerprint-report.md").is_file()
    assert (dirs.episode / "staleness-report.md").is_file()
    assert not (dirs.episode / "sbom-report.md").exists()
    assert not list(dirs.episode.glob("09-*")) + list(dirs.episode.glob("10-*"))
    assert not list(dirs.episode.glob("*.partial"))

    # Phase 08 is already finished: no phase runs, and the reports are
    # rewritten.
    (dirs.episode / "staleness-report.md").unlink()
    assert run(dirs, "--count", "3", "--stop-after", "08") == 0
    err = capsys.readouterr().err
    assert err.endswith(
        "08-fingerprint: already finished, skipped\nstopped after 08-fingerprint\n"
    )
    assert (dirs.episode / "staleness-report.md").is_file()

    # Stopping after part 2's last phase or phase 10.
    (dirs.episode / "08-fingerprint.jsonl").unlink()
    assert run(dirs, "--count", "3", "--stop-after", "07") == 0
    assert capsys.readouterr().err.endswith(
        "07-recognizers: already finished, skipped\nstopped after 07-recognizers\n"
    )
    assert not (dirs.episode / "08-fingerprint.jsonl").exists()
    assert run(dirs, "--count", "3", "--stop-after", "10") == 0
    err = capsys.readouterr().err
    assert "09-sboms: 2 ok, 1 skipped, 0 error" in err
    assert err.endswith("10-cves: 0 ok, 1 skipped, 0 error\nstopped after 10-cves\n")
    assert (dirs.episode / "sbom-report.md").is_file()
