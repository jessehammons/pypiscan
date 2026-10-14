import io
import json
import signal
from collections.abc import Iterator
from pathlib import Path

import pytest

from pypiscan import scan as scan_module
from pypiscan.cli import main
from pypiscan.package_list import Package
from pypiscan.scan import (
    EXIT_INTERRUPTED,
    TARGET,
    WHEEL_SIZE_LIMIT,
    ZIP_MEMBER_SIZE_LIMIT,
    Line,
    Phase,
    Result,
    Stop,
    fetch_phase,
    git_work_tree,
    inspect_phase,
    run_phases,
    scan,
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
        self.episode = tmp_path / "episode"
        self.cache = tmp_path / "cache"

    def argv(self, *extra: str) -> list[str]:
        return [
            "scan",
            str(self.list),
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
    def go(package: Package, previous: Line | None) -> Result:
        return Result(status, reason, {"seen": previous is not None})

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
    assert [json.loads(s)["seen"] for s in lines] == [True, True]


def test_stop_between_packages(tmp_path: Path) -> None:
    stop = Stop()

    def go(package: Package, previous: Line | None) -> Result:
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
        dirs.list, dirs.episode, dirs.cache, 3, Interrupting(), io.StringIO(), stop
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

    def go(package: Package, previous: Line | None) -> Result:
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

    def go(package: Package, previous: Line | None) -> Result:
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
    result = phase.run(Package("foo", "1"), previous)
    assert result == Result("skipped", "too_large")
    assert client.requested == []
    assert not (tmp_path / "wheels").exists()


def test_phase_02_at_the_limit_downloads(tmp_path: Path) -> None:
    phase = fetch_phase(RecordedClient(), tmp_path)
    previous = resolved_line(size=WHEEL_SIZE_LIMIT)
    # The limit itself isn't "over the limit"; the download attempt proceeds
    # and the recorded body's sha256 won't match, so phase 02 records an
    # error rather than a too_large skip.
    result = phase.run(Package("foo", "1"), previous)
    assert result.status == "error"
    assert "does not match" in (result.reason or "")


def test_phase_02_download_error(tmp_path: Path) -> None:
    client = RecordedClient({"https://files.example/foo.whl": b"wrong"})
    phase = fetch_phase(client, tmp_path)
    previous = resolved_line(size=5)
    result = phase.run(Package("foo", "1"), previous)
    assert result.status == "error"
    assert "does not match" in (result.reason or "")


def test_phase_02_is_skipped_when_phase_01_skipped(dirs: Dirs) -> None:
    # Smoke the chained-skip behaviour by driving a two-phase run_phases
    # with phase 01 returning skipped and no_target, then phase 02 fails if
    # it runs. puredemo never produces a WheelFile.
    err = io.StringIO()
    status = scan(dirs.list, dirs.episode, dirs.cache, 2, RecordedClient(), err)
    assert status == 0
    [demo, pure] = dirs.lines("02-fetch")
    assert pure["status"] == "skipped" and pure["reason"] == "01-resolve"
    assert demo["status"] == "ok"


def inspect_previous(path: Path) -> Line:
    return {"status": "ok", "path": str(path)}


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
    def phase_01(_: Package, _p: Line | None) -> Result:
        return Result("ok", None, {"size": 1})

    def phase_02(_: Package, _p: Line | None) -> Result:
        return Result("skipped", "too_large")

    def phase_03_fail(_: Package, _p: Line | None) -> Result:
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
