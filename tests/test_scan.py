import io
import json
import signal
from collections.abc import Iterator
from pathlib import Path

import pytest

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
    git_work_tree,
    run_phases,
    scan,
)
from test_fetch import RecordedClient

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


def test_scan_runs_phase_01(dirs: Dirs, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(dirs, "--count", "3") == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "01-resolve: 1 ok, 1 skipped, 1 error" in captured.err
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
    assert dirs.cache.is_dir()
    assert not (dirs.cache / "wheels").exists()


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
