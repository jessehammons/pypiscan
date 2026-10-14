"""Run the git command: the one module that does.

See README "Conventions". git runs by the absolute path ``shutil.which``
returns, with an argument list and never a shell, so this module alone
ignores ruff's S603. Each upstream repository is a bare, blobless clone; a
later run fetches into it with explicit refspecs, since a bare clone has
none.
"""

import os
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

REFSPECS = ("+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
# git's own options that take a value, ahead of the command.
_OPTIONS = ("-C", "-c", "--git-dir")


class GitError(Exception):
    """git isn't installed, or a git command failed."""


def git(
    *args: str,
    env: Mapping[str, str] | None = None,
    encoding: str = "utf-8",
) -> str:
    """Run ``git args`` and return its output; raise ``GitError`` if it fails.

    git never prompts for credentials: a repository that needs them fails.
    """
    executable = shutil.which("git")
    if executable is None:
        raise GitError("git is not installed")
    result = subprocess.run(
        [executable, *args],
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})},
        capture_output=True,
        encoding=encoding,
        check=False,
    )
    if result.returncode != 0:
        i = 0
        while i < len(args) - 1 and args[i] in _OPTIONS:
            i += 2
        lines = result.stderr.strip().splitlines() or [f"exit {result.returncode}"]
        raise GitError(f"git {args[i]} failed: {lines[-1]}")
    return result.stdout


def clone_or_fetch(repo: str, directory: Path) -> str:
    """Clone ``repo`` into ``directory``, or fetch into an existing clone.

    Returns ``"clone"`` or ``"fetch"``. An existing clone of another URL is
    an error that names the directory to delete.
    """
    if not directory.exists():
        git("clone", "--bare", "--filter=blob:none", "--quiet", repo, str(directory))
        return "clone"
    try:
        url = git("--git-dir", str(directory), "config", "remote.origin.url").strip()
    except GitError as exc:
        raise GitError(f"{directory} isn't a clone ({exc}); delete it") from exc
    if url != repo:
        raise GitError(f"{directory} is a clone of {url}, not {repo}; delete it")
    git("--git-dir", str(directory), "fetch", "--quiet", "origin", *REFSPECS)
    return "fetch"


def tags(directory: Path) -> list[str]:
    """Every tag in the repository at ``directory``, sorted by name."""
    return git("-C", str(directory), "tag", "--list").splitlines()
