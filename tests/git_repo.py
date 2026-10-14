"""Build synthetic git repositories for tests, with the git command."""

from pathlib import Path

from pypiscan.git import git


def make_repo(path: Path, tags: dict[str, dict[str, str]]) -> Path:
    """One commit per tag, in order, holding only that tag's files.

    Names with ``-`` get annotated tags; commit times count up from
    1,000,000 so the commits sort in order.
    """
    git("init", "--quiet", "--initial-branch=main", str(path))
    user = ("-c", "user.name=t", "-c", "user.email=t@example.com")
    for n, (name, files) in enumerate(tags.items()):
        date = f"@{1_000_000 + n} +0000"
        env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        git("-C", str(path), "rm", "-rq", "--ignore-unmatch", ".")
        for file, text in files.items():
            (path / file).write_text(text)
        git("-C", str(path), "add", ".")
        git("-C", str(path), *user, "commit", "-qm", name, "--allow-empty", env=env)
        annotate = ("-a", "-m", "release") if "-" in name else ()
        git("-C", str(path), *user, "tag", *annotate, name, env=env)
    return path
