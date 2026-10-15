"""Write tests/upstream/<library>.tsv from a library's upstream git repository.

The strings to extract come from the detectors' citations
(``pypiscan.fingerprint.Citation``): every symbol a pattern cites in the
library's repository. At every release tag, the script reads each cited
symbol's C literal straight from the source file and writes one row per tag
and string: the tag, ``file:line`` of the literal, and the string. The
fixtures are committed; tests check the detector against every row (README
roadmap 2.2).

The script clones the repository into a temporary directory outside the
working tree, so it needs the network and runs outside pytest:

    uv run python scripts/upstream_fixtures.py zlib
    uv run python scripts/upstream_fixtures.py zlib-ng

``--repo PATH`` reads an existing clone instead.
"""

import argparse
import re
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pypiscan.detectors import DETECTORS
from pypiscan.fingerprint import Detector
from pypiscan.git import GitError, clone_or_fetch, git, tags

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "upstream"


class ExtractError(Exception):
    pass


@dataclass(frozen=True)
class Source:
    """One cited symbol: a C variable whose initializer is the string, or,
    for header strings, a ``#define``."""

    file: str
    symbol: str
    is_define: bool

    @property
    def intro(self) -> re.Pattern[str]:
        """The text that introduces the literal: ``#define SYMBOL``, or a
        declaration up to ``=``, allowing zlib-ng's ``PREFIX3(symbol)``."""
        if self.is_define:
            return re.compile(rf"#[ \t]*define[ \t]+{self.symbol}\b")
        return re.compile(rf"\b(?:PREFIX[0-9]?\()?{self.symbol}\)?\[\]\s*=")


@dataclass(frozen=True)
class Library:
    repo: str  # GitHub owner/name, as in Citation.repo
    tags: re.Pattern[str]  # full match selects the library's release tags


LIBRARIES = {
    # madler/zlib tags only releases.
    "zlib": Library("madler/zlib", re.compile(r"v[0-9].*")),
    # zlib-ng/zlib-ng also carries madler/zlib's tags and the jtkv tags of
    # the fork it started from; its own releases are 1.9.9-b1 and 2.x.
    "zlib-ng": Library(
        "zlib-ng/zlib-ng",
        re.compile(r"1\.9\.9-b1|v?2\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+)?"),
    ),
}


def cited_sources(repo: str, detectors: Iterable[Detector]) -> list[Source]:
    """Every symbol the detectors cite in ``repo``, in citation order."""
    found: dict[tuple[str, str], Source] = {}
    for detector in detectors:
        for pattern in detector.patterns:
            if isinstance(pattern.source, str):
                continue
            for c in pattern.source:
                if c.repo == repo:
                    is_define = pattern.kind == "header_string"
                    found.setdefault(
                        (c.file, c.symbol), Source(c.file, c.symbol, is_define)
                    )
    return list(found.values())


_TOKEN = re.compile(
    r"""(?P<space>[ \t\r]+|/\*.*?\*/|//[^\n]*)
      | (?P<newline>\n)
      | "(?P<literal>[^"\\\n]*)"
      | (?P<end>;)""",
    re.VERBOSE | re.DOTALL,
)


def extract(text: str, source: Source) -> tuple[int, str] | None:
    """Return ``(line, string)`` for the literal ``source`` introduces in
    ``text``, or ``None`` if the file doesn't define it.

    Adjacent literals are concatenated. A string assembled from macros, or one
    with escapes, raises ``ExtractError``: it would need the preprocessor.
    """
    found = list(source.intro.finditer(text))
    if not found:
        return None
    if len(found) > 1:
        raise ExtractError(f"{source.intro.pattern!r} matches {len(found)} times")
    pos, line, parts = found[0].end(), None, list[str]()
    while True:
        m = _TOKEN.match(text, pos)
        if m is None or (m["newline"] and source.is_define):
            break
        pos = m.end()
        if m["end"]:
            break
        if m["literal"] is not None:
            if line is None:
                line = text.count("\n", 0, m.start()) + 1
            parts.append(m["literal"])
    if m is None and not (source.is_define and pos == len(text)):
        snippet = text[pos : pos + 40].split("\n")[0]
        raise ExtractError(f"not a plain C literal at {snippet!r}: needs cpp")
    if line is None:
        raise ExtractError(f"{source.intro.pattern!r} has no string literal")
    return line, "".join(parts)


def _read(repo: Path, commit: str, path: str) -> str | None:
    listed = git("-C", str(repo), "ls-tree", commit, "--", path).split()
    if not listed:
        return None
    if listed[1] != "blob":
        raise ExtractError(f"{path} is not a file")
    return git("-C", str(repo), "cat-file", "blob", listed[2], encoding="latin-1")


def _commit(repo: Path, tag: str) -> tuple[int, str]:
    """The commit time and id of the commit ``tag`` points at."""
    try:
        out = git("-C", str(repo), "log", "-1", "--format=%ct %H", f"{tag}^{{commit}}")
    except GitError:
        raise ExtractError(f"tag {tag} does not point at a commit") from None
    time, commit = out.split()
    return int(time), commit


def rows(
    repo: Path, tag_pattern: re.Pattern[str], sources: list[Source]
) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Return ``(tag, file:line, string)`` rows for every release tag, oldest
    tagged commit first, and the selected tags where no source was found."""
    selected = [
        (*_commit(repo, tag), tag) for tag in tags(repo) if tag_pattern.fullmatch(tag)
    ]
    found: list[tuple[str, str, str]] = []
    empty: list[str] = []
    for _, commit, tag in sorted(selected, key=lambda t: (t[0], t[2])):
        before = len(found)
        for source in sources:
            text = _read(repo, commit, source.file)
            if text is None:
                continue
            try:
                result = extract(text, source)
            except ExtractError as e:
                raise ExtractError(f"{tag}:{source.file}: {e}") from None
            if result is not None:
                line, string = result
                found.append((tag, f"{source.file}:{line}", string))
        if len(found) == before:
            empty.append(tag)
    return found, empty


def write_fixture(repo: Path, name: str, out_dir: Path) -> None:
    library = LIBRARIES[name]
    found, empty = rows(repo, library.tags, cited_sources(library.repo, DETECTORS))
    out = out_dir / f"{name}.tsv"
    lines = ["tag\tlocation\tstring", *("\t".join(row) for row in found)]
    out.write_text("\n".join(lines) + "\n", encoding="ascii")
    count = len({tag for tag, _, _ in found})
    print(f"{name}: {count} tags, {len(found)} rows -> {out}", file=sys.stderr)
    if empty:
        print(f"{name}: no cited string at: {' '.join(empty)}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("library", choices=sorted(LIBRARIES))
    parser.add_argument("--repo", type=Path, help="read this clone; don't clone")
    parser.add_argument("--out-dir", type=Path, default=FIXTURES)
    args = parser.parse_args(argv)
    try:
        if args.repo is not None:
            write_fixture(args.repo, args.library, args.out_dir)
        else:
            url = f"https://github.com/{LIBRARIES[args.library].repo}"
            with tempfile.TemporaryDirectory(prefix="upstream-fixtures-") as tmp:
                print(f"cloning {url} into {tmp}", file=sys.stderr)
                repo = Path(tmp) / "repo.git"
                clone_or_fetch(url, repo)
                write_fixture(repo, args.library, args.out_dir)
    except (ExtractError, GitError) as e:
        print(f"upstream_fixtures: error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
