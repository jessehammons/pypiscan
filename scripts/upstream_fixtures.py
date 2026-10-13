"""Write tests/upstream/<library>.tsv from a library's upstream git repository.

At every release tag, read each string the library's detector patterns cite
straight from its C literal, and write one row per tag and string: the tag,
``file:line`` of the literal, and the string. The fixtures are committed;
tests check the detector against every row (README roadmap 2.2).

The script reads a local clone, so cloning is the only step that needs the
network, and it runs outside pytest:

    git clone https://github.com/madler/zlib /tmp/zlib
    uv run python scripts/upstream_fixtures.py zlib /tmp/zlib

    git clone https://github.com/zlib-ng/zlib-ng /tmp/zlib-ng
    uv run python scripts/upstream_fixtures.py zlib-ng /tmp/zlib-ng
"""

import argparse
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from dulwich.object_store import tree_lookup_path
from dulwich.objects import Blob, Commit
from dulwich.refs import Ref
from dulwich.repo import Repo

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "upstream"


class ExtractError(Exception):
    pass


@dataclass(frozen=True)
class Source:
    """One cited string: the files that may define it, first match wins, and
    a regex for the text that introduces it (a declaration up to ``=``, or
    ``#define NAME``)."""

    paths: tuple[str, ...]
    intro: re.Pattern[str]

    @property
    def is_define(self) -> bool:
        return self.intro.pattern.startswith("#")


@dataclass(frozen=True)
class Library:
    tags: re.Pattern[str]  # full match selects the library's release tags
    sources: tuple[Source, ...]


def _decl(name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{name}\)?\[\]\s*=")


LIBRARIES = {
    # madler/zlib tags only releases. Before v0.99 the variable was named
    # ``copyright`` and inftrees.c defined no banner.
    "zlib": Library(
        tags=re.compile(r"v[0-9].*"),
        sources=(
            Source(("deflate.c",), _decl("(?:deflate_)?copyright")),
            Source(("inftrees.c",), _decl("inflate_copyright")),
        ),
    ),
    # zlib-ng/zlib-ng also carries madler/zlib's tags and the jtkv tags of
    # the fork it started from; its own releases are 1.9.9-b1 and 2.x.
    "zlib-ng": Library(
        tags=re.compile(r"1\.9\.9-b1|v?2\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+)?"),
        sources=(
            Source(("zutil.c",), _decl(r"(?:zlibng_string|PREFIX3\(vstring)")),
            Source(("deflate.c",), _decl("deflate_copyright")),
            Source(("inftrees.c",), _decl("inflate_copyright")),
            Source(
                ("zlib.h.in", "zlib.h"),
                re.compile(r"#[ \t]*define[ \t]+ZLIB_VERSION\b"),
            ),
        ),
    ),
}

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


def _read(repo: Repo, commit: Commit, path: str) -> str | None:
    try:
        _, sha = tree_lookup_path(repo.__getitem__, commit.tree, path.encode())
    except KeyError:
        return None
    blob = repo[sha]
    if not isinstance(blob, Blob):
        raise ExtractError(f"{path} is not a file")
    return blob.data.decode("latin-1")


def rows(repo_dir: Path, library: Library) -> Iterator[tuple[str, str, str]]:
    """Yield ``(tag, file:line, string)`` for every release tag, oldest
    tagged commit first."""
    repo = Repo(str(repo_dir))
    tags: list[tuple[int, str, Commit]] = []
    for ref in repo.refs.keys(base=Ref(b"refs/tags")):
        if library.tags.fullmatch(tag := ref.decode()):
            commit = repo[repo.get_peeled(Ref(b"refs/tags/" + ref))]
            if not isinstance(commit, Commit):
                raise ExtractError(f"tag {tag} does not point at a commit")
            tags.append((commit.commit_time, tag, commit))
    for _, tag, commit in sorted(tags, key=lambda t: t[:2]):
        for source in library.sources:
            for path in source.paths:
                text = _read(repo, commit, path)
                if text is None:
                    continue
                try:
                    result = extract(text, source)
                except ExtractError as e:
                    raise ExtractError(f"{tag}:{path}: {e}") from None
                if result is not None:
                    line, string = result
                    yield tag, f"{path}:{line}", string
                break


def write_tsv(out: Path, data: Iterator[tuple[str, str, str]]) -> int:
    lines = ["tag\tlocation\tstring"]
    lines += ["\t".join(row) for row in data]
    out.write_text("\n".join(lines) + "\n", encoding="ascii")
    return len(lines) - 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("library", choices=sorted(LIBRARIES))
    parser.add_argument("repo", type=Path, help="local clone of the upstream repo")
    parser.add_argument("--out-dir", type=Path, default=FIXTURES)
    args = parser.parse_args(argv)
    out = args.out_dir / f"{args.library}.tsv"
    try:
        count = write_tsv(out, rows(args.repo, LIBRARIES[args.library]))
    except ExtractError as e:
        print(f"upstream_fixtures: error: {e}", file=sys.stderr)
        return 1
    print(f"wrote {count} rows to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
