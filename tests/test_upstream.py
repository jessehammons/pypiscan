"""The zlib detector against its cited strings at every upstream release tag.

Fixtures come from ``scripts/upstream_fixtures.py`` (README roadmap 2.2).
"""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest
from dulwich.objects import Blob, Commit, ObjectID, Tag, Tree
from dulwich.refs import Ref
from dulwich.repo import Repo

from elf_builder import build_elf
from pypiscan.detectors import DETECTORS
from pypiscan.fingerprint import Citation, fingerprint_binary

UPSTREAM = Path(__file__).parent / "upstream"
SCRIPT = Path(__file__).parent.parent / "scripts" / "upstream_fixtures.py"

# Tags whose own strings name a different version than the tag: upstream
# pre-releases whose strings already carry the final version. The detector
# reports what the binary says.
STRING_DIFFERS_FROM_TAG = {
    ("zlib", "v0.99"): "1.0",
    ("zlib", "v1.0-pre"): "1.0",
    ("zlib", "v1.2.4-pre1"): "1.2.4",
    ("zlib", "v1.2.4-pre2"): "1.2.4",
    ("zlib-ng", "1.9.9-b1"): "1.9.9",
}
# zlib 0.71-0.95 (1995) define no cited string: their only banner is named
# ``copyright`` and carries no version, so they have no fixture rows.
UNCOVERED_TAGS = {
    ("zlib", f"v0.{n}") for n in ("71", "79", "8", "9", "91", "92", "93", "94", "95")
}


def load(library: str) -> dict[str, list[tuple[str, str]]]:
    lines = (UPSTREAM / f"{library}.tsv").read_text(encoding="ascii").splitlines()
    assert lines[0] == "tag\tlocation\tstring"
    by_tag: dict[str, list[tuple[str, str]]] = {}
    for line in lines[1:]:
        tag, location, string = line.split("\t")
        by_tag.setdefault(tag, []).append((location, string))
    return by_tag


def is_header(location: str) -> bool:
    return re.search(r"\.h(?:\.in)?:", location) is not None


def same_version(tag: str, version: str) -> bool:
    """``2.1.0-beta1`` and ``2.1.0.beta1`` spell the same version."""
    return tag.removeprefix("v").replace("-", ".") == version.replace("-", ".")


def binary(strings: list[str]) -> bytes:
    return build_elf(None, rodata=b"\0" + b"\0".join(s.encode() for s in strings))


CASES = [
    (library, tag, rows)
    for library in ("zlib", "zlib-ng")
    for tag, rows in load(library).items()
]


def test_fixtures_cover_every_tag() -> None:
    zlib, zlib_ng = load("zlib"), load("zlib-ng")
    assert len(zlib) == 78 - len(UNCOVERED_TAGS)
    assert {"v0.99", "v1.0.1", "v1.2.3.4", "v1.3.1.2", "v1.3.2"} <= set(zlib)
    assert len(zlib_ng) == 31
    assert {"1.9.9-b1", "v2.0.0-RC1", "2.0.7", "2.1.0-beta1", "2.3.3"} <= set(zlib_ng)
    # The derivative's tags never leak into the original's fixture, or back.
    assert not set(zlib) & set(zlib_ng)


@pytest.mark.parametrize(
    ("library", "tag", "rows"), CASES, ids=[f"{c[0]}@{c[1]}" for c in CASES]
)
def test_detector_reports_tag(
    library: str, tag: str, rows: list[tuple[str, str]]
) -> None:
    records = fingerprint_binary(
        DETECTORS, "x.whl", "lib.so", binary([s for _, s in rows])
    )

    assert [(r["library"], r["relation"], r["conflict"]) for r in records] == [
        (library, "contains", False)
    ]
    version = records[0]["version"]
    assert version is not None
    expected = STRING_DIFFERS_FROM_TAG.get((library, tag))
    if expected is None:
        assert same_version(tag, version)
    else:
        assert version == expected


@pytest.mark.parametrize(
    ("library", "tag", "rows"), CASES, ids=[f"{c[0]}@{c[1]}" for c in CASES]
)
def test_every_string_matches_alone(
    library: str, tag: str, rows: list[tuple[str, str]]
) -> None:
    """Each cited string is matched whole by a pattern of its own, so one
    pattern's miss can't hide behind another's match."""
    for _, string in rows:
        records = fingerprint_binary(DETECTORS, "x.whl", "lib.so", binary([string]))
        texts = [e["text"] for r in records for e in r["evidence"]]
        assert texts == [string]


@pytest.mark.parametrize(("tag", "rows"), load("zlib-ng").items())
def test_zlib_ng_header_alone_is_compiled_against(
    tag: str, rows: list[tuple[str, str]]
) -> None:
    (header,) = [s for loc, s in rows if is_header(loc)]
    records = fingerprint_binary(DETECTORS, "x.whl", "lib.so", binary([header]))

    assert [(r["library"], r["relation"], r["version"]) for r in records] == [
        ("zlib-ng", "compiled_against", header)
    ]


def test_exceptions_match_the_fixtures() -> None:
    """Every listed exception is a real tag, and its strings say so."""
    fixtures = {lib: load(lib) for lib in ("zlib", "zlib-ng")}
    for (library, tag), version in STRING_DIFFERS_FROM_TAG.items():
        rows = fixtures[library][tag]
        assert any(f" {version} " in s for _, s in rows)
        assert not same_version(tag, version)
    for library, tag in UNCOVERED_TAGS:
        assert tag not in fixtures[library]


REPO_FIXTURE = {"madler/zlib": "zlib", "zlib-ng/zlib-ng": "zlib-ng"}


def test_citations_match_the_fixtures() -> None:
    """Each citation names the file and line where the fixture found the
    string at that tag, and its pattern matches that string."""
    cited = 0
    for detector in DETECTORS:
        for pattern in detector.patterns:
            assert not isinstance(pattern.source, str)
            for c in pattern.source:
                rows = dict(load(REPO_FIXTURE[c.repo])[c.tag])
                string = rows[f"{c.file}:{c.line}"]
                assert pattern.regex.search(b"\0" + string.encode() + b"\0"), c
                cited += 1
    assert cited == 11


def test_citation_reads_as_file_line_at_tag() -> None:
    c = Citation("madler/zlib", "v1.3.2", "deflate.c", 55, "deflate_copyright")

    assert str(c) == "madler/zlib deflate.c:55 @ v1.3.2 (deflate_copyright)"


# The generating script, against a synthetic repository built in tmp_path.


@pytest.fixture(scope="module")
def script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("upstream_fixtures", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_repo(path: Path, tags: dict[str, dict[str, str]]) -> Repo:
    """One commit per tag, in order; annotated tags for names with '-'."""
    repo = Repo.init(str(path), mkdir=True)
    parent: list[ObjectID] = []
    for n, (name, files) in enumerate(tags.items()):
        tree = Tree()
        for file, text in files.items():
            blob = Blob.from_string(text.encode())
            repo.object_store.add_object(blob)
            tree.add(file.encode(), 0o100644, blob.id)
        repo.object_store.add_object(tree)
        commit = Commit()
        commit.tree, commit.parents = tree.id, parent
        commit.author = commit.committer = b"t <t@example.com>"
        commit.commit_time = commit.author_time = 1_000_000 + n
        commit.commit_timezone = commit.author_timezone = 0
        commit.message = name.encode()
        repo.object_store.add_object(commit)
        parent = [commit.id]
        target = commit.id
        if "-" in name:
            tag = Tag()
            tag.name, tag.object = name.encode(), (Commit, commit.id)
            tag.tagger, tag.tag_time, tag.tag_timezone = commit.author, 0, 0
            tag.message = b"release"
            repo.object_store.add_object(tag)
            target = tag.id
        repo.refs[Ref(b"refs/tags/" + name.encode())] = target
    return repo


ZUTIL = 'x;\nconst char PREFIX3(vstring)[] =\n    " zlib-ng " /* c */ "2.3.3";\n'
HEADER = '#define ZLIB_VERSION "1.3.1.zlib-ng" // compat\n#define X 1\n'


def test_script_extracts_what_the_citations_name(script: ModuleType) -> None:
    sources = script.cited_sources("zlib-ng/zlib-ng", DETECTORS)

    assert [(s.file, s.symbol, s.is_define) for s in sources] == [
        ("deflate.c", "deflate_copyright", False),
        ("inftrees.c", "inflate_copyright", False),
        ("zutil.c", "vstring", False),
        ("zutil.c", "zlibng_string", False),
        ("zlib.h.in", "ZLIB_VERSION", True),
        ("zlib.h", "ZLIB_VERSION", True),
    ]


def test_script_writes_rows_per_tag(script: ModuleType, tmp_path: Path) -> None:
    make_repo(
        tmp_path / "repo",
        {
            "2.0.0-rc1": {"zutil.c": ZUTIL.replace("2.3.3", "2.0.0"), "zlib.h": HEADER},
            "v1.2.11": {"zutil.c": ZUTIL},  # a zlib tag: not selected
            "2.3.3": {"zutil.c": ZUTIL, "zlib.h.in": HEADER, "zlib.h": "stale"},
        },
    )
    out = tmp_path / "out"
    out.mkdir()

    assert (
        script.main(
            ["zlib-ng", "--repo", str(tmp_path / "repo"), "--out-dir", str(out)]
        )
        == 0
    )
    assert (out / "zlib-ng.tsv").read_text().splitlines() == [
        "tag\tlocation\tstring",
        "2.0.0-rc1\tzutil.c:3\t zlib-ng 2.0.0",
        "2.0.0-rc1\tzlib.h:1\t1.3.1.zlib-ng",
        "2.3.3\tzutil.c:3\t zlib-ng 2.3.3",
        "2.3.3\tzlib.h.in:1\t1.3.1.zlib-ng",
    ]


@pytest.mark.parametrize(
    "zutil",
    [
        'const char PREFIX3(vstring)[] = " zlib-ng " PREFIX2(VERSION);\n',
        'const char PREFIX3(vstring)[] = " zlib-ng 2.3.3\\n";\n',
        "const char PREFIX3(vstring)[] = 0;\n",
        'const char PREFIX3(vstring)[] = "a";\nconst char PREFIX3(vstring)[] = "b";',
        'const char PREFIX3(vstring)[] = " zlib-ng 2.3.3"',
    ],
    ids=["macro", "escape", "no-literal", "twice", "unterminated"],
)
def test_script_refuses_what_needs_cpp(
    script: ModuleType,
    tmp_path: Path,
    zutil: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    make_repo(tmp_path / "repo", {"2.3.3": {"zutil.c": zutil}})

    code = script.main(
        ["zlib-ng", "--repo", str(tmp_path / "repo"), "--out-dir", str(tmp_path)]
    )

    assert code == 1
    assert capsys.readouterr().err.startswith("upstream_fixtures: error: 2.3.3:zutil.c")
