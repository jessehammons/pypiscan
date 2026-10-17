"""Check every recognizer in the committed library map against real strings.

``recognizer_examples.tsv`` holds strings from the full run's episode
(roadmap 3.8): for each recognizer row of a string kind, strings it must
match and the version it must give, and strings no recognizer under their
prefix may match, with an empty library, kind and version. Version function
rows read code, not strings; ``version_function_examples.tsv`` covers them.
"""

import csv
from pathlib import Path

import pytest

from pypiscan.library_map import VERSION_FUNCTION, MapRow, load_library_map, matcher
from pypiscan.library_report import prefix
from pypiscan.noise import usable
from pypiscan.wheel_strings import VERSION_TOKEN, StringRecord, template

ROOT = Path(__file__).parent.parent
FIELDS = ["prefix", "library", "kind", "version", "string", "wheel", "member"]


def load_examples() -> list[dict[str, str]]:
    path = Path(__file__).parent / "recognizer_examples.tsv"
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE)
        assert reader.fieldnames == FIELDS
        return list(reader)


RECOGNIZERS = [
    r
    for r in load_library_map(ROOT / "data/libraries.csv")
    if r.kind and r.kind != VERSION_FUNCTION
]
EXAMPLES = load_examples()
MATCHES = [e for e in EXAMPLES if e["version"]]
NON_MATCHES = [e for e in EXAMPLES if not e["version"]]


def version(row: MapRow, text: str) -> str | None:
    match = matcher(row.pattern, row.kind).fullmatch(text)
    return match.group(1) if match else None


def row_id(row: MapRow) -> str:
    return f"{row.prefix}-{row.library}-{row.kind}"


def example_id(example: dict[str, str]) -> str:
    return f"{example['prefix']}-{example['string'][:40]}"


@pytest.mark.parametrize("row", RECOGNIZERS, ids=row_id)
def test_every_recognizer_row_has_an_example(row: MapRow) -> None:
    assert any(
        (e["prefix"], e["library"], e["kind"]) == (row.prefix, row.library, row.kind)
        and version(row, e["string"]) == e["version"]
        for e in MATCHES
    )


@pytest.mark.parametrize("example", MATCHES, ids=example_id)
def test_example_gives_its_version(example: dict[str, str]) -> None:
    rows = [r for r in RECOGNIZERS if r.prefix == example["prefix"]]
    own = [
        r for r in rows if (r.library, r.kind) == (example["library"], example["kind"])
    ]
    assert any(version(r, example["string"]) == example["version"] for r in own)
    # No other recognizer under the prefix reads it differently.
    assert {version(r, example["string"]) for r in rows} <= {None, example["version"]}


@pytest.mark.parametrize("example", NON_MATCHES, ids=example_id)
def test_non_match_matches_no_recognizer(example: dict[str, str]) -> None:
    assert example["library"] == example["kind"] == ""
    rows = [r for r in RECOGNIZERS if r.prefix == example["prefix"]]
    assert rows
    assert all(version(r, example["string"]) is None for r in rows)


@pytest.mark.parametrize("example", EXAMPLES, ids=example_id)
def test_example_comes_from_its_prefix(example: dict[str, str]) -> None:
    assert example["wheel"].endswith(".whl")
    assert ".libs/" in example["member"]
    assert prefix(example["member"]) == example["prefix"]


@pytest.mark.parametrize("example", MATCHES, ids=example_id)
def test_phase_04_lists_the_example(example: dict[str, str]) -> None:
    """Phase 08 sees only strings phase 04 lists, with a dotted version
    token, that pass the noise filter; a recognizer whose string phase 04
    wouldn't list could never match."""
    text = example["string"]
    assert VERSION_TOKEN.search(text.encode("ascii"))
    record: StringRecord = {
        "offset": 0,
        "section": ".rodata",
        "text": text,
        "template": template(text),
    }
    assert usable(record)
