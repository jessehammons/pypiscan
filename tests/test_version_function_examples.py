"""Check every version function row in the committed library map against
real code.

``version_function_examples.tsv`` holds, for each such row, the function's
bytes from a real wheel, from its first byte through ``ret``, and for a
string the string it points to, with the version they must give. Rows with
an empty library and version hold real code that must give nothing.
"""

import csv
from pathlib import Path

import pytest

from pypiscan.library_map import (
    VERSION_FUNCTION,
    MapRow,
    load_library_map,
    parse_version_function,
)
from pypiscan.library_report import prefix
from pypiscan.version_function import Returned, shape, version

ROOT = Path(__file__).parent.parent
FIELDS = [
    "prefix",
    "library",
    "function",
    "code",
    "string",
    "version",
    "wheel",
    "member",
]


def load_examples() -> list[dict[str, str]]:
    path = Path(__file__).parent / "version_function_examples.tsv"
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE)
        assert reader.fieldnames == FIELDS
        return list(reader)


ROWS = [
    r
    for r in load_library_map(ROOT / "data/libraries.csv")
    if r.kind == VERSION_FUNCTION
]
EXAMPLES = load_examples()
MATCHES = [e for e in EXAMPLES if e["version"]]
NON_MATCHES = [e for e in EXAMPLES if not e["version"]]


def row_id(row: MapRow) -> str:
    return f"{row.prefix}-{row.library}"


def example_id(example: dict[str, str]) -> str:
    return f"{example['prefix']}-{example['function']}"


def decoded(row: MapRow, example: dict[str, str]) -> str | None:
    returned = shape(bytes.fromhex(example["code"]))
    if returned is None:
        return None
    result = version(returned, parse_version_function(row.pattern), example["string"])
    return None if result is None else result[1]


@pytest.mark.parametrize("row", ROWS, ids=row_id)
def test_every_version_function_row_has_an_example(row: MapRow) -> None:
    function = parse_version_function(row.pattern).function
    assert [
        e
        for e in MATCHES
        if (e["prefix"], e["library"], e["function"])
        == (row.prefix, row.library, function)
    ]


@pytest.mark.parametrize("example", MATCHES, ids=example_id)
def test_example_gives_its_version(example: dict[str, str]) -> None:
    [row] = [
        r
        for r in ROWS
        if (r.prefix, r.library) == (example["prefix"], example["library"])
        and parse_version_function(r.pattern).function == example["function"]
    ]
    assert decoded(row, example) == example["version"]
    # The code is the whole function: nothing follows its ret.
    code = bytes.fromhex(example["code"])
    assert shape(code[:-1]) is None
    # A string example holds its string, and only a string example does.
    returned = shape(code)
    assert returned is not None
    assert bool(example["string"]) == (returned.shape == "string")


@pytest.mark.parametrize("example", NON_MATCHES, ids=example_id)
def test_non_match_gives_nothing(example: dict[str, str]) -> None:
    assert example["library"] == example["string"] == ""
    assert shape(bytes.fromhex(example["code"])) is None
    assert bytes.fromhex(example["code"]).endswith(b"\xc3")


@pytest.mark.parametrize("example", EXAMPLES, ids=example_id)
def test_example_comes_from_its_prefix(example: dict[str, str]) -> None:
    assert example["wheel"].endswith(".whl")
    assert ".libs/" in example["member"]
    assert prefix(example["member"]) == example["prefix"]


def test_libwebp_demux_and_mux_rows_start_at_1_0_0() -> None:
    """Before libwebp 1.0.0, WebPGetDemuxVersion and WebPGetMuxVersion
    returned the demux and mux libraries' own versions (0.3.3 and 0.4.1 in
    libwebp 0.6.1), so their rows hold only from 0x10000."""
    rows = [r for r in ROWS if r.prefix in ("libwebpdemux", "libwebpmux")]
    assert len(rows) == 2
    for row in rows:
        function = parse_version_function(row.pattern)
        assert function.minimum == 0x10000
        for old in (0x000303, 0x000401, 0x00FFFF):
            assert version(Returned("integer", (old,)), function) is None
        assert version(Returned("integer", (0x10600,)), function) == (
            "0x10600",
            "1.6.0",
        )
