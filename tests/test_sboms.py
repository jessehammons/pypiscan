import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import cast

import pytest

from pypiscan import scan as scan_module
from pypiscan.cli import main
from pypiscan.package_list import Package
from pypiscan.scan import (
    ZIP_MEMBER_SIZE_LIMIT,
    Line,
    Stop,
    run_phases,
    sboms_phase,
)
from pypiscan.wheel_inspect import WheelError
from pypiscan.wheel_sboms import SCHEMA_VERSION, SbomRecord, is_sbom, sboms_wheel

WHEEL = "demo-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"
SBOMS = "demo-1.0.dist-info/sboms"


def build_wheel(path: Path, members: dict[str, bytes | object]) -> Path:
    """A wheel holding each member; a name ending in ``/`` is a directory
    entry, and a value that isn't bytes is written as JSON."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, value in members.items():
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            zf.writestr(zipfile.ZipInfo(name), data)
    return path


def read_one(tmp_path: Path, doc: bytes | object) -> SbomRecord:
    wheel = build_wheel(tmp_path / WHEEL, {f"{SBOMS}/x.json": doc})
    [record] = sboms_wheel(wheel)
    return record


def component(**fields: object) -> dict[str, object]:
    """A recorded component: the given fields, ``None`` for the others."""
    keys = ("bom-ref", "type", "name", "version", "purl", "scope")
    found = {key: fields.get(key.replace("-", "_")) for key in keys}
    return found | {"parent": fields.get("parent")}


# Shaped like auditwheel 6.7.0's SBOM in psycopg2-binary 2.9.13.
WHEEL_PURL = f"pkg:pypi/demo@1.0?file_name={WHEEL}"
KRB5 = "pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9"
AUDITWHEEL: dict[str, object] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "component": {
            "type": "library",
            "bom-ref": WHEEL_PURL,
            "name": "demo",
            "version": "1.0",
            "purl": WHEEL_PURL,
        },
        "tools": [{"name": "auditwheel", "version": "6.7.0"}],
    },
    "components": [
        {
            "type": "library",
            "bom-ref": WHEEL_PURL,
            "name": "demo",
            "version": "1.0",
            "purl": WHEEL_PURL,
        },
        {
            "type": "library",
            "bom-ref": f"{KRB5}#aaaa",
            "name": "krb5-libs",
            "version": "1.15.1-55.el7_9",
            "purl": KRB5,
        },
        {
            "type": "library",
            "bom-ref": f"{KRB5}#bbbb",
            "name": "krb5-libs",
            "version": "1.15.1-55.el7_9",
            "purl": KRB5,
        },
    ],
    "dependencies": [{"ref": WHEEL_PURL, "dependsOn": [f"{KRB5}#aaaa"]}],
}


def test_auditwheel_shaped_file(tmp_path: Path) -> None:
    record = read_one(tmp_path, AUDITWHEEL)
    data = json.dumps(AUDITWHEEL).encode()
    assert record == {
        "schema_version": SCHEMA_VERSION,
        "wheel": WHEEL,
        "path": f"{SBOMS}/x.json",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "format": "cyclonedx-json",
        "spec_version": "1.4",
        "tools": [{"name": "auditwheel", "version": "6.7.0"}],
        "components": [
            component(
                bom_ref=WHEEL_PURL,
                type="library",
                name="demo",
                version="1.0",
                purl=WHEEL_PURL,
            ),
            component(
                bom_ref=f"{KRB5}#aaaa",
                type="library",
                name="krb5-libs",
                version="1.15.1-55.el7_9",
                purl=KRB5,
            ),
            component(
                bom_ref=f"{KRB5}#bbbb",
                type="library",
                name="krb5-libs",
                version="1.15.1-55.el7_9",
                purl=KRB5,
            ),
        ],
        "subject": {
            "bom-ref": WHEEL_PURL,
            "type": "library",
            "name": "demo",
            "version": "1.0",
            "purl": WHEEL_PURL,
            "scope": None,
        },
        "error": None,
    }


def test_pillow_shaped_file(tmp_path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {
            "tools": {
                "components": [{"type": "application", "name": "generate-sbom.py"}]
            },
            "component": {"bom-ref": "pkg:pypi/pillow@12.3.0", "name": "Pillow"},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:generic/freetype2",
                "name": "FreeType",
                "version": "2.14.3",
                "scope": "optional",
            },
            {
                "type": "library",
                "bom-ref": "pkg:generic/zlib-ng",
                "name": "zlib",
                "version": "2.3.3",
                "pedigree": {
                    "ancestors": [{"type": "library", "name": "zlib-ng-ancestor"}]
                },
            },
        ],
    }
    record = read_one(tmp_path, doc)
    assert record["tools"] == [{"name": "generate-sbom.py", "version": None}]
    assert record["subject"] == {
        "bom-ref": "pkg:pypi/pillow@12.3.0",
        "type": None,
        "name": "Pillow",
        "version": None,
        "purl": None,
        "scope": None,
    }
    assert record["components"] == [
        component(
            bom_ref="pkg:generic/freetype2",
            type="library",
            name="FreeType",
            version="2.14.3",
            scope="optional",
        ),
        component(
            bom_ref="pkg:generic/zlib-ng", type="library", name="zlib", version="2.3.3"
        ),
    ]


def test_cargo_cyclonedx_shaped_file(tmp_path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": [
                {"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.9"}
            ]
        },
        "components": [
            {"name": "zstd-sys", "version": "2.0.16+zstd.1.5.7", "scope": "required"},
            {"name": "cc", "version": "1.2.0", "scope": "excluded"},
        ],
    }
    record = read_one(tmp_path, doc)
    assert record["tools"] == [{"name": "cargo-cyclonedx", "version": "0.5.9"}]
    assert record["components"] == [
        component(name="zstd-sys", version="2.0.16+zstd.1.5.7", scope="required"),
        component(name="cc", version="1.2.0", scope="excluded"),
    ]
    assert record["subject"] is None


def test_object_form_tools_lists_components_then_services(tmp_path: Path) -> None:
    tools = {
        "services": [{"name": "s", "version": "1"}],
        "components": [{"group": "g", "name": "c", "version": "2"}],
    }
    doc = {"bomFormat": "CycloneDX", "metadata": {"tools": tools}}
    record = read_one(tmp_path, doc)
    assert record["tools"] == [
        {"name": "c", "version": "2"},
        {"name": "s", "version": "1"},
    ]
    assert read_one(tmp_path, doc | {"metadata": {"tools": {}}})["tools"] == []


def test_no_tools_metadata_or_components(tmp_path: Path) -> None:
    record = read_one(tmp_path, {"bomFormat": "CycloneDX"})
    assert record["format"] == "cyclonedx-json"
    assert (record["spec_version"], record["tools"]) == (None, [])
    assert (record["components"], record["subject"]) == ([], None)
    assert record["error"] is None
    doc = {"bomFormat": "CycloneDX", "metadata": {"timestamp": "now"}}
    assert read_one(tmp_path, doc)["tools"] == []


def test_nested_components_are_flattened_in_pre_order(tmp_path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "name": "a",
                "components": [
                    {"name": "a1", "components": [{"name": "a1x"}]},
                    {"name": "a2"},
                ],
            },
            {"name": "b", "components": []},
            {"name": "c", "components": [{"name": "c1"}]},
        ],
    }
    found = read_one(tmp_path, doc)["components"]
    assert found is not None
    assert [(c["name"], c["parent"]) for c in found] == [
        ("a", None),
        ("a1", 0),
        ("a1x", 1),
        ("a2", 0),
        ("b", None),
        ("c", None),
        ("c1", 5),
    ]


def nested(depth: int) -> bytes:
    inner = '[{"name":"n","components":' * depth + "[]" + "}]" * depth
    return ('{"bomFormat":"CycloneDX","components":' + inner + "}").encode()


def test_deep_nesting_is_flattened_without_recursion(tmp_path: Path) -> None:
    # Deeper than Python's default recursion limit, which json still parses.
    found = read_one(tmp_path, nested(1500))["components"]
    assert found is not None
    assert len(found) == 1500
    assert [c["parent"] for c in found] == [None, *range(1499)]


def test_nesting_json_rejects_is_not_json(tmp_path: Path) -> None:
    record = read_one(tmp_path, nested(100_000))
    assert (record["format"], record["error"]) == ("other", "not_json")
    assert record["components"] is None


@pytest.mark.parametrize(
    ("doc", "kind", "error"),
    [
        ({"spdxVersion": "SPDX-2.3", "packages": []}, "spdx-json", None),
        ({"bomFormat": "CycloneDX", "spdxVersion": "SPDX-2.3"}, "cyclonedx-json", None),
        ({"bomFormat": "cyclonedx", "components": []}, "other", None),
        ({}, "other", None),
        ([{"bomFormat": "CycloneDX"}], "other", None),
        (
            b'<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/"/>',
            "other",
            "not_json",
        ),
        (b'{"bomFormat": "CycloneDX", "name": "\xff"}', "other", "not_json"),
    ],
)
def test_format_comes_from_content(
    tmp_path: Path, doc: object, kind: str, error: str | None
) -> None:
    record = read_one(tmp_path, doc)
    assert (record["format"], record["error"]) == (kind, error)
    if kind != "cyclonedx-json":
        assert record["spec_version"] is None
        assert (record["tools"], record["components"], record["subject"]) == (
            None,
            None,
            None,
        )


@pytest.mark.parametrize(
    ("doc", "path"),
    [
        ({"specVersion": 1.4}, "specVersion"),
        ({"metadata": []}, "metadata"),
        ({"components": {"name": "a"}}, "components"),
        ({"components": [{"name": "a"}, "b"]}, "components[1]"),
        ({"components": [{}, {}, {}, {"version": 2}]}, "components[3].version"),
        ({"components": [{"purl": None}]}, "components[0].purl"),
        ({"metadata": {"tools": "auditwheel"}}, "metadata.tools"),
        ({"metadata": {"tools": [{"name": 1}]}}, "metadata.tools[0].name"),
        ({"metadata": {"tools": {"components": [1]}}}, "metadata.tools.components[0]"),
        ({"metadata": {"tools": {"services": {}}}}, "metadata.tools.services"),
        ({"metadata": {"component": []}}, "metadata.component"),
        ({"metadata": {"component": {"scope": 0}}}, "metadata.component.scope"),
        (
            {"components": [{}, {"components": {"name": "x"}}]},
            "components[1].components",
        ),
        (
            {"components": [{}, {"components": [{"name": ["x"]}]}]},
            "components[1].components[0].name",
        ),
    ],
)
def test_wrong_type_reads_nothing(
    tmp_path: Path, doc: dict[str, object], path: str
) -> None:
    good = {"specVersion": "1.5", "metadata": {"tools": [{"name": "t"}]}}
    record = read_one(tmp_path, {"bomFormat": "CycloneDX"} | good | doc)
    assert record["format"] == "cyclonedx-json"
    assert record["error"] == f"wrong_type: {path}"
    assert (record["tools"], record["components"], record["subject"]) == (
        None,
        None,
        None,
    )


def test_fields_that_arent_read_arent_checked(tmp_path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "version": "one",
        "components": [{"name": "a", "licenses": 7, "pedigree": [1], "hashes": "x"}],
        "dependencies": 3,
    }
    record = read_one(tmp_path, doc)
    assert record["error"] is None
    assert record["components"] == [component(name="a")]


@pytest.mark.parametrize(
    ("path", "found"),
    [
        (f"{SBOMS}/auditwheel.cdx.json", True),
        (f"{SBOMS}/sub/dir/x.spdx.json", True),
        ("demo/sboms/x.json", False),
        ("demo-1.0.dist-info/sbomsx/y.json", False),
        ("a/demo-1.0.dist-info/sboms/y.json", False),
        ("demo-1.0.dist-info/x.json", False),
        ("sboms/x.json", False),
    ],
)
def test_is_sbom(path: str, found: bool) -> None:
    assert is_sbom(path) == found


def test_records_follow_archive_order_and_skip_directories(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / WHEEL,
        {
            f"{SBOMS}/": b"",
            f"{SBOMS}/b.json": {},
            "demo/sboms/x.json": {},
            f"{SBOMS}/sub/": b"",
            f"{SBOMS}/sub/a.txt": b"not json",
            "demo-1.0.dist-info/sbomsx/y.json": {},
            "a/demo-1.0.dist-info/sboms/y.json": {},
        },
    )
    records = sboms_wheel(wheel)
    assert [(r["path"], r["format"], r["error"]) for r in records] == [
        (f"{SBOMS}/b.json", "other", None),
        (f"{SBOMS}/sub/a.txt", "other", "not_json"),
    ]


def test_member_over_the_size_limit_isnt_read(tmp_path: Path) -> None:
    data = json.dumps(AUDITWHEEL).encode()
    wheel = build_wheel(tmp_path / WHEEL, {f"{SBOMS}/x.json": data})
    [record] = sboms_wheel(wheel, len(data) - 1)
    assert record == {
        "schema_version": SCHEMA_VERSION,
        "wheel": WHEEL,
        "path": f"{SBOMS}/x.json",
        "size": len(data),
        "sha256": None,
        "format": None,
        "spec_version": None,
        "tools": None,
        "components": None,
        "subject": None,
        "error": "too_large",
    }
    [record] = sboms_wheel(wheel, len(data))
    assert record["error"] is None


def test_unreadable_wheel_raises(tmp_path: Path) -> None:
    with pytest.raises(WheelError, match="no such file"):
        sboms_wheel(tmp_path / "missing.whl")
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip")
    with pytest.raises(WheelError, match="not a valid zip file"):
        sboms_wheel(bogus)
    garbled = build_wheel(tmp_path / "garbled.whl", {f"{SBOMS}/x.json": b"x" * 4096})
    data = bytearray(garbled.read_bytes())
    start = data.index(b"x.json") + len(b"x.json")
    data[start : start + 16] = b"\xff" * 16
    garbled.write_bytes(bytes(data))
    with pytest.raises(WheelError, match="not a valid zip file"):
        sboms_wheel(garbled)


def test_cli_prints_one_line_per_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = build_wheel(
        tmp_path / WHEEL, {f"{SBOMS}/a.json": AUDITWHEEL, f"{SBOMS}/b.json": {}}
    )
    assert main(["sbom", str(wheel)]) == 0
    out, err = capsys.readouterr()
    assert [json.loads(line) for line in out.splitlines()] == sboms_wheel(wheel)
    assert len(out.splitlines()) == 2
    assert err == ""

    empty = build_wheel(tmp_path / "empty.whl", {"demo/__init__.py": b""})
    assert main(["sbom", str(empty)]) == 0
    assert capsys.readouterr() == ("", "")


def test_cli_error_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip")
    assert main(["sbom", str(bogus)]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("pypiscan sbom: error: ")


# Phase 09.

PART_1 = ["01-resolve", "02-fetch", "03-inspect", "04-strings", "05-libraries"]
FINISHED = [*PART_1, "08-fingerprint"]


def write_lines(path: Path, lines: list[Line]) -> None:
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def episode(tmp_path: Path, wheels: dict[str, Path | None]) -> Path:
    """An episode with phases 01 to 05 and 08 finished, one package per wheel; a
    package with no wheel is skipped at 02-fetch as too large."""
    ep = tmp_path / "episode"
    ep.mkdir()
    for phase in FINISHED:
        lines: list[Line] = []
        for name, wheel in wheels.items():
            line: Line = {"name": name, "status": "ok", "reason": None}
            if wheel is None and phase != "01-resolve":
                reason = "too_large" if phase == "02-fetch" else "02-fetch"
                line |= {"status": "skipped", "reason": reason}
            elif phase == "01-resolve":
                line["sha256"] = "0" * 64 if wheel is None else sha256(wheel)
            elif phase == "02-fetch":
                line["path"] = str(wheel)
            lines.append(line)
        write_lines(ep / f"{phase}.jsonl", lines)
    return ep


def run_09(
    ep: Path, names: list[str], limit: int = ZIP_MEMBER_SIZE_LIMIT
) -> tuple[list[Line], str]:
    err = io.StringIO()
    packages = [Package(name, "1.0") for name in names]
    phase = sboms_phase(limit)
    status = run_phases(ep, packages, [phase], Stop(), err, finished=FINISHED)
    assert status == 0
    text = (ep / "09-sboms.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()], err.getvalue()


def test_phase_09(tmp_path: Path) -> None:
    sbom = build_wheel(tmp_path / WHEEL, {f"{SBOMS}/auditwheel.cdx.json": AUDITWHEEL})
    plain = build_wheel(tmp_path / "plain-1.0-py3-none-any.whl", {"p/x.py": b""})
    missing = build_wheel(tmp_path / "gone-1.0-py3-none-any.whl", {"g/x.py": b""})
    changed = build_wheel(tmp_path / "changed-1.0-py3-none-any.whl", {"c/x.py": b""})
    wheels = {
        "sbom": sbom,
        "plain": plain,
        "big": None,
        "gone": missing,
        "changed": changed,
    }
    ep = episode(tmp_path, wheels)
    missing.unlink()
    changed.write_bytes(changed.read_bytes() + b"\0")

    lines, err = run_09(ep, list(wheels))
    assert err == "09-sboms: 2 ok, 1 skipped, 2 error\n"
    assert [line["name"] for line in lines] == list(wheels)
    sbom_line, plain_line, big, gone, changed_line = lines
    assert sbom_line["status"] == "ok"
    assert sbom_line["wheel"] == WHEEL
    assert sbom_line["records"] == sboms_wheel(sbom)
    [record] = cast(list[Line], sbom_line["records"])
    assert record["path"] == f"{SBOMS}/auditwheel.cdx.json"
    assert (plain_line["status"], plain_line["records"]) == ("ok", [])
    assert (big["status"], big["reason"]) == ("skipped", "02-fetch")
    assert gone["status"] == "error"
    assert gone["reason"] == f"wheel {missing} is missing"
    assert changed_line["status"] == "error"
    assert changed_line["reason"] == f"wheel {changed}'s sha256 differs from phase 01's"


def test_phase_09_unreadable_wheel_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bogus = tmp_path / "bogus.whl"
    bogus.write_bytes(b"not a zip")
    lines, _ = run_09(episode(tmp_path, {"bogus": bogus}), ["bogus"])
    assert lines[0]["status"] == "error"
    assert "not a valid zip file" in str(lines[0]["reason"])

    def unreadable(path: Path) -> str:
        raise PermissionError(f"{path}: permission denied")

    monkeypatch.setattr(scan_module, "_sha256", unreadable)
    (tmp_path / "episode" / "09-sboms.jsonl").unlink()
    lines, _ = run_09(tmp_path / "episode", ["bogus"])
    assert (lines[0]["status"], lines[0]["reason"]) == (
        "error",
        f"{bogus}: permission denied",
    )


def test_phase_09_reads_members_up_to_the_zip_member_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[int | None] = []

    def spy(wheel: Path, max_member_size: int | None = None) -> list[SbomRecord]:
        seen.append(max_member_size)
        return []

    monkeypatch.setattr(scan_module, "sboms_wheel", spy)
    wheel = build_wheel(tmp_path / WHEEL, {})
    run_09(episode(tmp_path, {"demo": wheel}), ["demo"])
    assert seen == [ZIP_MEMBER_SIZE_LIMIT]
    (tmp_path / "raised").mkdir()
    run_09(episode(tmp_path / "raised", {"demo": wheel}), ["demo"], 3)
    assert seen == [ZIP_MEMBER_SIZE_LIMIT, 3]
