import hashlib
import json
import zipfile
from pathlib import Path
from typing import cast

import pytest

from elf_builder import build_elf
from pypiscan.cli import main
from pypiscan.wheel_summary import SCHEMA_VERSION, platform_tags
from test_static import DEFLATE, INFLATE

ROOT = Path(__file__).parent.parent
MAP = str(ROOT / "data/libraries.csv")
WHEEL = "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
KRB5 = "pkg:rpm/centos/krb5-libs@1.15.1-55.el7_9"
SASL = "pkg:rpm/centos/cyrus-sasl-lib@2.1.26-24.el7_9"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def component(name: str, purl: str, path: str) -> dict[str, object]:
    return {
        "type": "library",
        "bom-ref": f"{purl}#{digest(path)}",
        "name": name,
        "version": purl.rpartition("@")[2],
        "purl": purl,
    }


SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "metadata": {"tools": [{"name": "auditwheel", "version": "6.7.0"}]},
    "components": [
        component("krb5-libs", KRB5, "/lib64/libkrb5.so.3.3"),
        # Names a file the wheel doesn't carry.
        component("cyrus-sasl-lib", SASL, "/lib64/libsasl2.so.3"),
    ],
}


def build(tmp_path: Path, members: dict[str, bytes]) -> Path:
    path = tmp_path / WHEEL
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(["wheel", *args])
    out, err = capsys.readouterr()
    return code, out, err


def test_platform_tags() -> None:
    assert platform_tags(WHEEL) == ["manylinux_2_17_x86_64", "manylinux2014_x86_64"]
    assert platform_tags("demo-1.0-1-py3-none-any.whl") == ["any"]
    assert platform_tags("demo.zip") == platform_tags("demo-1.0.whl") == []


def test_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lib = build_elf(None)
    ext = build_elf(None, rodata=b"\0" + DEFLATE + INFLATE)
    wheel = build(
        tmp_path,
        {
            "demo.libs/libkrb5-fcafa220.so.3.3": lib,
            "demo.libs/libfoo-0a1b2c3d.so.1": lib,
            "demo/_ext.cpython-312-x86_64-linux-gnu.so": ext,
            "demo/_plain.so": build_elf(None),
            "demo-1.0.dist-info/sboms/auditwheel.cdx.json": json.dumps(SBOM).encode(),
        },
    )
    code, out, err = run(capsys, str(wheel), "--library-map", MAP)
    assert (code, err) == (0, "")
    records = [json.loads(line) for line in out.splitlines()]
    assert all(r["schema_version"] == SCHEMA_VERSION for r in records)
    by_kind: dict[str, list[dict[str, object]]] = {}
    for r in records:
        by_kind.setdefault(r.pop("kind"), []).append(r)
    [head] = by_kind["wheel"]
    assert head["filename"] == WHEEL
    assert head["sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert head["platform_tags"] == ["manylinux_2_17_x86_64", "manylinux2014_x86_64"]
    assert [(r["path"], r["prefix"], r["libraries"]) for r in by_kind["library"]] == [
        ("demo.libs/libkrb5-fcafa220.so.3.3", "libkrb5", ["krb5"]),
        ("demo.libs/libfoo-0a1b2c3d.so.1", "libfoo", []),
    ]
    [sbom] = by_kind["sbom"]
    assert cast(dict[str, object], sbom["sbom"])["path"] == (
        "demo-1.0.dist-info/sboms/auditwheel.cdx.json"
    )
    [untied] = by_kind["untied_component"]
    assert cast(dict[str, object], untied["component"])["name"] == "cyrus-sasl-lib"
    assert by_kind["untied_file"] == [
        {"schema_version": SCHEMA_VERSION, "path": "demo.libs/libfoo-0a1b2c3d.so.1"}
    ]
    [static] = by_kind["static"]
    assert static["path"] == "demo/_ext.cpython-312-x86_64-linux-gnu.so"
    found = cast(list[dict[str, object]], static["candidates"])
    assert [(c["library"], c["version"]) for c in found] == [("zlib", "1.3.2")] * 2
    [record] = cast(list[dict[str, object]], static["fingerprints"])
    assert (record["library"], record["linkage"]) == ("zlib", "static_lib")


def test_no_auditwheel_sbom_gives_no_untied_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = build(tmp_path, {"demo.libs/libfoo-0a1b2c3d.so.1": build_elf(None)})
    code, out, _ = run(capsys, str(wheel), "--library-map", MAP)
    kinds = [json.loads(line)["kind"] for line in out.splitlines()]
    assert (code, kinds) == (0, ["wheel", "library"])


def test_a_phase_error_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = tmp_path / WHEEL
    wheel.write_bytes(b"not a zip")
    code, out, err = run(capsys, str(wheel), "--library-map", MAP)
    assert (code, out) == (1, "")
    assert err.startswith("pypiscan wheel: error: 03-inspect: error: ")


@pytest.mark.parametrize("which", ["wheel", "map"])
def test_a_missing_file_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], which: str
) -> None:
    wheel = build(tmp_path, {})
    missing = str(tmp_path / "missing")
    args = [missing, "--library-map", MAP]
    if which == "map":
        args = [str(wheel), "--library-map", missing]
    code, out, err = run(capsys, *args)
    assert (code, out) == (1, "")
    assert err.startswith("pypiscan wheel: error: ")
