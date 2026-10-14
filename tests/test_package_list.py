from pathlib import Path

import pytest

from pypiscan.package_list import (
    MAX_PACKAGES,
    Package,
    PackageListError,
    load_package_list,
)

SMOKE = Path(__file__).parents[1] / "data" / "smoke.csv"


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "packages.csv"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_rows_in_order(tmp_path: Path) -> None:
    path = write(tmp_path, "name,version\nPillow,12.3.0\n\nlxml,6.1.3\n")
    assert load_package_list(path) == [
        Package("Pillow", "12.3.0"),
        Package("lxml", "6.1.3"),
    ]


def test_accepts_max_packages(tmp_path: Path) -> None:
    rows = "".join(f"pkg{i},1.0\n" for i in range(MAX_PACKAGES))
    assert len(load_package_list(write(tmp_path, "name,version\n" + rows))) == 100


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "header must be name,version, got None"),
        ("version,name\nlxml,6.1.3\n", "header must be name,version"),
        ("name,version,extra\nlxml,6.1.3,x\n", "header must be name,version"),
        ("name,version\n", "no packages"),
        ("name,version\n\n", "no packages"),
        ("name,version\nlxml\n", ":2: expected a name and a version"),
        ("name,version\nlxml,\n", ":2: expected a name and a version"),
        ("name,version\n,6.1.3\n", ":2: expected a name and a version"),
        ("name,version\nlxml,6.1.3,x\n", ":2: expected a name and a version"),
        ("name,version\nlxml>=6,6.1.3\n", ":2: name is invalid"),
        ("name,version\n lxml,6.1.3\n", ":2: name is invalid"),
        ("name,version\nlxml,x!y\n", ":2: Invalid version"),
        (
            "name,version\nPillow,12.3.0\nlxml,6.1.3\npillow,12.2.0\n",
            ":4: 'pillow' is the same package as line 2",
        ),
        (
            "name,version\nzope.interface,8.0\nZope_Interface,8.0\n",
            ":3: 'Zope_Interface' is the same package as line 2",
        ),
        (
            "name,version\n"
            + "".join(f"pkg{i},1.0\n" for i in range(MAX_PACKAGES + 1)),
            "more than 100 packages",
        ),
        ('name,version\n"lxml,6.1.3\n', ":2: expected a name and a version"),
        ("name,version\nlxml," + "1" * 200_000 + "\n", "field larger than"),
    ],
)
def test_rejects_bad_lists(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(PackageListError, match=message):
        load_package_list(write(tmp_path, text))


def test_rejects_unreadable_files(tmp_path: Path) -> None:
    with pytest.raises(PackageListError, match="No such file"):
        load_package_list(tmp_path / "missing.csv")
    path = tmp_path / "latin1.csv"
    path.write_bytes(b"name,version\ncaf\xe9,1.0\n")
    with pytest.raises(PackageListError, match="can't decode"):
        load_package_list(path)


def test_smoke_list_loads() -> None:
    packages = load_package_list(SMOKE)
    assert 4 <= len(packages) <= 10
    assert [p.name for p in packages[:4]] == ["pillow", "lxml", "requests", "torch"]
