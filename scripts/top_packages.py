"""Write data/packages.csv, the full package list (README roadmap 3.6).

Downloads a top-pypi-packages snapshot, walks it in rank order with
``pypiscan.top_packages.select_packages`` and writes the first 100 projects
whose latest final release has a target wheel. The snapshot isn't
committed; the script prints its date and sha256 for data/README.md, with
the rank it stopped at and the projects it passed over. It needs the
network, so it runs outside pytest:

    uv run python scripts/top_packages.py
"""

import argparse
import csv
import sys
from pathlib import Path

from pypiscan.package_list import COLUMNS
from pypiscan.pypi import UrllibClient
from pypiscan.top_packages import read_snapshot, select_packages

SNAPSHOT_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
OUTPUT = Path(__file__).resolve().parent.parent / "data" / "packages.csv"


def main() -> int:
    parser = argparse.ArgumentParser(description="Write data/packages.csv.")
    parser.add_argument("--url", default=SNAPSHOT_URL, help="snapshot URL")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    client = UrllibClient()
    snapshot = read_snapshot(b"".join(client.stream(args.url)))
    selection = select_packages(snapshot.names, client)

    with args.output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(COLUMNS)
        writer.writerows((p.name, p.version) for p in selection.packages)

    print(f"snapshot: {args.url}")
    print(f"last_update: {snapshot.last_update}")
    print(f"sha256: {snapshot.sha256}")
    print(f"selected: {len(selection.packages)} -> {args.output}")
    print(f"stopped at rank: {selection.stop_rank}")
    print(f"passed over, no target: {len(selection.no_target)}")
    print(f"passed over, no final release: {len(selection.no_release)}")
    for name in selection.no_release:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
