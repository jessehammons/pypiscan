"""Write data/packages.csv, the full package list (README roadmap 3.6).

Downloads a top-pypi-packages snapshot, or reads one with ``--snapshot``,
walks it in rank order with ``pypiscan.top_packages.select_packages`` and
writes the first MAX_PACKAGES (500) projects whose latest final release has
a target wheel. The snapshot isn't committed; the script prints its date and
sha256 for data/README.md, with the rank it stopped at. Beside the output it
writes ``<stem>-no-target.csv``: every project passed over, with its reason
(roadmap C.7), and it prints the counts by reason. It needs the network, so
it runs outside pytest:

    uv run python scripts/top_packages.py
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

from pypiscan.package_list import COLUMNS
from pypiscan.pypi import HttpClient, UrllibClient
from pypiscan.top_packages import (
    NO_FINAL_RELEASE,
    NO_TARGET_REASONS,
    read_snapshot,
    select_packages,
)

SNAPSHOT_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
OUTPUT = Path(__file__).resolve().parent.parent / "data" / "packages.csv"
REASON_COLUMNS = ("rank", "name", "version", "reason")


def main(argv: list[str] | None = None, client: HttpClient | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write data/packages.csv.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--url", default=SNAPSHOT_URL, help="snapshot URL")
    source.add_argument("--snapshot", type=Path, help="local snapshot file")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    client = client or UrllibClient()
    if args.snapshot is not None:
        body = args.snapshot.read_bytes()
    else:
        body = b"".join(client.stream(args.url))
    snapshot = read_snapshot(body)
    selection = select_packages(snapshot.names, client)

    with args.output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(COLUMNS)
        writer.writerows((p.name, p.version) for p in selection.packages)

    reasons_path = args.output.with_name(f"{args.output.stem}-no-target.csv")
    passed_over = sorted(
        selection.no_target + selection.no_release, key=lambda p: p.rank
    )
    with reasons_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(REASON_COLUMNS)
        writer.writerows((p.rank, p.name, p.version, p.reason) for p in passed_over)

    counts = Counter(p.reason for p in selection.no_target)
    total = sum(counts[reason] for reason in NO_TARGET_REASONS)
    print(f"snapshot: {args.snapshot if args.snapshot is not None else args.url}")
    print(f"last_update: {snapshot.last_update}")
    print(f"sha256: {snapshot.sha256}")
    print(f"selected: {len(selection.packages)} -> {args.output}")
    print(f"stopped at rank: {selection.stop_rank}")
    print(f"passed over, no target: {len(selection.no_target)}")
    for reason in NO_TARGET_REASONS:
        print(f"  {reason}: {counts[reason]}")
    print(f"  sum of reasons: {total}")
    print(f"passed over, {NO_FINAL_RELEASE}: {len(selection.no_release)}")
    for entry in selection.no_release:
        print(f"  {entry.name}")
    print(f"reasons: {reasons_path}")
    if total != len(selection.no_target):
        print("error: reasons don't sum to the no-target total", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
