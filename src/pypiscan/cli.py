import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pypiscan.wheel_inspect import WheelError, inspect_wheel


def inspect(wheel: Path) -> int:
    try:
        records = inspect_wheel(wheel)
    except WheelError as exc:
        print(f"pypiscan inspect: error: {exc}", file=sys.stderr)
        return 1
    for record in records:
        print(json.dumps(record))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pypiscan")
    sub = parser.add_subparsers(dest="command", required=True)
    p_inspect = sub.add_parser(
        "inspect", help="List the ELF binaries in a wheel as JSON Lines."
    )
    p_inspect.add_argument("wheel", type=Path, help="Path to a .whl file.")
    args = parser.parse_args(argv)
    return inspect(args.wheel)
