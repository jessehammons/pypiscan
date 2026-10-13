import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from pypiscan.detectors import DETECTORS
from pypiscan.fingerprint import fingerprint_wheel
from pypiscan.wheel_inspect import WheelError, inspect_wheel


def _emit(command: str, produce: Callable[[], Sequence[object]]) -> int:
    try:
        records = produce()
    except WheelError as exc:
        print(f"pypiscan {command}: error: {exc}", file=sys.stderr)
        return 1
    for record in records:
        print(json.dumps(record))
    return 0


def inspect(wheel: Path) -> int:
    return _emit("inspect", lambda: inspect_wheel(wheel))


def fingerprint(wheel: Path) -> int:
    return _emit("fingerprint", lambda: fingerprint_wheel(wheel, DETECTORS))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pypiscan")
    sub = parser.add_subparsers(dest="command", required=True)
    p_inspect = sub.add_parser(
        "inspect", help="List the ELF binaries in a wheel as JSON Lines."
    )
    p_inspect.add_argument("wheel", type=Path, help="Path to a .whl file.")
    p_fingerprint = sub.add_parser(
        "fingerprint",
        help="Identify bundled libraries and versions in a wheel as JSON Lines.",
    )
    p_fingerprint.add_argument("wheel", type=Path, help="Path to a .whl file.")
    args = parser.parse_args(argv)
    if args.command == "fingerprint":
        return fingerprint(args.wheel)
    return inspect(args.wheel)
