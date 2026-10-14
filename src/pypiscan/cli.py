import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from pypiscan.detectors import DETECTORS
from pypiscan.fetch import fetch_release
from pypiscan.fingerprint import fingerprint_wheel
from pypiscan.package_list import check_release
from pypiscan.pypi import HttpClient, PyPIError, UrllibClient
from pypiscan.scan import EXIT_PREFLIGHT, scan
from pypiscan.wheel_inspect import WheelError, inspect_wheel


def _emit(command: str, produce: Callable[[], Sequence[object]]) -> int:
    try:
        records = produce()
    except (WheelError, PyPIError) as exc:
        print(f"pypiscan {command}: error: {exc}", file=sys.stderr)
        return 1
    for record in records:
        print(json.dumps(record))
    return 0


def inspect(wheel: Path) -> int:
    return _emit("inspect", lambda: inspect_wheel(wheel))


def fingerprint(wheel: Path) -> int:
    return _emit("fingerprint", lambda: fingerprint_wheel(wheel, DETECTORS))


def fetch(release: tuple[str, str], cache_dir: Path, client: HttpClient) -> int:
    name, version = release
    return _emit("fetch", lambda: [fetch_release(client, name, version, cache_dir)])


def _release(spec: str) -> tuple[str, str]:
    name, sep, version = spec.partition("==")
    try:
        check_release(name, version)
    except ValueError:
        sep = ""
    if not sep:
        raise argparse.ArgumentTypeError(f"expected <name>==<version>, got {spec!r}")
    return name, version


def main(argv: Sequence[str] | None = None, client: HttpClient | None = None) -> int:
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
    p_fetch = sub.add_parser(
        "fetch",
        help="Download a release's target wheel into the cache, verify its "
        "sha256, and print a JSON Lines record.",
    )
    p_fetch.add_argument("release", type=_release, help="<name>==<version>")
    p_fetch.add_argument(
        "--cache-dir", type=Path, required=True, help="Directory for cached wheels."
    )
    p_scan = sub.add_parser(
        "scan",
        help="Run the first N packages of a package list through the scan's "
        "phases, writing results into an episode directory.",
    )
    p_scan.add_argument("package_list", type=Path, help="Package list CSV file.")
    p_scan.add_argument(
        "--episode-dir", type=Path, required=True, help="Directory for this run."
    )
    p_scan.add_argument(
        "--cache-dir", type=Path, required=True, help="Directory for cached wheels."
    )
    # Required, but checked after parsing so a missing --count prints the full
    # help rather than argparse's usage line.
    p_scan.add_argument(
        "--count",
        type=int,
        help="Required. Scan the first N packages (clamped to the list's length).",
    )
    args = parser.parse_args(argv)
    if args.command == "scan":
        if args.count is None:
            p_scan.print_help(sys.stderr)
            return EXIT_PREFLIGHT
        if args.count < 1:
            p_scan.error("--count must be at least 1")
        return scan(
            args.package_list,
            args.episode_dir,
            args.cache_dir,
            args.count,
            client or UrllibClient(),
            sys.stderr,
        )
    if args.command == "fetch":
        return fetch(args.release, args.cache_dir, client or UrllibClient())
    if args.command == "fingerprint":
        return fingerprint(args.wheel)
    return inspect(args.wheel)
