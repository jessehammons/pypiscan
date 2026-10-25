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
from pypiscan.scan import EXIT_PREFLIGHT, PHASE_NUMBERS, scan
from pypiscan.wheel_inspect import WheelError, inspect_wheel
from pypiscan.wheel_sboms import sboms_wheel
from pypiscan.wheel_strings import strings_wheel


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


def strings(wheel: Path) -> int:
    return _emit("strings", lambda: strings_wheel(wheel))


def sbom(wheel: Path) -> int:
    return _emit("sbom", lambda: sboms_wheel(wheel))


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
    p_strings = sub.add_parser(
        "strings",
        help="List the version-like strings in a wheel's ELF binaries as JSON Lines.",
    )
    p_strings.add_argument("wheel", type=Path, help="Path to a .whl file.")
    p_sbom = sub.add_parser(
        "sbom",
        help="List the SBOM files in a wheel's .dist-info/sboms/ directory, "
        "with their CycloneDX components, as JSON Lines.",
    )
    p_sbom.add_argument("wheel", type=Path, help="Path to a .whl file.")
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
        "--library-map",
        type=Path,
        required=True,
        help="Library map CSV file, normally data/libraries.csv.",
    )
    # Required, but checked after parsing, like --count.
    p_scan.add_argument(
        "--ambiguous-versions",
        type=Path,
        help="Required. List of ambiguous versions, normally "
        "data/ambiguous_versions.csv.",
    )
    # Required, but checked after parsing, like --count.
    p_scan.add_argument(
        "--cve-table",
        type=Path,
        help="Required. CVE table, normally data/cves.toml.",
    )
    # Required, but checked after parsing, like --count.
    p_scan.add_argument(
        "--line-eol",
        type=Path,
        help="Required. Lines' ends of life, normally data/line_eol.csv.",
    )
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
    p_scan.add_argument(
        "--stop-after",
        choices=PHASE_NUMBERS,
        metavar="NN",
        help="Stop once phase NN (01 to 10) is finished, with exit 0.",
    )
    args = parser.parse_args(argv)
    if args.command == "scan":
        if None in (args.count, args.ambiguous_versions, args.cve_table, args.line_eol):
            p_scan.print_help(sys.stderr)
            return EXIT_PREFLIGHT
        if args.count < 1:
            p_scan.error("--count must be at least 1")
        return scan(
            args.package_list,
            args.library_map,
            args.ambiguous_versions,
            args.cve_table,
            args.line_eol,
            args.episode_dir,
            args.cache_dir,
            args.count,
            client or UrllibClient(),
            sys.stderr,
            stop_after=args.stop_after,
        )
    if args.command == "fetch":
        return fetch(args.release, args.cache_dir, client or UrllibClient())
    if args.command == "strings":
        return strings(args.wheel)
    if args.command == "sbom":
        return sbom(args.wheel)
    if args.command == "fingerprint":
        return fingerprint(args.wheel)
    return inspect(args.wheel)
