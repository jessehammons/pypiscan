import argparse
from collections.abc import Sequence


def verify() -> int:
    print("pypiscan verify: no packages specified; nothing to do.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pypiscan")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify", help="Verify installed packages against known CVEs (stub).")
    parser.parse_args(argv)
    return verify()
