"""Compare ``pypiscan wheel`` output with one package's lines in an episode.

Usage: python3 scripts/wheel_vs_episode.py <wheel.jsonl> <episode-dir> <name>

For phases 05, 09 and 10, prints "match" or the differences between the
package's line and the output's records, then the output's counts. Checks
the output's wheel sha256 against phase 01's. Always exits 0.

Standard library only, so it runs with any python3.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def episode_line(episode: Path, number: str, name: str) -> dict[str, Any] | None:
    """The package's line in phase ``number``'s finished file, if any."""
    for path in sorted(episode.glob(f"{number}-*.jsonl")):
        for text in path.read_text(encoding="utf-8").splitlines():
            line = json.loads(text)
            if line.get("name") == name:
                return line
    return None


def keys(items: list[object]) -> list[str]:
    return [json.dumps(item, sort_keys=True) for item in items]


def compare(label: str, episode: list[object], output: list[object]) -> None:
    if keys(episode) == keys(output):
        print(f"{label}: match ({len(output)} entries)")
        return
    print(f"{label}: DIFFERENT")
    only_episode = set(keys(episode)) - set(keys(output))
    only_output = set(keys(output)) - set(keys(episode))
    if not only_episode and not only_output:
        print("  same entries, different order")
    for text in sorted(only_episode):
        print(f"  only in episode: {text[:300]}")
    for text in sorted(only_output):
        print(f"  only in output: {text[:300]}")


def main() -> None:
    output_path, episode, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for text in output_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(text)
        by_kind.setdefault(record["kind"], []).append(record)
    print(f"package {name}")

    resolve = episode_line(episode, "01", name)
    wheels = by_kind.get("wheel", [])
    sha256 = wheels[0]["sha256"] if wheels else None
    if resolve is None or resolve.get("status") != "ok":
        print("01-resolve: no ok line")
    elif sha256 == resolve.get("sha256"):
        print(f"01-resolve: sha256 match ({sha256})")
    else:
        print(f"01-resolve: sha256 DIFFERENT: {resolve.get('sha256')} vs {sha256}")

    checks = [
        (
            "05",
            "05-libraries",
            lambda line: line["libraries"],
            [
                {"path": r["path"], "prefix": r["prefix"]}
                for r in by_kind.get("library", [])
            ],
        ),
        (
            "09",
            "09-sboms",
            lambda line: line["records"],
            [r["sbom"] for r in by_kind.get("sbom", [])],
        ),
        (
            "10",
            "10-static",
            lambda line: [
                b for b in line["binaries"] if b["candidates"] or b["fingerprints"]
            ],
            [
                {k: r[k] for k in ("path", "sha256", "candidates", "fingerprints")}
                for r in by_kind.get("static", [])
            ],
        ),
    ]
    for number, label, payload, output in checks:
        line = episode_line(episode, number, name)
        if line is None or line.get("status") != "ok":
            status = "missing" if line is None else line.get("status")
            print(f"{label}: no ok line ({status})")
            continue
        compare(label, payload(line), output)

    static = by_kind.get("static", [])
    candidates = sum(len(r["candidates"]) for r in static)
    print(
        "counts: "
        f"libraries {len(by_kind.get('library', []))}, "
        f"sboms {len(by_kind.get('sbom', []))}, "
        f"untied components {len(by_kind.get('untied_component', []))}, "
        f"untied files {len(by_kind.get('untied_file', []))}, "
        f"binaries with candidates {sum(1 for r in static if r['candidates'])}, "
        f"candidates {candidates}"
    )


if __name__ == "__main__":
    main()
