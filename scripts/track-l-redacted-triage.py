#!/usr/bin/env python3
"""Emit source context for Track L findings without printing matched values."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath


def rule_id(finding: dict[str, object]) -> str:
    title = finding.get("title")
    prefix = "Secret candidate matched "
    if isinstance(title, str) and title.startswith(prefix):
        return title.removeprefix(prefix)
    evidence = finding.get("evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get("kind"), str):
        return str(evidence["kind"])
    return "unknown"


def redacted_context(root: Path, location: dict[str, object]) -> str:
    path_value = location.get("path")
    span = location.get("span")
    if not isinstance(path_value, str) or not isinstance(span, dict):
        return "<no source span>"
    relative = PurePosixPath(path_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe repository-relative path: {path_value!r}")
    line_number = span.get("line")
    col_start = span.get("col_start")
    col_end = span.get("col_end")
    if not all(isinstance(value, int) for value in (line_number, col_start, col_end)):
        return "<invalid source span>"
    lines = (root / Path(*relative.parts)).read_bytes().splitlines()
    if line_number < 1 or line_number > len(lines):
        return "<source line unavailable>"
    line = lines[line_number - 1]
    start = max(col_start - 1, 0)
    end = max(col_end - 1, start)
    return (line[:start] + b"<redacted>" + line[end:]).decode(
        "utf-8", errors="replace"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    parser.add_argument("repo", type=Path)
    args = parser.parse_args()

    result = json.loads(args.result.read_text(encoding="utf-8"))
    for finding in result.get("findings", []):
        if not isinstance(finding, dict):
            raise ValueError("finding must be an object")
        locations = finding.get("locations", [])
        if not isinstance(locations, list):
            raise ValueError("finding locations must be a list")
        for location in locations:
            if not isinstance(location, dict):
                raise ValueError("location must be an object")
            print(
                json.dumps(
                    {
                        "rule_id": rule_id(finding),
                        "path": location.get("path"),
                        "location_class": location.get("location_class"),
                        "severity": finding.get("severity"),
                        "confidence": finding.get("confidence"),
                        "context": redacted_context(args.repo, location),
                    },
                    sort_keys=True,
                )
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
