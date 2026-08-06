#!/usr/bin/env python3
"""Mechanically verify the committed Track L triage worklist is redacted."""

from __future__ import annotations

import csv
import re
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent.parent
WORKLIST = ROOT / "docs/tracks/vibescan-trackL-real-repo-triage.tsv"
FIELDS = (
    "repository",
    "commit",
    "rule_id",
    "path",
    "location_class",
    "severity",
    "label",
    "rationale",
)
SECRET_PATTERNS = (
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}"),
    re.compile(r"sk-ant-api03-[A-Za-z0-9_-]{24,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{24,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{24,}"),
    re.compile(r"sb_(?:publishable|secret)_[A-Za-z0-9_-]{24,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)
OPAQUE_RATIONALE_TOKEN = re.compile(r"(?<![A-Za-z0-9_+=./-])[A-Za-z0-9_+=./-]{24,}(?![A-Za-z0-9_+=./-])")


def main() -> int:
    with WORKLIST.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, dialect="excel-tab")
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError(f"unexpected triage fields: {reader.fieldnames!r}")
        rows = list(reader)

    if not rows:
        raise ValueError("triage worklist must contain at least one finding")
    for index, row in enumerate(rows, start=2):
        if any(not row[field] for field in FIELDS):
            raise ValueError(f"row {index} contains an empty field")
        if not re.fullmatch(r"[0-9a-f]{40}", row["commit"]):
            raise ValueError(f"row {index} commit is not a full SHA")
        path = PurePosixPath(row["path"])
        if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", row["path"]):
            raise ValueError(f"row {index} path is not repository-relative")
        if row["label"] not in {"TP", "FP", "uncertain"}:
            raise ValueError(f"row {index} has an invalid label")
        serialized = "\t".join(row[field] for field in FIELDS)
        if "://" in serialized or "@" in serialized or "/private/" in serialized:
            raise ValueError(f"row {index} contains endpoint, email, or absolute-path material")
        for pattern in SECRET_PATTERNS:
            if pattern.search(serialized):
                raise ValueError(f"row {index} contains credential-shaped material")
        if OPAQUE_RATIONALE_TOKEN.search(row["rationale"]):
            raise ValueError(f"row {index} rationale contains an opaque token")

    print(f"track-l-triage: redaction checks passed rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
