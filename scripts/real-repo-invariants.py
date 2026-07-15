#!/usr/bin/env python3
"""Validate repo-agnostic invariants over a vibescan JSON result."""

from __future__ import annotations

import argparse
import copy
import json
import ntpath
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit


RAW_SUPABASE_KEY = re.compile(
    r"(?<![A-Za-z0-9_-])sb_(?:publishable|secret)_[A-Za-z0-9_-]{20,}"
)
CLASSIFIED_CATEGORIES = {"secret_exposure", "key_classification", "rls"}


@dataclass(frozen=True)
class ValidationSummary:
    coverage_percent: float
    findings: int
    projects: int

    def line(self) -> str:
        return (
            "REALREPO_INVARIANTS ok "
            f"coverage={self.coverage_percent:.2f}% "
            f"findings={self.findings} projects={self.projects}"
        )


class InvariantFailure(Exception):
    def __init__(self, violations: Iterable[str]) -> None:
        self.violations = tuple(violations)
        super().__init__("; ".join(self.violations))


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any, path: str = "evidence") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _strings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _strings(child, f"{path}[{index}]")


def _normalized_project_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    raw = value.strip()
    parsed = urlsplit(raw)
    if parsed.scheme and parsed.netloc:
        path = parsed.path
        marker = "/rest/v1"
        if marker in path:
            path = path.split(marker, 1)[0]
        path = path.rstrip("/")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    return raw.rstrip("/").lower()


def _project_from_evidence(evidence: dict[str, Any]) -> str:
    project = evidence.get("project")
    if isinstance(project, dict):
        return _normalized_project_url(project.get("url"))
    if isinstance(project, str):
        return _normalized_project_url(project)
    return _normalized_project_url(evidence.get("project_url"))


def _rule_id(finding: dict[str, Any], evidence: dict[str, Any]) -> str:
    explicit = finding.get("rule_id")
    if isinstance(explicit, str) and explicit:
        return explicit

    kind = evidence.get("kind")
    if kind == "secret":
        title = finding.get("title")
        prefix = "Secret candidate matched "
        if isinstance(title, str) and title.startswith(prefix):
            return title[len(prefix) :]
        return "generic-secret"
    if kind == "supabase_key":
        return f"supabase-key:{evidence.get('class', 'unknown')}"
    if kind == "rls_probe":
        return f"rls:{evidence.get('exposure', 'unknown')}"
    if kind == "dependency":
        return f"dependency:{evidence.get('reason', 'unknown')}"
    if kind == "correlation":
        return str(evidence.get("rule_id", "correlation"))
    return str(kind or "unknown")


def _identity(finding: dict[str, Any]) -> tuple[str, str, str] | None:
    evidence = _dict(finding.get("evidence"))
    fingerprint = evidence.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    return (
        _rule_id(finding, evidence),
        fingerprint,
        _project_from_evidence(evidence),
    )


def _locations(finding: dict[str, Any]) -> list[tuple[str, str | None]]:
    class_by_path: dict[str, str] = {}
    for value in finding.get("location_classes", []):
        if isinstance(value, str) and "=" in value:
            path, location_class = value.rsplit("=", 1)
            class_by_path[path] = location_class

    raw_locations = finding.get("locations", [])
    if not isinstance(raw_locations, list):
        raw_locations = []
    locations: list[tuple[str, str | None]] = []
    for location in raw_locations:
        if isinstance(location, dict):
            path = location.get("path")
            location_class = location.get("location_class")
            if isinstance(path, str):
                locations.append(
                    (path, location_class if isinstance(location_class, str) else None)
                )
        elif isinstance(location, str):
            locations.append((location, class_by_path.get(location)))
    return locations


def _has_segments(segments: list[str], needle: tuple[str, ...]) -> bool:
    width = len(needle)
    return any(tuple(segments[index : index + width]) == needle for index in range(len(segments) - width + 1))


def _has_package_server_root(segments: list[str]) -> bool:
    if segments[:1] == ["api"] or segments[:2] == ["src", "api"]:
        return True
    package_roots = {"apps", "packages", "services"}
    for index, segment in enumerate(segments):
        if segment not in package_roots:
            continue
        if index + 1 < len(segments) and segments[index + 1] == "api":
            return True
        if index + 2 < len(segments) and segments[index + 2] == "api":
            return True
        if (
            index + 3 < len(segments)
            and segments[index + 2 : index + 4] == ["src", "api"]
        ):
            return True
    return False


def _expected_location_class(path: str) -> str | None:
    segments = [segment for segment in path.replace("\\", "/").lower().split("/") if segment]
    basename = segments[-1] if segments else ""
    is_env = basename == ".env" or basename.startswith(".env.")
    if (
        is_env
        or _has_segments(segments, ("app", "api"))
        or _has_segments(segments, ("pages", "api"))
        or _has_segments(segments, ("src", "app", "api"))
        or _has_segments(segments, ("src", "pages", "api"))
        or "server" in segments
        or _has_segments(segments, (".next", "server"))
        or _has_segments(segments, ("supabase", "functions"))
        or _has_package_server_root(segments)
    ):
        return "server_only"
    if (
        any(segment in segments for segment in ("public", "app", "pages"))
        or _has_segments(segments, ("src", "app"))
        or _has_segments(segments, ("src", "pages"))
        or _has_segments(segments, ("src", "components"))
        or any(segment in segments for segment in ("dist", "build", "out"))
        or _has_segments(segments, (".next", "static"))
        or ".svelte-kit" in segments
        or "client" in segments
        or ".client." in basename
    ):
        return "client_reachable"
    return None


def _is_absolute_path(path: str) -> bool:
    return posixpath.isabs(path) or ntpath.isabs(path)


def _contains_root(value: str, scan_root: str | None) -> bool:
    if not scan_root:
        return False
    normalized_value = value.replace("\\", "/")
    normalized_root = scan_root.rstrip("/\\").replace("\\", "/")
    return bool(normalized_root) and normalized_root in normalized_value


def validate(
    document: Any,
    *,
    scan_root: str | None = None,
    require_classification_coverage: bool = False,
    expect_findings: int | None = None,
    require_supabase_location: str | None = None,
) -> ValidationSummary:
    if not isinstance(document, dict):
        raise InvariantFailure(["top-level JSON value must be an object"])
    findings = document.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise InvariantFailure(["findings must be an array of objects"])

    scope = _dict(document.get("scope"))
    if scan_root is None:
        target = scope.get("target")
        if isinstance(target, str) and _is_absolute_path(target):
            scan_root = target
    if scan_root is not None:
        scan_root = os.path.realpath(scan_root)

    violations: list[str] = []
    identities: dict[tuple[str, str, str], int] = {}
    projects: set[str] = set()
    coverage_total = 0
    coverage_classified = 0

    for index, raw_finding in enumerate(findings):
        finding = _dict(raw_finding)
        identity = _identity(finding)
        if identity is not None:
            previous = identities.get(identity)
            if previous is not None:
                violations.append(
                    "fingerprint uniqueness: findings "
                    f"{previous} and {index} share identity {identity!r}"
                )
            else:
                identities[identity] = index

        evidence = _dict(finding.get("evidence"))
        project = _project_from_evidence(evidence)
        if project:
            projects.add(project)

        locations = _locations(finding)
        for path, location_class in locations:
            if _is_absolute_path(path):
                violations.append(
                    f"serialized path safety: finding {index} contains absolute location {path!r}"
                )
            if _contains_root(path, scan_root):
                violations.append(
                    f"serialized path safety: finding {index} location contains scan root"
                )
            expected_class = _expected_location_class(path)
            if (
                expected_class is not None
                and isinstance(location_class, str)
                and location_class.lower() == "unknown"
            ):
                violations.append(
                    "classification: classifiable path "
                    f"{path!r} is Unknown (expected {expected_class})"
                )

        category = finding.get("category")
        has_class_annotations = any(location_class is not None for _, location_class in locations)
        if category in CLASSIFIED_CATEGORIES and has_class_annotations:
            coverage_total += 1
            if any(
                isinstance(location_class, str) and location_class.lower() != "unknown"
                for _, location_class in locations
            ):
                coverage_classified += 1

        for evidence_path, value in _strings(evidence):
            if _contains_root(value, scan_root):
                violations.append(
                    f"serialized path safety: finding {index} {evidence_path} contains scan root"
                )
            if RAW_SUPABASE_KEY.search(value):
                violations.append(
                    f"redaction: finding {index} {evidence_path} contains a full Supabase key"
                )

    network = _dict(scope.get("network"))
    actions = network.get("actions", [])
    if not isinstance(actions, list):
        violations.append("scope.network.actions must be an array")
        actions = []
    network_enabled = bool(network.get("enabled") or network.get("tier0_read_probe"))
    root_action_projects: dict[str, int] = {}
    action_identities: dict[tuple[str, str, str], int] = {}
    for index, raw_action in enumerate(actions):
        action = _dict(raw_action)
        project = _normalized_project_url(action.get("endpoint"))
        if project:
            projects.add(project)
        if not network_enabled or not project:
            continue
        kind = str(action.get("kind", ""))
        table = str(action.get("table") or "")
        action_identity = (project, kind, table)
        previous_action = action_identities.get(action_identity)
        if previous_action is not None:
            violations.append(
                "probe-input uniqueness: network actions "
                f"{previous_action} and {index} repeat {action_identity!r}"
            )
        else:
            action_identities[action_identity] = index
        if kind == "root_enumeration":
            previous_root = root_action_projects.get(project)
            if previous_root is not None:
                violations.append(
                    "probe-input uniqueness: Tier 0 root actions "
                    f"{previous_root} and {index} share project {project!r}"
                )
            else:
                root_action_projects[project] = index

    if expect_findings is not None and len(findings) != expect_findings:
        violations.append(
            f"control finding count: expected {expect_findings}, got {len(findings)}"
        )

    if require_supabase_location is not None:
        positive = any(
            any(path == require_supabase_location for path, _ in _locations(finding))
            and (
                "supabase" in str(finding.get("title", "")).lower()
                or _dict(finding.get("evidence")).get("kind") == "supabase_key"
            )
            for finding in findings
        )
        if not positive:
            violations.append(
                "planted positive control: expected a Supabase finding at "
                f"{require_supabase_location!r}"
            )

    if require_classification_coverage and coverage_total and not coverage_classified:
        violations.append(
            "classification coverage: secret/RLS findings exist but all are Unknown"
        )

    if violations:
        raise InvariantFailure(violations)

    coverage = 100.0 if coverage_total == 0 else 100.0 * coverage_classified / coverage_total
    return ValidationSummary(
        coverage_percent=coverage,
        findings=len(findings),
        projects=len(projects),
    )


def _expect_failure(label: str, document: dict[str, Any], expected: str, **kwargs: Any) -> None:
    try:
        validate(document, **kwargs)
    except InvariantFailure as error:
        if expected not in str(error):
            raise AssertionError(f"{label}: expected {expected!r} in {error!r}") from error
    else:
        raise AssertionError(f"{label}: checker unexpectedly accepted invalid JSON")


def _sample_finding() -> dict[str, Any]:
    return {
        "id": "sample",
        "category": "secret_exposure",
        "severity": "high",
        "title": "Secret candidate matched sample-secret",
        "locations": [
            {
                "path": "apps/web/src/app/page.tsx",
                "location_class": "client_reachable",
            }
        ],
        "evidence": {
            "kind": "secret",
            "redacted": "sb_sec...WXYZ",
            "fingerprint": "sample-fingerprint",
        },
    }


def run_self_tests() -> None:
    sample = _sample_finding()
    duplicate = {"findings": [sample, copy.deepcopy(sample)]}
    _expect_failure("duplicate fingerprint", duplicate, "fingerprint uniqueness")

    absolute = copy.deepcopy(sample)
    absolute["locations"][0]["path"] = "/tmp/vibescan-real/src/app/page.tsx"
    _expect_failure(
        "absolute path",
        {"findings": [absolute]},
        "absolute location",
        scan_root="/tmp/vibescan-real",
    )

    raw_secret = copy.deepcopy(sample)
    raw_secret["evidence"]["redacted"] = (
        "sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF"
    )
    _expect_failure("raw secret", {"findings": [raw_secret]}, "full Supabase key")

    unknown = copy.deepcopy(sample)
    unknown["locations"][0]["location_class"] = "unknown"
    _expect_failure("classifiable Unknown", {"findings": [unknown]}, "classifiable path")

    duplicate_probe = {
        "findings": [],
        "scope": {
            "network": {
                "enabled": True,
                "tier0_read_probe": True,
                "actions": [
                    {
                        "kind": "root_enumeration",
                        "endpoint": "https://Example.supabase.co/rest/v1/",
                    },
                    {
                        "kind": "root_enumeration",
                        "endpoint": "https://example.supabase.co/rest/v1/",
                    },
                ],
            }
        },
    }
    _expect_failure(
        "duplicate Tier 0 project", duplicate_probe, "probe-input uniqueness"
    )

    golden_path = (
        Path(__file__).resolve().parents[1]
        / "tests"
        / "fixtures"
        / "offline-composite-exposed-public-key-chain"
        / "expected.json"
    )
    with golden_path.open(encoding="utf-8") as handle:
        validate(json.load(handle))

    summary = validate(
        {"findings": [sample]}, require_classification_coverage=True
    )
    assert summary.coverage_percent == 100.0
    print("REALREPO_INVARIANTS self-test ok cases=7")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_path", nargs="?", help="scan JSON path; reads stdin when omitted")
    parser.add_argument("--scan-root", help="absolute scan root forbidden in finding output")
    parser.add_argument(
        "--require-classification-coverage",
        action="store_true",
        help="fail when eligible findings exist but every class is Unknown",
    )
    parser.add_argument("--expect-findings", type=int)
    parser.add_argument("--require-supabase-location")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if args.self_test:
        if args.json_path:
            parser.error("--self-test does not accept a JSON path")
        run_self_tests()
        return 0

    try:
        if args.json_path:
            with open(args.json_path, encoding="utf-8") as handle:
                document = json.load(handle)
        else:
            document = json.load(sys.stdin)
    except (OSError, json.JSONDecodeError) as error:
        print(f"REALREPO_INVARIANTS input error: {error}", file=sys.stderr)
        return 2

    try:
        summary = validate(
            document,
            scan_root=args.scan_root,
            require_classification_coverage=args.require_classification_coverage,
            expect_findings=args.expect_findings,
            require_supabase_location=args.require_supabase_location,
        )
    except InvariantFailure as error:
        for violation in error.violations:
            print(f"REALREPO_INVARIANTS failed: {violation}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(summary.line())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
