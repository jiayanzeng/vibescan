#!/usr/bin/env python3
"""Fail closed when STATE.md drifts from repository-owned source artifacts.

This checker is deterministic, offline, and standard-library only. The npm
packaging contract in npm/scripts/verify-packages.mjs already proves that the
six publishable npm packages match the CLI version and platform inventory.
This status gate cites that contract but re-reads the same manifest fields so
it can report the exact STATE.md field, source path, and conflicting value
without requiring Node.js. The private npm/package.json is tooling metadata,
not a publishable package, and intentionally has no version or license field.
"""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Iterable


STATE_MARKER = "# vibescan:current-state"
STATE_FIELDS = (
    "reviewed",
    "head_commit",
    "worktree",
    "workspace_version",
    "license",
    "released_version",
    "released_tag",
    "integration_status",
    "corpus_version",
    "corpus_tp",
    "corpus_fp",
    "corpus_fn",
    "corpus_precision",
    "corpus_recall",
    "classification_coverage",
    "open_tracks",
)
INTEGRATION_STATUSES = {
    "merged",
    "committed-not-merged",
    "working-tree-only",
}
BANNED_CURRENT_TERMS = ("routes/",)
CURRENT_STATUS_DOCUMENTS = (
    "STATE.md",
    "vibescan-architecture.md",
    "README.md",
    "FAQ.md",
)
REPOMIX_BUNDLE_PATTERN = "repomix-output.*"


def parse_state_block(content: str) -> dict[str, str]:
    lines = content.splitlines()
    marker_indexes = [index for index, line in enumerate(lines) if line == STATE_MARKER]
    if len(marker_indexes) != 1:
        raise ValueError(
            f"STATE.md must contain exactly one {STATE_MARKER!r} marker; "
            f"found {len(marker_indexes)}"
        )

    values: dict[str, str] = {}
    for line in lines[marker_indexes[0] + 1 :]:
        if line == "```":
            break
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"invalid current-state line: {line!r}")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in values:
            raise ValueError(f"duplicate current-state field: {key}")
        if not value:
            raise ValueError(f"current-state field is empty: {key}")
        values[key] = value
    else:
        raise ValueError("current-state block is missing its closing fence")

    missing = [field for field in STATE_FIELDS if field not in values]
    extra = sorted(set(values) - set(STATE_FIELDS))
    if missing:
        raise ValueError(f"current-state block is missing fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"current-state block contains unknown fields: {', '.join(extra)}")
    return values


def format_mismatch(field: str, state_value: str, source: str, source_value: str) -> str:
    return f"{field}: STATE.md={state_value!r} but {source}={source_value!r}"


def check_version_records(
    state: dict[str, str], records: Iterable[tuple[str, str]]
) -> list[str]:
    expected = state["workspace_version"]
    return [
        format_mismatch("workspace_version", expected, source, value)
        for source, value in records
        if value != expected
    ]


def check_license_records(
    state: dict[str, str], records: Iterable[tuple[str, str]]
) -> list[str]:
    expected = state["license"]
    return [
        format_mismatch("license", expected, source, value)
        for source, value in records
        if value != expected
    ]


def metric_records(metrics: dict[str, object]) -> list[tuple[str, str, str]]:
    totals = metrics.get("totals")
    if not isinstance(totals, dict):
        raise ValueError("corpus metrics artifact is missing an object-valued totals field")
    mappings = (
        ("corpus_version", metrics.get("corpus_version"), "corpus_version"),
        ("corpus_tp", totals.get("tp"), "totals.tp"),
        ("corpus_fp", totals.get("fp"), "totals.fp"),
        ("corpus_fn", totals.get("fn"), "totals.fn"),
        ("corpus_precision", totals.get("precision"), "totals.precision"),
        ("corpus_recall", totals.get("recall"), "totals.recall"),
        ("classification_coverage", totals.get("coverage"), "totals.coverage"),
    )
    records = []
    for field, value, source_field in mappings:
        if value is None:
            raise ValueError(f"corpus metrics artifact is missing {source_field}")
        records.append((field, str(value), source_field))
    return records


def check_metrics(state: dict[str, str], metrics: dict[str, object]) -> list[str]:
    errors = []
    source = "tests/fixtures/corpus-metrics-baseline.json"
    for field, value, source_field in metric_records(metrics):
        if state[field] != value:
            errors.append(
                format_mismatch(field, state[field], f"{source}:{source_field}", value)
            )
    return errors


def evaluate_git_check(
    state: dict[str, str],
    *,
    available: bool,
    resolves: bool,
    ancestor: bool,
    shallow: bool,
) -> tuple[list[str], list[str]]:
    commit = state["head_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        return [f"head_commit: expected a full lowercase 40-character SHA, got {commit!r}"], []
    if not available:
        return [], ["head_commit check skipped: git metadata is unavailable"]
    if not resolves:
        if shallow:
            return [], [f"head_commit check skipped: {commit} is absent from the shallow checkout"]
        return [f"head_commit: {commit} does not resolve in this repository"], []
    if not ancestor:
        return [f"head_commit: {commit} resolves but is not an ancestor of HEAD"], []
    return [], []


def run_git(args: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def check_head_commit(
    state: dict[str, str], root: Path
) -> tuple[list[str], list[str]]:
    inside = run_git(["rev-parse", "--is-inside-work-tree"], root)
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return evaluate_git_check(
            state,
            available=False,
            resolves=False,
            ancestor=False,
            shallow=False,
        )

    commit = state["head_commit"]
    resolves = run_git(["cat-file", "-e", f"{commit}^{{commit}}"], root).returncode == 0
    shallow_result = run_git(["rev-parse", "--is-shallow-repository"], root)
    shallow = shallow_result.returncode == 0 and shallow_result.stdout.strip() == "true"
    ancestor = resolves and run_git(
        ["merge-base", "--is-ancestor", commit, "HEAD"], root
    ).returncode == 0
    return evaluate_git_check(
        state,
        available=True,
        resolves=resolves,
        ancestor=ancestor,
        shallow=shallow,
    )


def check_tracked_repomix_paths(paths: Iterable[str]) -> list[str]:
    errors = []
    for path in sorted(paths):
        parts = Path(path).parts
        if (
            fnmatch.fnmatchcase(Path(path).name, REPOMIX_BUNDLE_PATTERN)
            or ".repomix" in parts
        ):
            errors.append(
                f"tracked Repomix audit bundle is forbidden: {path}"
            )
    return errors


def check_tracked_repomix_files(
    root: Path,
) -> tuple[list[str], list[str]]:
    inside = run_git(["rev-parse", "--is-inside-work-tree"], root)
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return [], ["tracked Repomix audit-bundle check skipped: git metadata is unavailable"]

    tracked = run_git(["ls-files", "-z"], root)
    if tracked.returncode != 0:
        return [f"tracked Repomix audit-bundle check failed: {tracked.stderr.strip()}"], []
    return check_tracked_repomix_paths(tracked.stdout.split("\0")), []


def evaluate_integration_truth(
    state: dict[str, str],
    *,
    git_available: bool,
    origin_available: bool,
    head_resolves: bool,
    merged_into_origin: bool,
    worktree_dirty: bool,
) -> tuple[list[str], list[str]]:
    if not git_available:
        return [], ["integration_status truth check skipped: git metadata is unavailable"]
    if not origin_available:
        return [], ["integration_status truth check skipped: origin/main is unavailable"]

    claim = state["integration_status"]
    if claim not in INTEGRATION_STATUSES:
        return [], []
    matches = {
        "merged": head_resolves and merged_into_origin,
        "committed-not-merged": head_resolves and not merged_into_origin,
        "working-tree-only": not head_resolves or worktree_dirty,
    }[claim]
    if matches:
        return [], []

    observed = (
        f"head_commit_resolves={str(head_resolves).lower()}, "
        f"merged_into_origin/main={str(merged_into_origin).lower()}, "
        f"worktree_dirty={str(worktree_dirty).lower()}"
    )
    return [
        f"integration_status: STATE.md={claim!r} contradicts git: {observed}"
    ], []


def check_git_status_truth(
    state: dict[str, str], root: Path
) -> tuple[list[str], list[str]]:
    inside = run_git(["rev-parse", "--is-inside-work-tree"], root)
    git_available = inside.returncode == 0 and inside.stdout.strip() == "true"
    if not git_available:
        integration_errors, integration_notes = evaluate_integration_truth(
            state,
            git_available=False,
            origin_available=False,
            head_resolves=False,
            merged_into_origin=False,
            worktree_dirty=False,
        )
        return integration_errors, integration_notes

    origin_available = (
        run_git(["cat-file", "-e", "origin/main^{commit}"], root).returncode == 0
    )
    if not origin_available:
        integration_errors, integration_notes = evaluate_integration_truth(
            state,
            git_available=True,
            origin_available=False,
            head_resolves=False,
            merged_into_origin=False,
            worktree_dirty=False,
        )
        return integration_errors, integration_notes

    status_result = run_git(["status", "--porcelain"], root)
    if status_result.returncode != 0:
        return [f"integration_status truth check failed: {status_result.stderr.strip()}"], []

    commit = state["head_commit"]
    head_resolves = (
        run_git(["cat-file", "-e", f"{commit}^{{commit}}"], root).returncode == 0
    )
    merged_into_origin = head_resolves and run_git(
        ["merge-base", "--is-ancestor", commit, "origin/main"], root
    ).returncode == 0
    worktree_dirty = bool(status_result.stdout)

    integration_errors, integration_notes = evaluate_integration_truth(
        state,
        git_available=True,
        origin_available=True,
        head_resolves=head_resolves,
        merged_into_origin=merged_into_origin,
        worktree_dirty=worktree_dirty,
    )
    return integration_errors, integration_notes


def check_banned_terms(documents: dict[str, str]) -> list[str]:
    errors = []
    for source, content in sorted(documents.items()):
        for term in BANNED_CURRENT_TERMS:
            for line_number, line in enumerate(content.splitlines(), start=1):
                if term in line:
                    errors.append(
                        f"banned current-status term {term!r} in {source}:{line_number}: "
                        f"{line.strip()}"
                    )
    return errors


def check_integration_status(state: dict[str, str]) -> list[str]:
    value = state["integration_status"]
    if value in INTEGRATION_STATUSES:
        return []
    return [
        "integration_status: STATE.md="
        f"{value!r} but permitted values={sorted(INTEGRATION_STATUSES)!r}"
    ]


def load_repository_records(
    root: Path,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    with (root / "Cargo.toml").open("rb") as handle:
        workspace_manifest = tomllib.load(handle)
    workspace_license = workspace_manifest["workspace"]["package"]["license"]

    versions: list[tuple[str, str]] = []
    licenses: list[tuple[str, str]] = [
        ("Cargo.toml:workspace.package.license", str(workspace_license))
    ]
    cargo_manifests = sorted((root / "crates").glob("*/Cargo.toml"))
    if not cargo_manifests:
        raise ValueError("no workspace crate manifests found under crates/*/Cargo.toml")
    for manifest_path in cargo_manifests:
        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
        package = manifest.get("package", {})
        source = manifest_path.relative_to(root).as_posix()
        version = package.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"{source} has no string package.version")
        versions.append((f"{source}:package.version", version))

        license_value = package.get("license")
        if isinstance(license_value, dict) and license_value.get("workspace") is True:
            resolved_license = workspace_license
        elif isinstance(license_value, str):
            resolved_license = license_value
        else:
            raise ValueError(f"{source} has no resolvable package.license")
        licenses.append((f"{source}:package.license", str(resolved_license)))

    npm_manifests = sorted((root / "npm").glob("**/package.json"))
    for manifest_path in npm_manifests:
        with manifest_path.open(encoding="utf-8") as handle:
            manifest = json.load(handle)
        source = manifest_path.relative_to(root).as_posix()
        if manifest.get("private") is True and "version" not in manifest:
            continue
        version = manifest.get("version")
        license_value = manifest.get("license")
        if not isinstance(version, str) or not version:
            raise ValueError(f"{source} has no string version")
        if not isinstance(license_value, str) or not license_value:
            raise ValueError(f"{source} has no string license")
        versions.append((f"{source}:version", version))
        licenses.append((f"{source}:license", license_value))

    return versions, licenses


def check_repository(root: Path) -> tuple[list[str], list[str]]:
    with (root / "STATE.md").open(encoding="utf-8") as handle:
        state = parse_state_block(handle.read())
    versions, licenses = load_repository_records(root)
    with (root / "tests/fixtures/corpus-metrics-baseline.json").open(
        encoding="utf-8"
    ) as handle:
        metrics = json.load(handle)
    documents = {}
    for relative in CURRENT_STATUS_DOCUMENTS:
        with (root / relative).open(encoding="utf-8") as handle:
            documents[relative] = handle.read()

    errors = []
    notes = []
    errors.extend(check_version_records(state, versions))
    errors.extend(check_license_records(state, licenses))
    errors.extend(check_metrics(state, metrics))
    git_errors, git_notes = check_head_commit(state, root)
    errors.extend(git_errors)
    notes.extend(git_notes)
    errors.extend(check_banned_terms(documents))
    errors.extend(check_integration_status(state))
    repomix_errors, repomix_notes = check_tracked_repomix_files(root)
    errors.extend(repomix_errors)
    notes.extend(repomix_notes)
    truth_errors, truth_notes = check_git_status_truth(state, root)
    errors.extend(truth_errors)
    notes.extend(truth_notes)
    return errors, notes


def sample_state() -> dict[str, str]:
    return {
        "reviewed": "2026-08-02",
        "head_commit": "a" * 40,
        "worktree": "clean",
        "workspace_version": "0.2.0",
        "license": "PolyForm-Noncommercial-1.0.0",
        "released_version": "0.2.0",
        "released_tag": "v0.2.0",
        "integration_status": "merged",
        "corpus_version": "test-v1",
        "corpus_tp": "2",
        "corpus_fp": "0",
        "corpus_fn": "0",
        "corpus_precision": "1.0",
        "corpus_recall": "1.0",
        "classification_coverage": "0.5",
        "open_tracks": "none",
    }


def sample_metrics() -> dict[str, object]:
    return {
        "corpus_version": "test-v1",
        "totals": {
            "tp": 2,
            "fp": 0,
            "fn": 0,
            "precision": 1.0,
            "recall": 1.0,
            "coverage": 0.5,
        },
    }


def require_error(name: str, errors: list[str], text: str) -> None:
    if not any(text in error for error in errors):
        raise AssertionError(f"{name} did not fail with {text!r}: {errors!r}")


def run_self_tests() -> None:
    state = sample_state()
    block = "```yaml\n" + STATE_MARKER + "\n" + "\n".join(
        f"{field}: {state[field]}" for field in STATE_FIELDS
    ) + "\n```\n"
    if parse_state_block(block) != state:
        raise AssertionError("current-state parser positive control drifted")
    try:
        parse_state_block(block.replace("open_tracks: none\n", ""))
    except ValueError as error:
        if "open_tracks" not in str(error):
            raise AssertionError(f"parser negative control named wrong field: {error}") from error
    else:
        raise AssertionError("parser accepted a missing required field")

    versions = [("crate", "0.2.0"), ("npm package", "0.2.0")]
    licenses = [("workspace", "PolyForm-Noncommercial-1.0.0")]
    if check_version_records(state, versions):
        raise AssertionError("version positive control was rejected")
    if check_license_records(state, licenses):
        raise AssertionError("license positive control was rejected")
    require_error(
        "version mismatch",
        check_version_records(state, [("npm package", "9.9.9")]),
        "workspace_version",
    )
    require_error(
        "license mismatch",
        check_license_records(state, [("workspace", "MIT")]),
        "license",
    )

    metrics = sample_metrics()
    if check_metrics(state, metrics):
        raise AssertionError("metrics positive control was rejected")
    bad_metrics = sample_metrics()
    bad_metrics["totals"] = {**bad_metrics["totals"], "coverage": 0.75}
    require_error(
        "metrics mismatch",
        check_metrics(state, bad_metrics),
        "classification_coverage",
    )

    git_errors, _ = evaluate_git_check(
        state, available=True, resolves=True, ancestor=True, shallow=False
    )
    if git_errors:
        raise AssertionError(f"git positive control was rejected: {git_errors}")
    git_errors, _ = evaluate_git_check(
        state, available=True, resolves=True, ancestor=False, shallow=False
    )
    require_error("git ancestry", git_errors, "not an ancestor of HEAD")
    git_errors, git_notes = evaluate_git_check(
        state, available=False, resolves=False, ancestor=False, shallow=False
    )
    if git_errors or not git_notes:
        raise AssertionError("missing git metadata did not produce a clean skip")

    if check_banned_terms({"STATE.md": "Next.js route-handler roots"}):
        raise AssertionError("terminology positive control was rejected")
    require_error(
        "banned terminology",
        check_banned_terms({"STATE.md": "bare routes/ remain server-only"}),
        "routes/",
    )

    if check_integration_status(state):
        raise AssertionError("integration-status positive control was rejected")
    invalid_state = {**state, "integration_status": "probably-merged"}
    require_error(
        "integration status",
        check_integration_status(invalid_state),
        "permitted values",
    )

    if check_tracked_repomix_paths(["src/main.rs", "docs/STATE-HISTORY.md"]):
        raise AssertionError("Repomix tracked-file positive control was rejected")
    require_error(
        "tracked Repomix output",
        check_tracked_repomix_paths(["sub/dir/repomix-output.xml"]),
        "sub/dir/repomix-output.xml",
    )
    require_error(
        "tracked Repomix state",
        check_tracked_repomix_paths(["tools/.repomix/cache.json"]),
        "tools/.repomix/cache.json",
    )

    integration_errors, integration_notes = evaluate_integration_truth(
        state,
        git_available=True,
        origin_available=True,
        head_resolves=True,
        merged_into_origin=True,
        worktree_dirty=False,
    )
    if integration_errors or integration_notes:
        raise AssertionError(
            "integration positive control was rejected: "
            f"{integration_errors!r} {integration_notes!r}"
        )
    committed_state = {**state, "integration_status": "committed-not-merged"}
    integration_errors, _ = evaluate_integration_truth(
        committed_state,
        git_available=True,
        origin_available=True,
        head_resolves=True,
        merged_into_origin=True,
        worktree_dirty=False,
    )
    require_error(
        "integration contradiction",
        integration_errors,
        "merged_into_origin/main=true",
    )
    working_tree_state = {**state, "integration_status": "working-tree-only"}
    integration_errors, _ = evaluate_integration_truth(
        working_tree_state,
        git_available=True,
        origin_available=True,
        head_resolves=True,
        merged_into_origin=False,
        worktree_dirty=True,
    )
    if integration_errors:
        raise AssertionError(
            f"working-tree-only dirty control was rejected: {integration_errors!r}"
        )

    integration_errors, integration_notes = evaluate_integration_truth(
        state,
        git_available=True,
        origin_available=False,
        head_resolves=True,
        merged_into_origin=False,
        worktree_dirty=False,
    )
    if integration_errors or not integration_notes:
        raise AssertionError("missing origin/main did not skip integration truth check cleanly")


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        run_self_tests()
        print("status-consistency: synthetic positive and negative controls passed")
        return 0
    if argv:
        print("usage: check-status-consistency.py [--self-test]", file=sys.stderr)
        return 2

    try:
        errors, notes = check_repository(repository_root())
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"status-consistency: {error}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"status-consistency: {note}")
    if errors:
        for error in errors:
            print(f"status-consistency: {error}", file=sys.stderr)
        return 1

    print(
        "status-consistency: version, license, corpus, git, terminology, "
        "Repomix and integration fields agree"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
