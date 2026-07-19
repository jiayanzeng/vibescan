#!/usr/bin/env python3
"""Verify deterministic G3 release-channel contracts without live publication."""

import json
import pathlib
import sys
import tomllib


REPOSITORY = "https://github.com/jiayanzeng/vibescan"
TAP = "jiayanzeng/homebrew-tap"
NPM_MAIN_PACKAGE = "@jiayanzeng/vibescan"
PUBLISH_ORDER = [
    "vibescan-types",
    "vibescan-secrets",
    "vibescan-git",
    "vibescan-report",
    "vibescan-supabase",
    "vibescan-registry",
    "vibescan-core",
    "vibescan-cli",
]
REQUIRED_PUBLISH_JOBS = {"homebrew", "./publish-crates", "./publish-npm"}


def fail(message):
    raise AssertionError(message)


def read_toml(path):
    with path.open("rb") as handle:
        return tomllib.load(handle)


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def workspace_dependency_names(manifest, workspace_names):
    names = set()
    for section in ("dependencies", "build-dependencies", "dev-dependencies"):
        for name in manifest.get(section, {}):
            if name in workspace_names:
                names.add(name)
    for target in manifest.get("target", {}).values():
        for section in ("dependencies", "build-dependencies", "dev-dependencies"):
            for name in target.get(section, {}):
                if name in workspace_names:
                    names.add(name)
    return names


def main():
    repository_root = pathlib.Path(__file__).resolve().parents[1]
    workspace = read_toml(repository_root / "Cargo.toml")
    workspace_package = workspace["workspace"]["package"]
    if workspace_package.get("homepage") != REPOSITORY:
        fail("workspace homepage must match the public repository")
    if workspace_package.get("repository") != REPOSITORY:
        fail("workspace repository must match the public repository")

    member_manifests = {}
    for member in workspace["workspace"]["members"]:
        manifest_path = repository_root / member / "Cargo.toml"
        manifest = read_toml(manifest_path)
        package = manifest["package"]
        member_manifests[package["name"]] = (manifest_path, manifest)

    if set(member_manifests) != set(PUBLISH_ORDER):
        fail(
            "publish order must name the exact architecture workspace: "
            f"expected {PUBLISH_ORDER}, found {sorted(member_manifests)}"
        )

    positions = {name: index for index, name in enumerate(PUBLISH_ORDER)}
    for name in PUBLISH_ORDER:
        manifest_path, manifest = member_manifests[name]
        package = manifest["package"]
        for field in ("description", "version"):
            if not package.get(field):
                fail(f"{manifest_path}: package.{field} is required")
        for inherited in ("homepage", "license", "repository", "rust-version"):
            if package.get(inherited) != {"workspace": True}:
                fail(f"{manifest_path}: package.{inherited} must inherit workspace metadata")
        if package.get("readme") != "../../README.md":
            fail(f"{manifest_path}: package.readme must package the root README")
        if package.get("publish") is False:
            fail(f"{manifest_path}: package is disabled for publication")

        for dependency in workspace_dependency_names(manifest, set(PUBLISH_ORDER)):
            if positions[dependency] >= positions[name]:
                fail(f"publish order places {name} before dependency {dependency}")

    cli_package = member_manifests["vibescan-cli"][1]["package"]
    cli_bins = member_manifests["vibescan-cli"][1].get("bin", [])
    if not any(binary.get("name") == "vibescan" for binary in cli_bins):
        fail("vibescan-cli must continue to ship the vibescan binary")
    if cli_package["name"] != "vibescan-cli":
        fail("the architecture-named CLI package must remain vibescan-cli")

    workspace_dependencies = workspace["workspace"]["dependencies"]
    for name in PUBLISH_ORDER[:-1]:
        dependency = workspace_dependencies.get(name)
        if not isinstance(dependency, dict) or not dependency.get("path") or not dependency.get("version"):
            fail(f"workspace dependency {name} must carry path and registry version")

    dist = read_toml(repository_root / "dist-workspace.toml")["dist"]
    if set(dist.get("installers", [])) != {"shell", "powershell", "homebrew"}:
        fail("dist installers must be shell, powershell, and homebrew")
    if dist.get("tap") != TAP or dist.get("formula") != "vibescan":
        fail("dist Homebrew tap/formula contract is incorrect")
    if set(dist.get("publish-jobs", [])) != REQUIRED_PUBLISH_JOBS:
        fail("dist publish jobs must include Homebrew, crates.io, and npm")
    if "npm" in dist.get("installers", []) or "npm" in dist.get("publish-jobs", []):
        fail("the fetch-based built-in npm installer/publisher must remain disabled")

    npm_main = read_json(repository_root / "npm" / "vibescan" / "package.json")
    if npm_main.get("name") != NPM_MAIN_PACKAGE:
        fail(f"main npm package must be the approved scoped identity {NPM_MAIN_PACKAGE}")
    if npm_main.get("publishConfig") != {"access": "public", "provenance": True}:
        fail("main npm package must request public provenance publication")
    for package_dir in (repository_root / "npm" / "platforms").iterdir():
        if not package_dir.is_dir():
            continue
        package = read_json(package_dir / "package.json")
        if package.get("publishConfig") != {"access": "public", "provenance": True}:
            fail(f"{package['name']} must request public provenance publication")

    required_files = {
        ".github/workflows/publish-crates.yml": [
            "rust-lang/crates-io-auth-action@v1",
            "BOOTSTRAP_CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "scripts/publish-crates.sh",
            "--publish",
        ],
        ".github/workflows/publish-npm.yml": [
            'id-token: write',
            'node-version: 24',
            "publish-packages.mjs",
            "--publish",
        ],
        "RELEASING.md": [
            "vibescan-types",
            "vibescan-cli",
            "npm publish",
            "HOMEBREW_TAP_TOKEN",
            "gh attestation verify",
        ],
    }
    for relative_path, markers in required_files.items():
        source = (repository_root / relative_path).read_text(encoding="utf-8")
        for marker in markers:
            if marker not in source:
                fail(f"{relative_path} is missing required marker: {marker}")

    crates_workflow = (
        repository_root / ".github" / "workflows" / "publish-crates.yml"
    ).read_text(encoding="utf-8")
    if "if: ${{ secrets." in crates_workflow:
        fail("publish-crates.yml must route secret-dependent conditions through env")

    print("release publishing contracts verified")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"release publishing contract failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
