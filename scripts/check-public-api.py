#!/usr/bin/env python3
"""Check the committed, deterministic crate-root public API inventory.

The inventory mirrors Track K's rustdoc-path contract: local named items that
are reachable at each scoped crate root, plus their enum variants. It is
derived directly from Rust source so the gate is offline and does not depend on
nightly rustdoc, a captured Track K artifact, or a previously built target/.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


SCOPED_CRATES = (
    "vibescan-core",
    "vibescan-supabase",
    "vibescan-git",
    "vibescan-registry",
    "vibescan-report",
    "vibescan-secrets",
)
DEFAULT_INVENTORY = Path("docs/public-api-inventory.txt")


@dataclass(frozen=True)
class Item:
    kind: str
    name: str
    variants: tuple[str, ...] = ()


def mask_non_code(source: str) -> str:
    """Replace comments and literals with spaces while preserving offsets."""
    masked = list(source)
    index = 0
    block_depth = 0
    while index < len(source):
        if block_depth:
            if source.startswith("/*", index):
                masked[index : index + 2] = "  "
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                masked[index : index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if source[index] != "\n":
                    masked[index] = " "
                index += 1
            continue

        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end == -1 else end
            for position in range(index, end):
                masked[position] = " "
            index = end
            continue
        if source.startswith("/*", index):
            masked[index : index + 2] = "  "
            block_depth = 1
            index += 2
            continue

        raw = re.match(r'(?:b)?r(#{0,16})"', source[index:])
        if raw:
            marker = '"' + raw.group(1)
            end = source.find(marker, index + raw.end())
            end = len(source) if end == -1 else end + len(marker)
            for position in range(index, end):
                if source[position] != "\n":
                    masked[position] = " "
            index = end
            continue

        start = index
        if source.startswith('b"', index):
            index += 1
        if source[index] == '"':
            index += 1
            escaped = False
            while index < len(source):
                character = source[index]
                if character == '"' and not escaped:
                    index += 1
                    break
                if character == "\\":
                    escaped = not escaped
                else:
                    escaped = False
                index += 1
            for position in range(start, index):
                if source[position] != "\n":
                    masked[position] = " "
            continue

        if source[index] == "'" and index + 2 < len(source):
            end = index + 1
            escaped = False
            while end < len(source) and source[end] != "\n":
                if source[end] == "'" and not escaped:
                    end += 1
                    break
                if source[end] == "\\":
                    escaped = not escaped
                else:
                    escaped = False
                end += 1
            if source[end - 1 : end] == "'":
                for position in range(index, end):
                    masked[position] = " "
                index = end
                continue

        index += 1
    return "".join(masked)


def brace_depths(masked: str) -> list[int]:
    depths = [0] * (len(masked) + 1)
    depth = 0
    for index, character in enumerate(masked):
        depths[index] = depth
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced closing brace")
    depths[len(masked)] = depth
    if depth:
        raise ValueError("unbalanced opening brace")
    return depths


def matching_brace(masked: str, opening: int) -> int:
    depth = 1
    for position in range(opening + 1, len(masked)):
        if masked[position] == "{":
            depth += 1
        elif masked[position] == "}":
            depth -= 1
            if depth == 0:
                return position
    raise ValueError("unbalanced item body")


def enum_variants(masked: str, opening: int, closing: int) -> tuple[str, ...]:
    body = masked[opening + 1 : closing]
    segments: list[str] = []
    start = 0
    paren = bracket = brace = 0
    for index, character in enumerate(body):
        if character == "(":
            paren += 1
        elif character == ")":
            paren -= 1
        elif character == "[":
            bracket += 1
        elif character == "]":
            bracket -= 1
        elif character == "{":
            brace += 1
        elif character == "}":
            brace -= 1
        elif character == "," and paren == bracket == brace == 0:
            segments.append(body[start:index])
            start = index + 1
    segments.append(body[start:])

    variants = []
    for segment in segments:
        without_attributes = re.sub(r"#\s*\[[^\]]*\]", " ", segment).strip()
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\b", without_attributes)
        if match:
            variants.append(match.group(1))
    return tuple(variants)


def module_items(path: Path) -> dict[str, Item]:
    source = path.read_text()
    masked = mask_non_code(source)
    depths = brace_depths(masked)
    declaration = re.compile(
        r"(?m)^\s*pub\s+(?!\()(const\s+fn|const|static|type|struct|enum|trait|fn)"
        r"\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    kinds = {
        "const fn": "function",
        "const": "constant",
        "static": "static",
        "type": "type_alias",
        "struct": "struct",
        "enum": "enum",
        "trait": "trait",
        "fn": "function",
    }
    items: dict[str, Item] = {}
    for match in declaration.finditer(masked):
        if depths[match.start()] != 0:
            continue
        raw_kind, name = match.groups()
        variants: tuple[str, ...] = ()
        if raw_kind == "enum":
            opening = masked.find("{", match.end())
            if opening == -1:
                raise ValueError(f"{path}: enum {name} has no body")
            variants = enum_variants(masked, opening, matching_brace(masked, opening))
        items[name] = Item(kinds[raw_kind], name, variants)
    return items


def top_level_reexports(path: Path) -> list[str]:
    source = path.read_text()
    masked = mask_non_code(source)
    depths = brace_depths(masked)
    statements = []
    for match in re.finditer(r"(?ms)^\s*pub\s+use\s+(.+?);", masked):
        if depths[match.start()] == 0:
            statements.append(re.sub(r"\s+", " ", match.group(1)).strip())
    return statements


def selected_names(selection: str) -> tuple[str, list[str] | None]:
    if "::{" in selection:
        module, names = selection.split("::{", 1)
        names = names.rsplit("}", 1)[0]
        return module.strip(), [name.strip() for name in names.split(",") if name.strip()]
    if selection.endswith("::*"):
        return selection[:-3].strip(), None
    module, separator, name = selection.rpartition("::")
    if not separator:
        return "", [name]
    return module.strip(), [name.strip()]


def crate_inventory(root: Path, crate: str) -> list[str]:
    crate_name = crate.replace("-", "_")
    src = root / "crates" / crate / "src"
    lib = src / "lib.rs"
    local_modules = {
        match.group(1)
        for match in re.finditer(
            r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
            mask_non_code(lib.read_text()),
        )
    }
    modules = {"": module_items(lib)}
    for module in local_modules:
        module_path = src / f"{module}.rs"
        if module_path.is_file():
            modules[module] = module_items(module_path)

    exported = dict(modules[""])
    for selection in top_level_reexports(lib):
        module, names = selected_names(selection)
        if module not in modules:
            # Track K's local-item inventory deliberately excludes external
            # re-exports such as vibescan_types::Severity.
            continue
        source_items = modules[module]
        chosen = source_items if names is None else {name: source_items[name] for name in names}
        exported.update(chosen)

    lines = [f"module\t{crate_name}"]
    for item in exported.values():
        lines.append(f"{item.kind}\t{crate_name}::{item.name}")
        lines.extend(
            f"variant\t{crate_name}::{item.name}::{variant}" for variant in item.variants
        )
    return lines


def derive(root: Path) -> str:
    lines = []
    for crate in SCOPED_CRATES:
        lines.extend(crate_inventory(root, crate))
    return "\n".join(sorted(lines)) + "\n"


def self_test() -> None:
    sample = '''
pub enum Example { First, Second { value: usize }, Third(String) }
pub(crate) fn hidden() {}
pub fn visible() { let _ = "}"; }
'''
    with tempfile.TemporaryDirectory(prefix="vibescan-public-api-self-test-") as temp_dir:
        temporary = Path(temp_dir) / "lib.rs"
        temporary.write_text(sample)
        assert module_items(temporary) == {
            "Example": Item("enum", "Example", ("First", "Second", "Third")),
            "visible": Item("function", "visible"),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--print", dest="print_inventory", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("public-api-inventory: self-test passed")
        return 0

    root = args.root.resolve()
    actual = derive(root)
    if args.print_inventory:
        sys.stdout.write(actual)
        return 0

    inventory = args.inventory
    if not inventory.is_absolute():
        inventory = root / inventory
    if args.write:
        inventory.parent.mkdir(parents=True, exist_ok=True)
        inventory.write_text(actual)
        print(f"public-api-inventory: wrote {inventory}")
        return 0
    if not inventory.is_file():
        print(f"public-api-inventory: missing generated artifact {inventory}", file=sys.stderr)
        return 1

    expected = inventory.read_text()
    if expected == actual:
        print("public-api-inventory: committed inventory matches source")
        return 0

    expected_lines = set(expected.splitlines())
    actual_lines = set(actual.splitlines())
    print("public-api-inventory: mismatch", file=sys.stderr)
    for line in sorted(expected_lines - actual_lines):
        print(f"removed: {line}", file=sys.stderr)
    for line in sorted(actual_lines - expected_lines):
        print(f"added: {line}", file=sys.stderr)
    print(
        "intentional API changes require: python3 scripts/check-public-api.py --write",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
