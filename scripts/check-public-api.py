#!/usr/bin/env python3
"""Check the committed, deterministic crate-root public API inventory.

The inventory mirrors Track K's rustdoc-path contract for the seven library
crates: local named items reachable at each crate root, enum variants, public
fields of public structs, public inherent items, and trait implementations on
public local types. ``vibescan-cli`` is intentionally excluded because it is a
binary crate and has no library API surface.

The derivation is offline, deterministic, and source-text based; it needs no
nightly rustdoc, captured Track K artifact, or previously built target/. Its
explicit limits are:

* macro-generated items, including derive-generated trait implementations,
  are invisible because they do not exist as source declarations;
* cfg predicates are not evaluated, so the inventory is the textual union of
  declarations across feature graphs and cannot represent feature-dependent
  visibility separately;
* external re-exports are measured in their defining scoped crate, not repeated
  in every consumer, and renamed re-exports are not resolved;
* complex or blanket impl self types that do not resolve to one directly
  inventoried local public type are omitted rather than guessed; and
* enum variant payload fields and items declared inside public traits are not
  separate records; enum variant names and trait names remain recorded.
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
    "vibescan-types",
)
DEFAULT_INVENTORY = Path("docs/public-api-inventory.txt")


@dataclass(frozen=True)
class Item:
    kind: str
    name: str
    variants: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class InherentItem:
    kind: str
    name: str


@dataclass(frozen=True)
class TraitImpl:
    self_type: str
    trait: str


@dataclass(frozen=True)
class ModuleSurface:
    items: dict[str, Item]
    inherent_items: dict[str, tuple[InherentItem, ...]]
    trait_impls: tuple[TraitImpl, ...]


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
    return matching_delimiter(masked, opening, "{", "}")


def matching_delimiter(masked: str, opening: int, start: str, end: str) -> int:
    if masked[opening] != start:
        raise ValueError(f"expected {start!r} at offset {opening}")
    depth = 1
    for position in range(opening + 1, len(masked)):
        if masked[position] == start:
            depth += 1
        elif masked[position] == end:
            depth -= 1
            if depth == 0:
                return position
    raise ValueError(f"unbalanced {start}{end} delimiters")


def split_top_level(body: str) -> list[str]:
    """Split a Rust declaration list at top-level commas."""
    segments: list[str] = []
    start = 0
    paren = bracket = brace = angle = 0
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
        elif character == "<":
            angle += 1
        elif character == ">" and angle:
            angle -= 1
        elif character == "," and paren == bracket == brace == angle == 0:
            segments.append(body[start:index])
            start = index + 1
    segments.append(body[start:])
    return segments


def without_leading_attributes(declaration: str) -> str:
    remaining = declaration.lstrip()
    while remaining.startswith("#"):
        opening = remaining.find("[")
        if opening == -1:
            break
        closing = matching_delimiter(remaining, opening, "[", "]")
        remaining = remaining[closing + 1 :].lstrip()
    return remaining


def enum_variants(masked: str, opening: int, closing: int) -> tuple[str, ...]:
    body = masked[opening + 1 : closing]
    variants = []
    for segment in split_top_level(body):
        match = re.match(
            r"([A-Za-z_][A-Za-z0-9_]*)\b",
            without_leading_attributes(segment),
        )
        if match:
            variants.append(match.group(1))
    return tuple(variants)


def struct_fields(masked: str, declaration_end: int) -> tuple[str, ...]:
    """Return public named or positional fields from one public struct."""
    cursor = declaration_end
    angle = 0
    while cursor < len(masked):
        character = masked[cursor]
        if character == "<":
            angle += 1
        elif character == ">" and angle:
            angle -= 1
        elif not angle and character in "{(;":
            if character == ";":
                return ()
            closing = matching_delimiter(
                masked,
                cursor,
                character,
                "}" if character == "{" else ")",
            )
            fields: list[str] = []
            for index, segment in enumerate(split_top_level(masked[cursor + 1 : closing])):
                declaration = without_leading_attributes(segment)
                if character == "{":
                    match = re.match(
                        r"pub\s+(?!\()([A-Za-z_][A-Za-z0-9_]*)\s*:",
                        declaration,
                    )
                    if match:
                        fields.append(match.group(1))
                elif re.match(r"pub\s+(?!\()", declaration):
                    fields.append(str(index))
            return tuple(fields)
        cursor += 1
    raise ValueError("struct declaration has no body or terminator")


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
        fields: tuple[str, ...] = ()
        if raw_kind == "enum":
            opening = masked.find("{", match.end())
            if opening == -1:
                raise ValueError(f"{path}: enum {name} has no body")
            variants = enum_variants(masked, opening, matching_brace(masked, opening))
        elif raw_kind == "struct":
            fields = struct_fields(masked, match.end())
        items[name] = Item(kinds[raw_kind], name, variants, fields)
    return items


def normalized_rust_path(text: str) -> str:
    text = re.sub(r"\s*::\s*", "::", text.strip())
    text = re.sub(r"\s*([<>,&])\s*", r"\1", text)
    return re.sub(r"\s+", " ", text)


def strip_impl_generics(header: str) -> str:
    header = header.strip()
    if not header.startswith("<"):
        return header
    closing = matching_delimiter(header, 0, "<", ">")
    return header[closing + 1 :].strip()


def split_impl_header(header: str) -> tuple[str | None, str]:
    """Return optional trait and self-type text from an impl header."""
    header = strip_impl_generics(header)
    header = re.split(r"\bwhere\b", header, maxsplit=1)[0].strip()
    angle = paren = bracket = 0
    for match in re.finditer(r"\bfor\b", header):
        for character in header[: match.start()]:
            if character == "<":
                angle += 1
            elif character == ">" and angle:
                angle -= 1
            elif character == "(":
                paren += 1
            elif character == ")":
                paren -= 1
            elif character == "[":
                bracket += 1
            elif character == "]":
                bracket -= 1
        if angle == paren == bracket == 0:
            return (
                normalized_rust_path(header[: match.start()]),
                normalized_rust_path(header[match.end() :]),
            )
        angle = paren = bracket = 0
    return None, normalized_rust_path(header)


def nominal_self_type(self_type: str) -> str | None:
    """Resolve a direct local nominal impl self type without guessing."""
    candidate = self_type.strip()
    while candidate.startswith("&"):
        candidate = candidate[1:].lstrip()
        if candidate.startswith("mut "):
            candidate = candidate[4:].lstrip()
    candidate = re.sub(r"<.*>$", "", candidate).strip()
    match = re.fullmatch(
        r"(?:(?:self|super|crate|[A-Za-z_][A-Za-z0-9_]*)::)*"
        r"([A-Za-z_][A-Za-z0-9_]*)",
        candidate,
    )
    return match.group(1) if match else None


def inherent_items(masked: str, opening: int, closing: int) -> tuple[InherentItem, ...]:
    body = masked[opening + 1 : closing]
    depths = brace_depths(body)
    declaration = re.compile(
        r"(?m)^\s*pub\s+(?!\()"
        r"(?:(?P<qualifiers>(?:(?:const|async|unsafe)\s+)*)fn\s+"
        r"(?P<function>[A-Za-z_][A-Za-z0-9_]*)\b|"
        r"(?P<kind>const|type)\s+(?P<item>[A-Za-z_][A-Za-z0-9_]*)\b)"
    )
    members: list[InherentItem] = []
    for match in declaration.finditer(body):
        if depths[match.start()] != 0:
            continue
        if match.group("function"):
            name = match.group("function")
            parameters_open = body.find("(", match.end())
            if parameters_open == -1:
                raise ValueError(f"public function {name} has no parameter list")
            parameters_close = matching_delimiter(body, parameters_open, "(", ")")
            parameters = body[parameters_open + 1 : parameters_close]
            kind = "method" if re.search(r"\bself\b", parameters) else "associated_function"
        else:
            name = match.group("item")
            kind = "associated_constant" if match.group("kind") == "const" else "associated_type"
        members.append(InherentItem(kind, name))
    return tuple(members)


def module_surface(path: Path) -> ModuleSurface:
    source = path.read_text()
    masked = mask_non_code(source)
    depths = brace_depths(masked)
    items = module_items(path)
    inherent: dict[str, list[InherentItem]] = {}
    trait_impls: list[TraitImpl] = []
    for match in re.finditer(r"(?m)^\s*impl\b", masked):
        if depths[match.start()] != 0:
            continue
        opening = masked.find("{", match.end())
        if opening == -1:
            raise ValueError(f"{path}: impl has no body")
        closing = matching_brace(masked, opening)
        trait, self_type = split_impl_header(masked[match.end() : opening])
        self_name = nominal_self_type(self_type)
        if self_name is None or self_name not in items:
            continue
        if items[self_name].kind not in {"enum", "struct", "type_alias"}:
            continue
        if trait is None:
            inherent.setdefault(self_name, []).extend(inherent_items(masked, opening, closing))
        else:
            trait_impls.append(TraitImpl(self_name, trait))
    return ModuleSurface(
        items,
        {name: tuple(members) for name, members in inherent.items()},
        tuple(trait_impls),
    )


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
    modules = {"": module_surface(lib)}
    for module in local_modules:
        module_path = src / f"{module}.rs"
        if module_path.is_file():
            modules[module] = module_surface(module_path)

    exported = {name: (item, modules[""]) for name, item in modules[""].items.items()}
    for selection in top_level_reexports(lib):
        module, names = selected_names(selection)
        if module not in modules:
            # Track K's local-item inventory deliberately excludes external
            # re-exports such as vibescan_types::Severity.
            continue
        source = modules[module]
        chosen = (
            source.items
            if names is None
            else {name: source.items[name] for name in names}
        )
        exported.update({name: (item, source) for name, item in chosen.items()})

    lines = [f"module\t{crate_name}"]
    for item, source in exported.values():
        lines.append(f"{item.kind}\t{crate_name}::{item.name}")
        lines.extend(
            f"variant\t{crate_name}::{item.name}::{variant}" for variant in item.variants
        )
        lines.extend(
            f"field\t{crate_name}::{item.name}::{field}" for field in item.fields
        )
        lines.extend(
            f"{member.kind}\t{crate_name}::{item.name}::{member.name}"
            for member in source.inherent_items.get(item.name, ())
        )
        lines.extend(
            f"trait_impl\t{crate_name}::{item.name}\t{implementation.trait}"
            for implementation in source.trait_impls
            if implementation.self_type == item.name
        )
    return lines


def derive(root: Path) -> str:
    lines = []
    for crate in SCOPED_CRATES:
        lines.extend(crate_inventory(root, crate))
    return "\n".join(sorted(lines)) + "\n"


def self_test() -> None:
    sample = '''
pub struct Public {
    pub visible_field: usize,
    hidden_field: usize,
}
pub struct Tuple(pub usize, usize, pub(crate) usize, pub String);
struct Private { pub invisible_field: usize }
pub enum Example { First, Second { value: usize }, Third(String) }
pub(crate) fn hidden() {}
pub fn visible() { let _ = "}"; }
trait ExampleTrait {}
impl Public {
    pub fn method(&self) {}
    pub fn associated() -> Self { todo!() }
    pub const LIMIT: usize = 1;
    pub type Output = usize;
    fn private_method(&self) {}
}
impl ExampleTrait for Public {}
impl ExampleTrait for Private {}
impl Private { pub fn invisible_method(&self) {} }
'''
    with tempfile.TemporaryDirectory(prefix="vibescan-public-api-self-test-") as temp_dir:
        temporary = Path(temp_dir) / "lib.rs"
        temporary.write_text(sample)
        assert module_items(temporary) == {
            "Public": Item("struct", "Public", (), ("visible_field",)),
            "Tuple": Item("struct", "Tuple", (), ("0", "3")),
            "Example": Item("enum", "Example", ("First", "Second", "Third"), ()),
            "visible": Item("function", "visible"),
        }
        surface = module_surface(temporary)
        assert surface.inherent_items == {
            "Public": (
                InherentItem("method", "method"),
                InherentItem("associated_function", "associated"),
                InherentItem("associated_constant", "LIMIT"),
                InherentItem("associated_type", "Output"),
            )
        }
        assert surface.trait_impls == (TraitImpl("Public", "ExampleTrait"),)


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
