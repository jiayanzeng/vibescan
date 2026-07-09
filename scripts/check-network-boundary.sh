#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

default_metadata="$(mktemp)"
network_metadata="$(mktemp)"
metadata_error="$(mktemp)"
trap 'rm -f "$default_metadata" "$network_metadata" "$metadata_error"' EXIT

host="$(rustc -vV | sed -n 's/^host: //p')"

metadata() {
  local output="$1"
  shift

  if cargo metadata --format-version 1 --locked --filter-platform "$host" "$@" > "$output" 2> "$metadata_error"; then
    return 0
  fi

  if grep -q "because --locked was passed" "$metadata_error"; then
    echo "network-boundary: locked metadata unavailable; retrying offline for boundary diagnostics" >&2
    cargo metadata --format-version 1 --offline --filter-platform "$host" "$@" > "$output"
    return 0
  fi

  cat "$metadata_error" >&2
  return 1
}

metadata "$default_metadata"
metadata "$network_metadata" --features network

python3 - "$default_metadata" "$network_metadata" <<'PY'
import json
import sys
from collections import defaultdict, deque

default_path, network_path = sys.argv[1:3]

# Exact resolved package names only. A package named "not-reqwest-helper" does
# not match "reqwest"; the comparison is against Cargo's Package.name field.
TRANSPORT_DENYLIST = {
    # HTTP clients / transports.
    "reqwest",
    "hyper",
    "hyper-util",
    "h2",
    "ureq",
    "isahc",
    "curl",
    # Async runtime/socket plumbing commonly pulled in by HTTP stacks.
    "tokio",
    "tokio-util",
    # TLS stacks and bindings. rustls is allowed only under the network feature
    # and only when nearest-parented by vibescan-supabase.
    "rustls",
    "tokio-rustls",
    "native-tls",
    "openssl",
    "openssl-sys",
}

PURE_LOCALSTATIC = {
    "vibescan-types",
    "vibescan-git",
    "vibescan-secrets",
    "vibescan-report",
}

ALLOWED_NETWORK_PARENT = "vibescan-supabase"


def load_metadata(path):
    with open(path, encoding="utf-8") as handle:
        metadata = json.load(handle)
    names_by_id = {package["id"]: package["name"] for package in metadata["packages"]}
    ids_by_name = {}
    for package_id, name in names_by_id.items():
        ids_by_name.setdefault(name, package_id)
    workspace_ids = set(metadata["workspace_members"])
    workspace_names = {names_by_id[package_id] for package_id in workspace_ids}
    normal_edges = defaultdict(list)
    for node in metadata["resolve"]["nodes"]:
        parent = node["id"]
        for dep in node["deps"]:
            if any(kind["kind"] in (None, "normal") for kind in dep["dep_kinds"]):
                normal_edges[parent].append(dep["pkg"])
    return {
        "names_by_id": names_by_id,
        "ids_by_name": ids_by_name,
        "workspace_ids": workspace_ids,
        "workspace_names": workspace_names,
        "normal_edges": normal_edges,
    }


def reachable(graph, roots):
    seen = set()
    stack = list(roots)
    while stack:
        package_id = stack.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        stack.extend(graph["normal_edges"].get(package_id, []))
    return seen


def transport_names_in(graph, package_ids):
    return sorted(
        {
            graph["names_by_id"][package_id]
            for package_id in package_ids
            if graph["names_by_id"][package_id] in TRANSPORT_DENYLIST
        }
    )


def workspace_roots_reaching(graph, transport_name):
    transport_ids = [
        package_id
        for package_id, name in graph["names_by_id"].items()
        if name == transport_name
    ]
    roots = set()
    for workspace_id in graph["workspace_ids"]:
        if reachable(graph, [workspace_id]).intersection(transport_ids):
            roots.add(graph["names_by_id"][workspace_id])
    return roots


def nearest_workspace_parents(graph, transport_name):
    reverse_edges = defaultdict(list)
    for parent, children in graph["normal_edges"].items():
        for child in children:
            reverse_edges[child].append(parent)

    transport_ids = [
        package_id
        for package_id, name in graph["names_by_id"].items()
        if name == transport_name
    ]
    parents = set()
    queue = deque(transport_ids)
    seen = set(transport_ids)
    while queue:
        package_id = queue.popleft()
        for parent in reverse_edges.get(package_id, []):
            if parent in seen:
                continue
            seen.add(parent)
            parent_name = graph["names_by_id"][parent]
            if parent in graph["workspace_ids"]:
                parents.add(parent_name)
                continue
            queue.append(parent)
    return parents


default_graph = load_metadata(default_path)
errors = []
default_reachable = reachable(default_graph, default_graph["workspace_ids"])
default_transports = transport_names_in(default_graph, default_reachable)
if default_transports:
    details = []
    for transport in default_transports:
        roots = ", ".join(sorted(workspace_roots_reaching(default_graph, transport)))
        details.append(f"{transport} reached by {roots}")
    errors.append("default build contains transport crates: " + "; ".join(details))

network_graph = load_metadata(network_path)
network_reachable = reachable(network_graph, network_graph["workspace_ids"])
network_transports = transport_names_in(network_graph, network_reachable)
if not network_transports:
    errors.append("network build did not contain any known transport crate; expected reqwest/rustls")

for transport in network_transports:
    parents = nearest_workspace_parents(network_graph, transport)
    if parents != {ALLOWED_NETWORK_PARENT}:
        errors.append(
            "network feature transport parent violation for "
            f"{transport}: nearest workspace parents were {sorted(parents)}, "
            f"expected [{ALLOWED_NETWORK_PARENT!r}]"
        )

for graph_name, graph in (("default", default_graph), ("network", network_graph)):
    missing = PURE_LOCALSTATIC - graph["workspace_names"]
    if missing:
        errors.append(f"{graph_name} metadata missing workspace crates: {sorted(missing)}")
    for crate_name in sorted(PURE_LOCALSTATIC):
        crate_id = graph["ids_by_name"][crate_name]
        transports = transport_names_in(graph, reachable(graph, [crate_id]))
        if transports:
            errors.append(
                f"{graph_name} build lets {crate_name} reach transport crates: "
                + ", ".join(transports)
            )

if "rustls" in default_transports:
    errors.append("rustls appeared in default build")
if "rustls" not in network_transports:
    errors.append("rustls did not appear in network build; rustls-tls may not be enabled")

if errors:
    for error in errors:
        print(f"network-boundary: {error}", file=sys.stderr)
    sys.exit(1)

print("network-boundary: default build has no transport crates")
print("network-boundary: network build transport is nearest-parented by vibescan-supabase")
print("network-boundary: pure LocalStatic crates are transport-free in default and network metadata")
PY
