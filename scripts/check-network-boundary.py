#!/usr/bin/env python3
"""Validate the exact workspace DAG and LocalStatic transport boundary."""

import json
import sys
from collections import defaultdict, deque


EXPECTED_WORKSPACE = {
    "vibescan-cli",
    "vibescan-core",
    "vibescan-git",
    "vibescan-report",
    "vibescan-secrets",
    "vibescan-supabase",
    "vibescan-types",
}

ALLOWED_WORKSPACE_EDGES = {
    ("vibescan-cli", "vibescan-core"),
    ("vibescan-core", "vibescan-git"),
    ("vibescan-core", "vibescan-report"),
    ("vibescan-core", "vibescan-secrets"),
    ("vibescan-core", "vibescan-supabase"),
    ("vibescan-core", "vibescan-types"),
    ("vibescan-git", "vibescan-types"),
    ("vibescan-report", "vibescan-types"),
    ("vibescan-secrets", "vibescan-types"),
    ("vibescan-supabase", "vibescan-types"),
}

TRANSPORT_DENYLIST = {
    "reqwest",
    "hyper",
    "hyper-util",
    "h2",
    "ureq",
    "isahc",
    "curl",
    "tokio",
    "tokio-util",
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
        for dependency in node["deps"]:
            if any(kind["kind"] in (None, "normal") for kind in dependency["dep_kinds"]):
                normal_edges[node["id"]].append(dependency["pkg"])
    return {
        "metadata": metadata,
        "names_by_id": names_by_id,
        "ids_by_name": ids_by_name,
        "workspace_ids": workspace_ids,
        "workspace_names": workspace_names,
        "normal_edges": normal_edges,
    }


def declared_workspace_edges(graph):
    details = []
    workspace_names = graph["workspace_names"]
    for package in graph["metadata"]["packages"]:
        if package["id"] not in graph["workspace_ids"]:
            continue
        for dependency in package["dependencies"]:
            if dependency["name"] not in workspace_names:
                continue
            details.append(
                {
                    "parent": package["name"],
                    "child": dependency["name"],
                    "kind": dependency["kind"] or "normal",
                    "optional": dependency["optional"],
                    "target": dependency["target"],
                }
            )
    return details


def workspace_policy_errors(workspace_names, edge_details):
    errors = []
    missing_crates = EXPECTED_WORKSPACE - workspace_names
    unexpected_crates = workspace_names - EXPECTED_WORKSPACE
    if missing_crates:
        errors.append(f"workspace is missing crates: {sorted(missing_crates)}")
    if unexpected_crates:
        errors.append(f"workspace contains non-architecture crates: {sorted(unexpected_crates)}")

    actual_edges = {(edge["parent"], edge["child"]) for edge in edge_details}
    for edge in edge_details:
        pair = (edge["parent"], edge["child"])
        if pair in ALLOWED_WORKSPACE_EDGES:
            continue
        qualifiers = [edge["kind"]]
        if edge["optional"]:
            qualifiers.append("optional")
        if edge["target"]:
            qualifiers.append(f"target={edge['target']}")
        errors.append(
            f"forbidden workspace edge {edge['parent']} -> {edge['child']} "
            f"({', '.join(qualifiers)})"
        )

    missing_edges = ALLOWED_WORKSPACE_EDGES - actual_edges
    if missing_edges:
        errors.append(f"workspace is missing architecture edges: {sorted(missing_edges)}")
    return errors


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
    transport_ids = {
        package_id
        for package_id, name in graph["names_by_id"].items()
        if name == transport_name
    }
    return {
        graph["names_by_id"][workspace_id]
        for workspace_id in graph["workspace_ids"]
        if reachable(graph, [workspace_id]).intersection(transport_ids)
    }


def nearest_workspace_parents(graph, transport_name):
    reverse_edges = defaultdict(list)
    for parent, children in graph["normal_edges"].items():
        for child in children:
            reverse_edges[child].append(parent)

    transport_ids = {
        package_id
        for package_id, name in graph["names_by_id"].items()
        if name == transport_name
    }
    parents = set()
    queue = deque(transport_ids)
    seen = set(transport_ids)
    while queue:
        package_id = queue.popleft()
        for parent in reverse_edges.get(package_id, []):
            if parent in seen:
                continue
            seen.add(parent)
            if parent in graph["workspace_ids"]:
                parents.add(graph["names_by_id"][parent])
            else:
                queue.append(parent)
    return parents


def transport_policy_errors(default_graph, network_graph):
    errors = []
    default_reachable = reachable(default_graph, default_graph["workspace_ids"])
    default_transports = transport_names_in(default_graph, default_reachable)
    if default_transports:
        details = []
        for transport in default_transports:
            roots = ", ".join(sorted(workspace_roots_reaching(default_graph, transport)))
            details.append(f"{transport} reached by {roots}")
        errors.append("default build contains transport crates: " + "; ".join(details))

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
        for crate_name in sorted(PURE_LOCALSTATIC - missing):
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
    return errors


def edge_detail(parent, child, kind="normal", optional=False, target=None):
    return {
        "parent": parent,
        "child": child,
        "kind": kind,
        "optional": optional,
        "target": target,
    }


def synthetic_graph(edges, extra_names=()):
    names = EXPECTED_WORKSPACE | set(extra_names)
    return {
        "names_by_id": {name: name for name in names},
        "ids_by_name": {name: name for name in names},
        "workspace_ids": set(EXPECTED_WORKSPACE),
        "workspace_names": set(EXPECTED_WORKSPACE),
        "normal_edges": defaultdict(list, {parent: list(children) for parent, children in edges.items()}),
    }


def require_rejection(name, errors, expected_text):
    if not any(expected_text in error for error in errors):
        raise AssertionError(f"{name} negative control did not reject as expected: {errors}")


def run_self_tests():
    allowed_details = [edge_detail(parent, child) for parent, child in ALLOWED_WORKSPACE_EDGES]
    if workspace_policy_errors(set(EXPECTED_WORKSPACE), allowed_details):
        raise AssertionError("exact architecture DAG positive control was rejected")

    sibling_dev = allowed_details + [
        edge_detail("vibescan-git", "vibescan-secrets", kind="dev")
    ]
    require_rejection(
        "sibling dev-dependency",
        workspace_policy_errors(set(EXPECTED_WORKSPACE), sibling_dev),
        "forbidden workspace edge vibescan-git -> vibescan-secrets (dev)",
    )

    unauthorized_direct = allowed_details + [
        edge_detail(
            "vibescan-cli",
            "vibescan-types",
            optional=True,
            target="cfg(target_os = \"windows\")",
        )
    ]
    require_rejection(
        "unauthorized direct edge",
        workspace_policy_errors(set(EXPECTED_WORKSPACE), unauthorized_direct),
        "forbidden workspace edge vibescan-cli -> vibescan-types "
        "(normal, optional, target=cfg(target_os = \"windows\"))",
    )

    default_graph = synthetic_graph({})
    network_graph = synthetic_graph(
        {
            "vibescan-supabase": ["reqwest"],
            "reqwest": ["rustls"],
        },
        {"reqwest", "rustls"},
    )
    if transport_policy_errors(default_graph, network_graph):
        raise AssertionError("allowed transport positive control was rejected")

    leaking_default = synthetic_graph(
        {"vibescan-git": ["reqwest"]},
        {"reqwest"},
    )
    require_rejection(
        "LocalStatic transport leakage",
        transport_policy_errors(leaking_default, network_graph),
        "default build contains transport crates",
    )


def validate(default_path, network_path):
    default_graph = load_metadata(default_path)
    network_graph = load_metadata(network_path)
    errors = []
    errors.extend(
        f"default: {error}"
        for error in workspace_policy_errors(
            default_graph["workspace_names"], declared_workspace_edges(default_graph)
        )
    )
    errors.extend(
        f"network: {error}"
        for error in workspace_policy_errors(
            network_graph["workspace_names"], declared_workspace_edges(network_graph)
        )
    )
    errors.extend(transport_policy_errors(default_graph, network_graph))
    return errors


def main():
    if sys.argv[1:] == ["--self-test"]:
        run_self_tests()
        print("network-boundary: synthetic positive and negative controls passed")
        return 0
    if len(sys.argv) != 3:
        print(
            "usage: check-network-boundary.py DEFAULT_METADATA NETWORK_METADATA",
            file=sys.stderr,
        )
        return 2

    run_self_tests()
    errors = validate(sys.argv[1], sys.argv[2])
    if errors:
        for error in errors:
            print(f"network-boundary: {error}", file=sys.stderr)
        return 1

    print("network-boundary: exact seven-crate DAG holds across all dependency kinds")
    print("network-boundary: default build has no transport crates")
    print("network-boundary: network build transport is nearest-parented by vibescan-supabase")
    print("network-boundary: pure LocalStatic crates are transport-free in default and network metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
