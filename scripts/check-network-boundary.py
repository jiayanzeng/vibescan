#!/usr/bin/env python3
"""Validate the exact workspace DAG and LocalStatic transport boundary."""

import json
import sys
from collections import defaultdict, deque


EXPECTED_WORKSPACE = {
    "vibescan-cli",
    "vibescan-core",
    "vibescan-git",
    "vibescan-registry",
    "vibescan-report",
    "vibescan-secrets",
    "vibescan-supabase",
    "vibescan-types",
}

ALLOWED_WORKSPACE_EDGES = {
    ("vibescan-cli", "vibescan-core"),
    ("vibescan-core", "vibescan-git"),
    ("vibescan-core", "vibescan-registry"),
    ("vibescan-core", "vibescan-report"),
    ("vibescan-core", "vibescan-secrets"),
    ("vibescan-core", "vibescan-supabase"),
    ("vibescan-core", "vibescan-types"),
    ("vibescan-git", "vibescan-types"),
    ("vibescan-registry", "vibescan-types"),
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
    "postgres",
    "tokio-postgres",
    "tokio-postgres-rustls",
}

PURE_LOCALSTATIC = {
    "vibescan-types",
    "vibescan-git",
    "vibescan-secrets",
    "vibescan-report",
}

ALLOWED_NETWORK_PARENTS = {"vibescan-supabase", "vibescan-registry"}


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


def transport_policy_errors(graphs):
    errors = []
    default_graph = graphs["default"]
    default_reachable = reachable(default_graph, default_graph["workspace_ids"])
    default_transports = transport_names_in(default_graph, default_reachable)
    if default_transports:
        details = []
        for transport in default_transports:
            roots = ", ".join(sorted(workspace_roots_reaching(default_graph, transport)))
            details.append(f"{transport} reached by {roots}")
        errors.append("default build contains transport crates: " + "; ".join(details))

    transports_by_graph = {"default": default_transports}
    for graph_name in ("network", "registry", "combined"):
        graph = graphs[graph_name]
        enabled_reachable = reachable(graph, graph["workspace_ids"])
        transports = transport_names_in(graph, enabled_reachable)
        transports_by_graph[graph_name] = transports
        if not transports:
            errors.append(
                f"{graph_name} build did not contain any known transport crate"
            )
        for transport in transports:
            parents = nearest_workspace_parents(graph, transport)
            if not parents or not parents.issubset(ALLOWED_NETWORK_PARENTS):
                errors.append(
                    f"{graph_name} feature transport parent violation for "
                    f"{transport}: nearest workspace parents were {sorted(parents)}, "
                    f"allowed parents are {sorted(ALLOWED_NETWORK_PARENTS)}"
                )

    for graph_name, graph in graphs.items():
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
    for graph_name in ("network", "combined"):
        transports = transports_by_graph[graph_name]
        if "rustls" not in transports:
            errors.append(
                f"rustls did not appear in {graph_name} build; rustls-tls may not be enabled"
            )
        for required in ("postgres", "tokio-postgres", "tokio-postgres-rustls"):
            if required not in transports:
                errors.append(f"{required} did not appear in {graph_name} build")

    for graph_name in ("registry", "combined"):
        transports = transports_by_graph[graph_name]
        for required in ("reqwest", "rustls"):
            if required not in transports:
                errors.append(f"{required} did not appear in {graph_name} build")

    registry_only = set(transports_by_graph["registry"])
    unexpected_supabase_transport = {
        "postgres",
        "tokio-postgres",
        "tokio-postgres-rustls",
    }.intersection(registry_only)
    if unexpected_supabase_transport:
        errors.append(
            "registry-only build contains Supabase Postgres transport: "
            + ", ".join(sorted(unexpected_supabase_transport))
        )

    network_registry_transports = transport_names_in(
        graphs["network"],
        reachable(
            graphs["network"],
            [graphs["network"]["ids_by_name"]["vibescan-registry"]],
        ),
    )
    if network_registry_transports:
        errors.append(
            "network-only build activates vibescan-registry transport: "
            + ", ".join(network_registry_transports)
        )

    registry_supabase_transports = transport_names_in(
        graphs["registry"],
        reachable(
            graphs["registry"],
            [graphs["registry"]["ids_by_name"]["vibescan-supabase"]],
        ),
    )
    if registry_supabase_transports:
        errors.append(
            "registry-only build activates vibescan-supabase transport: "
            + ", ".join(registry_supabase_transports)
        )

    for graph_name in ("network", "registry", "combined"):
        forbidden_tls = {"native-tls", "openssl", "openssl-sys"}.intersection(
            transports_by_graph[graph_name]
        )
        if forbidden_tls:
            errors.append(
                f"{graph_name} build contains forbidden non-rustls TLS crates: "
                + ", ".join(sorted(forbidden_tls))
            )
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

    registry_to_localstatic = allowed_details + [
        edge_detail("vibescan-registry", "vibescan-git")
    ]
    require_rejection(
        "registry to LocalStatic edge",
        workspace_policy_errors(set(EXPECTED_WORKSPACE), registry_to_localstatic),
        "forbidden workspace edge vibescan-registry -> vibescan-git",
    )

    default_graph = synthetic_graph({})
    network_graph = synthetic_graph(
        {
            "vibescan-supabase": [
                "postgres",
                "reqwest",
                "tokio-postgres-rustls",
            ],
            "postgres": ["tokio-postgres"],
            "reqwest": ["rustls"],
            "tokio-postgres-rustls": ["rustls", "tokio-postgres"],
        },
        {
            "postgres",
            "reqwest",
            "rustls",
            "tokio-postgres",
            "tokio-postgres-rustls",
        },
    )
    registry_graph = synthetic_graph(
        {
            "vibescan-registry": ["reqwest"],
            "reqwest": ["rustls"],
        },
        {"reqwest", "rustls"},
    )
    combined_graph = synthetic_graph(
        {
            "vibescan-supabase": [
                "postgres",
                "reqwest",
                "tokio-postgres-rustls",
            ],
            "vibescan-registry": ["reqwest"],
            "postgres": ["tokio-postgres"],
            "reqwest": ["rustls"],
            "tokio-postgres-rustls": ["rustls", "tokio-postgres"],
        },
        {
            "postgres",
            "reqwest",
            "rustls",
            "tokio-postgres",
            "tokio-postgres-rustls",
        },
    )
    graphs = {
        "default": default_graph,
        "network": network_graph,
        "registry": registry_graph,
        "combined": combined_graph,
    }
    if transport_policy_errors(graphs):
        raise AssertionError("allowed transport positive control was rejected")

    leaking_default = synthetic_graph(
        {"vibescan-git": ["reqwest"]},
        {"reqwest"},
    )
    require_rejection(
        "LocalStatic transport leakage",
        transport_policy_errors({**graphs, "default": leaking_default}),
        "default build contains transport crates",
    )

    leaking_registry = synthetic_graph(
        {
            "vibescan-registry": ["reqwest"],
            "vibescan-git": ["reqwest"],
            "reqwest": ["rustls"],
        },
        {"reqwest", "rustls"},
    )
    require_rejection(
        "registry LocalStatic transport leakage",
        transport_policy_errors({**graphs, "registry": leaking_registry}),
        "registry build lets vibescan-git reach transport crates",
    )

    unauthorized_parent = synthetic_graph(
        {
            "vibescan-core": ["reqwest"],
            "reqwest": ["rustls"],
        },
        {"reqwest", "rustls"},
    )
    require_rejection(
        "unauthorized transport parent",
        transport_policy_errors({**graphs, "registry": unauthorized_parent}),
        "registry feature transport parent violation for reqwest",
    )

    openssl_network = synthetic_graph(
        {
            "vibescan-supabase": [
                "openssl",
                "postgres",
                "reqwest",
                "tokio-postgres-rustls",
            ],
            "postgres": ["tokio-postgres"],
            "reqwest": ["rustls"],
            "tokio-postgres-rustls": ["rustls", "tokio-postgres"],
        },
        {
            "openssl",
            "postgres",
            "reqwest",
            "rustls",
            "tokio-postgres",
            "tokio-postgres-rustls",
        },
    )
    require_rejection(
        "OpenSSL transport",
        transport_policy_errors({**graphs, "network": openssl_network}),
        "network build contains forbidden non-rustls TLS crates",
    )


def validate(default_path, network_path, registry_path, combined_path):
    graphs = {
        "default": load_metadata(default_path),
        "network": load_metadata(network_path),
        "registry": load_metadata(registry_path),
        "combined": load_metadata(combined_path),
    }
    errors = []
    for graph_name, graph in graphs.items():
        errors.extend(
            f"{graph_name}: {error}"
            for error in workspace_policy_errors(
                graph["workspace_names"], declared_workspace_edges(graph)
            )
        )
    errors.extend(transport_policy_errors(graphs))
    return errors


def main():
    if sys.argv[1:] == ["--self-test"]:
        run_self_tests()
        print("network-boundary: synthetic positive and negative controls passed")
        return 0
    if len(sys.argv) != 5:
        print(
            "usage: check-network-boundary.py DEFAULT_METADATA NETWORK_METADATA "
            "REGISTRY_METADATA COMBINED_METADATA",
            file=sys.stderr,
        )
        return 2

    run_self_tests()
    errors = validate(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    if errors:
        for error in errors:
            print(f"network-boundary: {error}", file=sys.stderr)
        return 1

    print("network-boundary: exact eight-crate DAG holds across all dependency kinds")
    print("network-boundary: default build has no transport crates")
    print(
        "network-boundary: rustls transports are nearest-parented only by "
        "vibescan-supabase/vibescan-registry; OpenSSL/native-tls absent"
    )
    print(
        "network-boundary: pure LocalStatic crates are transport-free across "
        "default, network, registry, and combined metadata"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
