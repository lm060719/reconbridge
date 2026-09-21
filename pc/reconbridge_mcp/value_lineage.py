"""跨方法 Value Lineage 图的轻量构建与解析工具。"""
from __future__ import annotations

import hashlib
from collections import deque
from typing import Any


TERMINAL_KINDS = {
    "preferences",
    "intent_or_state",
    "database_or_cache",
    "network_or_repository",
    "literal_or_constant",
}


def _hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def new_graph() -> dict[str, Any]:
    return {
        "nodes": {},
        "edges": [],
        "ambiguities": [],
        "unresolved_calls": [],
    }


def add_node(
    graph: dict[str, Any],
    node_type: str,
    key: str,
    label: str,
    **attrs: Any,
) -> str:
    node_id = f"{node_type}:{_hash(key)}"
    node = graph["nodes"].get(node_id)
    if node is None:
        node = {
            "id": node_id,
            "type": node_type,
            "label": label,
        }
        graph["nodes"][node_id] = node
    for name, value in attrs.items():
        if value not in (None, "", [], {}):
            node[name] = value
    return node_id


def add_edge(
    graph: dict[str, Any],
    source: str,
    target: str,
    relation: str,
    **attrs: Any,
) -> None:
    key = (source, target, relation)
    for edge in graph["edges"]:
        if (
            edge.get("source"),
            edge.get("target"),
            edge.get("relation"),
        ) == key:
            for name, value in attrs.items():
                if value not in (None, "", [], {}):
                    edge[name] = value
            return
    edge = {
        "source": source,
        "target": target,
        "relation": relation,
    }
    for name, value in attrs.items():
        if value not in (None, "", [], {}):
            edge[name] = value
    graph["edges"].append(edge)


def simple_call_name(call_expression: str) -> str:
    value = (call_expression or "").strip()
    if not value:
        return ""
    return value.rsplit(".", 1)[-1]


def resolve_call(
    call_expression: str,
    callees: list[dict[str, Any]],
) -> dict[str, Any]:
    """按简单方法名把源码调用与 DEX callee 对齐；歧义时不擅自选类。"""
    method_name = simple_call_name(call_expression)
    matches = [
        dict(item)
        for item in callees
        if str(item.get("method", "")) == method_name
    ]
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in matches:
        key = (
            str(item.get("class", "")),
            str(item.get("method", "")),
            str(item.get("descriptor", "")),
        )
        unique[key] = item
    matches = list(unique.values())

    return {
        "expression": call_expression,
        "method": method_name,
        "resolved": matches[0] if len(matches) == 1 else None,
        "ambiguous": len(matches) > 1,
        "candidates": matches,
    }


def terminal_hints(source_hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        dict(item)
        for item in source_hints
        if str(item.get("kind", "")) in TERMINAL_KINDS
    ]
    rows.sort(key=lambda item: -float(item.get("confidence", 0) or 0))
    return rows


def finalize(
    graph: dict[str, Any],
    sink_id: str,
    max_paths: int = 24,
) -> dict[str, Any]:
    """输出 nodes/edges 和从来源节点指向 sink 的代表路径。"""
    nodes = graph["nodes"]
    edges = graph["edges"]
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    incoming: dict[str, int] = {node_id: 0 for node_id in nodes}

    for edge in edges:
        source = str(edge["source"])
        target = str(edge["target"])
        adjacency.setdefault(source, []).append((target, edge))
        incoming[target] = incoming.get(target, 0) + 1

    origins = [
        node_id
        for node_id, node in nodes.items()
        if node.get("type") == "origin"
        or incoming.get(node_id, 0) == 0
    ]

    paths: list[dict[str, Any]] = []
    for origin in origins:
        queue = deque([(origin, [origin], [])])
        seen_states: set[tuple[str, tuple[str, ...]]] = set()
        while queue and len(paths) < max_paths:
            current, node_path, relations = queue.popleft()
            if current == sink_id:
                path_nodes = [nodes[node_id] for node_id in node_path]
                paths.append(
                    {
                        "length": max(0, len(path_nodes) - 1),
                        "nodes": path_nodes,
                        "relations": relations,
                        "text": " -> ".join(
                            str(item.get("label", ""))
                            for item in path_nodes
                        ),
                    }
                )
                continue

            for target, edge in adjacency.get(current, []):
                if target in node_path:
                    continue
                next_path = [*node_path, target]
                state = (target, tuple(next_path[-8:]))
                if state in seen_states:
                    continue
                seen_states.add(state)
                queue.append(
                    (
                        target,
                        next_path,
                        [*relations, str(edge.get("relation", ""))],
                    )
                )

    paths.sort(key=lambda item: (-item["length"], item["text"]))
    return {
        "ok": True,
        "sink_id": sink_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": list(nodes.values()),
        "edges": edges,
        "origin_paths": paths[:max_paths],
        "ambiguities": graph.get("ambiguities", []),
        "unresolved_calls": graph.get("unresolved_calls", []),
    }
