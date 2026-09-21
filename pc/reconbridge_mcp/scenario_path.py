"""调用图场景采集与差异分析纯逻辑。

两次场景使用同一张静态调用图和同一组方法 Hook 后，可以直接比较真实命中节点、
静态边覆盖、主线程顺序、首次分叉与共享边耗时差异。
"""
from __future__ import annotations

import hashlib
import json
from bisect import bisect_left
from typing import Any

from . import runtime_path


def graph_fingerprint(call_graph: dict[str, Any]) -> str:
    nodes = sorted(
        (
            runtime_path.normalize_class_name(str(node.get("class", ""))),
            str(node.get("method", "")),
            str(node.get("descriptor", "")),
        )
        for node in call_graph.get("nodes") or []
    )
    edges = sorted(
        (int(edge.get("source", -1)), int(edge.get("target", -1)))
        for edge in call_graph.get("edges") or []
    )
    raw = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def graph_methods(
    call_graph: dict[str, Any],
    max_hooks: int = 24,
    include_external: bool = False,
) -> list[dict[str, Any]]:
    """从调用图提取唯一 Java 方法，默认不 Hook 外部框架节点。"""
    max_hooks = max(1, min(int(max_hooks), 48))
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    nodes = sorted(
        call_graph.get("nodes") or [],
        key=lambda node: (
            0 if node.get("is_target") else 1,
            abs(int(node.get("upstream_distance") or 0))
            + abs(int(node.get("downstream_distance") or 0)),
            int(node.get("id", 0)),
        ),
    )

    for node in nodes:
        method = str(node.get("method", ""))
        class_name = runtime_path.normalize_class_name(str(node.get("class", "")))
        if not class_name or not method or method == "<clinit>":
            continue
        if node.get("external") and not include_external:
            continue

        key = (class_name, method)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "node_id": int(node.get("id", -1)),
                "class": class_name,
                "method": method,
                "descriptor": str(node.get("descriptor", "")),
                "is_target": bool(node.get("is_target")),
                "external": bool(node.get("external")),
            }
        )
        if len(result) >= max_hooks:
            break
    return result


def hook_fingerprint(methods: list[dict[str, Any]]) -> str:
    rows = sorted(
        (
            int(item.get("node_id", -1)),
            runtime_path.normalize_class_name(str(item.get("class", ""))),
            str(item.get("method", "")),
        )
        for item in methods
    )
    raw = json.dumps(rows, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(event: dict[str, Any]) -> tuple[float, int]:
        try:
            ts = float(event.get("ts", 0) or 0)
        except (TypeError, ValueError):
            ts = 0.0
        try:
            seq = int(event.get("seq", 0) or 0)
        except (TypeError, ValueError):
            seq = 0
        return ts, seq

    return sorted(events, key=key)


def _event_meta(
    event: dict[str, Any],
    hook_map: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    hook_id = str(event.get("hook_id", ""))
    if hook_id in hook_map:
        return hook_map[hook_id]

    event_key = (
        runtime_path.normalize_class_name(str(event.get("class", ""))),
        str(event.get("method", "")),
    )
    for meta in hook_map.values():
        if (meta["class"], meta["method"]) == event_key:
            return meta
    return None


def _method_label(meta: dict[str, Any]) -> str:
    return f"{meta['class']}.{meta['method']}"


def analyze_graph_scenario(
    call_graph: dict[str, Any],
    events: list[dict[str, Any]],
    hook_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """分析一次整图 Hook 采集，得到真实节点/边和各线程方法顺序。"""
    ordered = _sort_events(events)
    timeline: list[dict[str, Any]] = []
    method_hits: dict[int, int] = {}
    threads: dict[Any, list[dict[str, Any]]] = {}

    for event in ordered:
        meta = _event_meta(event, hook_map)
        if meta is None:
            continue
        node_id = int(meta["node_id"])
        method_hits[node_id] = method_hits.get(node_id, 0) + 1
        item = {
            "ts": float(event.get("ts", 0) or 0),
            "seq": event.get("seq"),
            "tid": event.get("tid"),
            "node_id": node_id,
            "class": meta["class"],
            "method": meta["method"],
            "label": _method_label(meta),
        }
        timeline.append(item)
        threads.setdefault(item["tid"], []).append(item)

    node_by_id = {
        int(node["id"]): node
        for node in call_graph.get("nodes") or []
    }
    static_edges = {
        (int(edge.get("source", -1)), int(edge.get("target", -1))): edge
        for edge in call_graph.get("edges") or []
    }

    # 按 node/tid 建时间索引，然后逐条静态边判断同线程是否按序出现。
    # 这样一个 source 同时调用多个下游时不会因为“只取第一个”而漏边。
    times_by_node_tid: dict[tuple[int, Any], list[float]] = {}
    for tid, items in threads.items():
        for item in items:
            times_by_node_tid.setdefault(
                (int(item["node_id"]), tid),
                [],
            ).append(float(item["ts"]))

    observed_edges: dict[tuple[int, int], dict[str, Any]] = {}
    tids = list(threads)
    for edge_key in static_edges:
        source_id, target_id = edge_key
        best: dict[str, Any] | None = None
        for tid in tids:
            source_times = times_by_node_tid.get((source_id, tid), [])
            target_times = times_by_node_tid.get((target_id, tid), [])
            if not source_times or not target_times:
                continue

            for source_ts in source_times:
                pos = bisect_left(target_times, source_ts)
                if pos >= len(target_times):
                    continue
                target_ts = target_times[pos]
                delta = target_ts - source_ts
                if best is None or delta < best["delta_ms"]:
                    best = {
                        "source": source_id,
                        "target": target_id,
                        "tid": tid,
                        "delta_ms": round(delta, 3),
                    }
        if best is not None:
            observed_edges[edge_key] = best

    # 选择“覆盖静态图节点最多”的线程作为主业务线程；同覆盖率时选事件更多的。
    primary_tid = None
    primary_items: list[dict[str, Any]] = []
    best_score = (-1, -1)
    for tid, items in threads.items():
        distinct = len({int(item["node_id"]) for item in items})
        score = (distinct, len(items))
        if score > best_score:
            best_score = score
            primary_tid = tid
            primary_items = items

    # 连续重复命中压缩，但保留后续再次回到同一方法的循环。
    sequence: list[dict[str, Any]] = []
    last_node = None
    for item in primary_items:
        if int(item["node_id"]) == last_node:
            continue
        sequence.append(item)
        last_node = int(item["node_id"])

    observed_node_ids = set(method_hits)
    hooked_node_ids = {int(meta["node_id"]) for meta in hook_map.values()}
    edge_keys = set(observed_edges)

    return {
        "event_count": len(timeline),
        "hooked_nodes": len(hooked_node_ids),
        "observed_nodes": len(observed_node_ids),
        "node_coverage": (
            round(len(observed_node_ids) / len(hooked_node_ids), 3)
            if hooked_node_ids
            else 0.0
        ),
        "observed_edges": len(edge_keys),
        "primary_tid": primary_tid,
        "method_hits": [
            {
                "node_id": node_id,
                "hits": hits,
                "class": runtime_path.normalize_class_name(
                    str(node_by_id.get(node_id, {}).get("class", ""))
                ),
                "method": str(node_by_id.get(node_id, {}).get("method", "")),
            }
            for node_id, hits in sorted(method_hits.items())
        ],
        "edges": [
            {
                **value,
                "source_label": (
                    f"{runtime_path.normalize_class_name(str(node_by_id.get(key[0], {}).get('class', '')))}."
                    f"{node_by_id.get(key[0], {}).get('method', '')}"
                ),
                "target_label": (
                    f"{runtime_path.normalize_class_name(str(node_by_id.get(key[1], {}).get('class', '')))}."
                    f"{node_by_id.get(key[1], {}).get('method', '')}"
                ),
            }
            for key, value in sorted(observed_edges.items())
        ],
        "primary_sequence": [
            {
                "node_id": int(item["node_id"]),
                "class": item["class"],
                "method": item["method"],
                "label": item["label"],
                "ts": item["ts"],
            }
            for item in sequence[:200]
        ],
        "timeline": timeline[:400],
    }


def _sequence_labels(scenario: dict[str, Any]) -> list[str]:
    return [
        str(item.get("label", ""))
        for item in scenario.get("analysis", {}).get("primary_sequence", [])
        if item.get("label")
    ]


def _longest_common_prefix(a: list[str], b: list[str]) -> list[str]:
    out: list[str] = []
    for left, right in zip(a, b):
        if left != right:
            break
        out.append(left)
    return out


def diff_graph_scenarios(
    scenario_a: dict[str, Any],
    scenario_b: dict[str, Any],
) -> dict[str, Any]:
    """对比同一静态调用图上的两次真实执行场景。"""
    fp_a = str(scenario_a.get("graph_fingerprint", ""))
    fp_b = str(scenario_b.get("graph_fingerprint", ""))
    hook_fp_a = str(scenario_a.get("hook_fingerprint", ""))
    hook_fp_b = str(scenario_b.get("hook_fingerprint", ""))
    comparable = bool(
        fp_a
        and fp_a == fp_b
        and hook_fp_a
        and hook_fp_a == hook_fp_b
    )

    analysis_a = scenario_a.get("analysis") or {}
    analysis_b = scenario_b.get("analysis") or {}

    hits_a = {
        int(item["node_id"]): item
        for item in analysis_a.get("method_hits") or []
    }
    hits_b = {
        int(item["node_id"]): item
        for item in analysis_b.get("method_hits") or []
    }
    nodes_a = set(hits_a)
    nodes_b = set(hits_b)

    edges_a = {
        (int(item["source"]), int(item["target"])): item
        for item in analysis_a.get("edges") or []
    }
    edges_b = {
        (int(item["source"]), int(item["target"])): item
        for item in analysis_b.get("edges") or []
    }

    seq_a = _sequence_labels(scenario_a)
    seq_b = _sequence_labels(scenario_b)
    common_prefix = _longest_common_prefix(seq_a, seq_b)
    divergence_index = len(common_prefix)

    def node_payload(node_id: int, source: dict[int, dict[str, Any]]) -> dict[str, Any]:
        item = source[node_id]
        return {
            "node_id": node_id,
            "class": item.get("class", ""),
            "method": item.get("method", ""),
            "hits": int(item.get("hits", 0) or 0),
        }

    shared_edge_timing: list[dict[str, Any]] = []
    for key in sorted(set(edges_a) & set(edges_b)):
        left = edges_a[key]
        right = edges_b[key]
        a_delta = float(left.get("delta_ms", 0) or 0)
        b_delta = float(right.get("delta_ms", 0) or 0)
        shared_edge_timing.append(
            {
                "source": key[0],
                "target": key[1],
                "source_label": left.get("source_label", ""),
                "target_label": left.get("target_label", ""),
                "a_delta_ms": a_delta,
                "b_delta_ms": b_delta,
                "delta_change_ms": round(b_delta - a_delta, 3),
            }
        )

    only_a_edges = [
        edges_a[key]
        for key in sorted(set(edges_a) - set(edges_b))
    ]
    only_b_edges = [
        edges_b[key]
        for key in sorted(set(edges_b) - set(edges_a))
    ]

    first_divergence = {
        "index": divergence_index,
        "common_prefix": common_prefix,
        "a_next": seq_a[divergence_index] if divergence_index < len(seq_a) else None,
        "b_next": seq_b[divergence_index] if divergence_index < len(seq_b) else None,
        "a_tail": seq_a[divergence_index : divergence_index + 12],
        "b_tail": seq_b[divergence_index : divergence_index + 12],
    }

    only_a_nodes = [node_payload(node_id, hits_a) for node_id in sorted(nodes_a - nodes_b)]
    only_b_nodes = [node_payload(node_id, hits_b) for node_id in sorted(nodes_b - nodes_a)]

    return {
        "ok": comparable,
        "comparable": comparable,
        "graph_fingerprint_a": fp_a,
        "graph_fingerprint_b": fp_b,
        "hook_fingerprint_a": hook_fp_a,
        "hook_fingerprint_b": hook_fp_b,
        "a": scenario_a.get("name", ""),
        "b": scenario_b.get("name", ""),
        "common_nodes": len(nodes_a & nodes_b),
        "only_in_a": only_a_nodes,
        "only_in_b": only_b_nodes,
        "only_edges_a": only_a_edges,
        "only_edges_b": only_b_edges,
        "shared_edge_timing": shared_edge_timing,
        "first_divergence": first_divergence,
        "a_sequence": seq_a[:100],
        "b_sequence": seq_b[:100],
        "summary": (
            f"共同命中 {len(nodes_a & nodes_b)} 个方法；"
            f"仅 A {len(only_a_nodes)} 个，仅 B {len(only_b_nodes)} 个；"
            f"仅 A 边 {len(only_a_edges)} 条，仅 B 边 {len(only_b_edges)} 条；"
            f"公共前缀 {len(common_prefix)} 个方法"
        ),
        "error": (
            None
            if comparable
            else "两个场景的静态调用图或 Hook 方法集合不一致，无法可靠比较分支"
        ),
    }
