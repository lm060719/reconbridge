"""静态代表路径的运行时验证与时间线分析。"""
from __future__ import annotations

from typing import Any


def normalize_class_name(name: str) -> str:
    value = (name or "").strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    return value.replace("/", ".")


def method_key(node: dict[str, Any]) -> tuple[str, str]:
    return (
        normalize_class_name(str(node.get("class", ""))),
        str(node.get("method", "")),
    )


def path_methods(path: dict[str, Any], max_hooks: int = 12) -> list[dict[str, Any]]:
    """从一条代表路径提取可 Hook 的唯一 class+method，保持静态顺序。"""
    max_hooks = max(1, min(int(max_hooks), 24))
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for index, node in enumerate(path.get("nodes") or []):
        key = method_key(node)
        if not key[0] or not key[1] or key[1] == "<clinit>" or key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "path_index": index,
                "class": key[0],
                "method": key[1],
                "descriptor": str(node.get("descriptor", "")),
                "external": bool(node.get("external")),
            }
        )
        if len(result) >= max_hooks:
            break
    return result


def _event_sort_key(item: tuple[int, dict[str, Any]]) -> tuple[float, int, int]:
    index, event = item
    try:
        ts = float(event.get("ts", 0) or 0)
    except (TypeError, ValueError):
        ts = 0.0
    try:
        seq = int(event.get("seq", 0) or 0)
    except (TypeError, ValueError):
        seq = 0
    return (ts, seq, index)


def build_timeline(
    events: list[dict[str, Any]],
    hook_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """按 ts/seq 排序事件，并映射回静态路径位置。"""
    by_method: dict[tuple[str, str], dict[str, Any]] = {}
    for meta in hook_map.values():
        by_method[(meta["class"], meta["method"])] = meta

    ordered = sorted(enumerate(events), key=_event_sort_key)
    timeline: list[dict[str, Any]] = []
    previous_ts: float | None = None

    for _, event in ordered:
        meta = hook_map.get(str(event.get("hook_id", "")))
        if meta is None:
            meta = by_method.get(
                (
                    normalize_class_name(str(event.get("class", ""))),
                    str(event.get("method", "")),
                )
            )
        if meta is None:
            continue

        try:
            ts = float(event.get("ts", 0) or 0)
        except (TypeError, ValueError):
            ts = 0.0
        delta_ms = None
        if previous_ts is not None and ts and previous_ts:
            delta_ms = round(ts - previous_ts, 3)

        timeline.append(
            {
                "ts": ts,
                "seq": event.get("seq"),
                "delta_ms": delta_ms,
                "hook_id": event.get("hook_id", ""),
                "class": meta["class"],
                "method": meta["method"],
                "descriptor": meta.get("descriptor", ""),
                "path_index": int(meta["path_index"]),
                "pid": event.get("pid"),
                "tid": event.get("tid"),
                "phase": event.get("phase"),
            }
        )
        if ts:
            previous_ts = ts

    return timeline


def _same_thread(source: dict[str, Any], target: dict[str, Any]) -> bool:
    source_tid = source.get("tid")
    target_tid = target.get("tid")
    if source_tid in (None, 0, "") or target_tid in (None, 0, ""):
        return True
    return source_tid == target_tid


def _adjacent_edge_observed(
    timeline: list[dict[str, Any]],
    source_index: int,
    target_index: int,
) -> tuple[bool, float | None]:
    """判断静态相邻节点是否在同一线程按顺序命中，并返回最短入口间隔。"""
    sources = [
        item for item in timeline
        if int(item.get("path_index", -1)) == source_index
    ]
    targets = [
        item for item in timeline
        if int(item.get("path_index", -1)) == target_index
    ]

    best_delta: float | None = None
    observed = False
    for source in sources:
        source_ts = float(source.get("ts", 0) or 0)
        for target in targets:
            if not _same_thread(source, target):
                continue
            target_ts = float(target.get("ts", 0) or 0)
            if target_ts < source_ts:
                continue
            observed = True
            if source_ts and target_ts:
                delta = target_ts - source_ts
                if best_delta is None or delta < best_delta:
                    best_delta = delta
            break
    return observed, round(best_delta, 3) if best_delta is not None else None


def analyze_path(
    path: dict[str, Any],
    events: list[dict[str, Any]],
    hook_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """把一次采集结果转换为路径覆盖、时间线和按序执行情况。"""
    methods = path_methods(path, max_hooks=max(1, len(hook_map)))
    timeline = build_timeline(events, hook_map)
    path_indexes = [int(item["path_index"]) for item in methods]

    hits: dict[int, int] = {index: 0 for index in path_indexes}
    for item in timeline:
        index = int(item["path_index"])
        if index in hits:
            hits[index] += 1

    hit_indexes = {index for index, count in hits.items() if count > 0}
    node_count = len(path_indexes)
    observed_nodes = len(hit_indexes)

    edges: list[dict[str, Any]] = []
    observed_edges = 0
    for source, target in zip(path_indexes, path_indexes[1:]):
        observed, delta_ms = _adjacent_edge_observed(timeline, source, target)
        if observed:
            observed_edges += 1
        edges.append(
            {
                "source_index": source,
                "target_index": target,
                "observed": observed,
                "delta_ms": delta_ms,
            }
        )

    edge_count = max(0, node_count - 1)

    # 在每个线程内部检查静态顺序；选择匹配节点最多的线程作为主执行链。
    grouped: dict[Any, list[dict[str, Any]]] = {}
    for event in timeline:
        grouped.setdefault(event.get("tid"), []).append(event)
    if not grouped:
        grouped[None] = []

    best_tid: Any = None
    best_ordered: list[int] = []
    for tid, thread_events in grouped.items():
        expected_pos = 0
        ordered: list[int] = []
        for event in thread_events:
            if expected_pos >= len(path_indexes):
                break
            if int(event["path_index"]) == path_indexes[expected_pos]:
                ordered.append(path_indexes[expected_pos])
                expected_pos += 1
        if len(ordered) > len(best_ordered):
            best_tid = tid
            best_ordered = ordered

    ordered_indexes = best_ordered
    full_path_observed = bool(path_indexes) and len(ordered_indexes) == len(path_indexes)

    compact_timeline: list[dict[str, Any]] = []
    for item in timeline[:200]:
        compact_timeline.append(
            {
                "ts": item["ts"],
                "delta_ms": item["delta_ms"],
                "path_index": item["path_index"],
                "class": item["class"],
                "method": item["method"],
                "tid": item.get("tid"),
            }
        )

    return {
        "static_text": path.get("text", ""),
        "static_length": path.get("length", max(0, node_count - 1)),
        "hooked_nodes": node_count,
        "event_count": len(timeline),
        "node_hits": [
            {"path_index": index, "hits": hits[index]}
            for index in path_indexes
        ],
        "node_coverage": round(observed_nodes / node_count, 3) if node_count else 0.0,
        "edge_coverage": round(observed_edges / edge_count, 3) if edge_count else (1.0 if node_count else 0.0),
        "ordered_matched_nodes": len(ordered_indexes),
        "ordered_indexes": ordered_indexes,
        "full_path_observed": full_path_observed,
        "primary_tid": best_tid,
        "edges": edges,
        "timeline": compact_timeline,
    }


def choose_path(
    call_graph: dict[str, Any],
    path_index: int = 0,
) -> dict[str, Any] | None:
    paths = call_graph.get("representative_paths") or []
    if not paths:
        paths = call_graph.get("upstream_paths") or call_graph.get("downstream_paths") or []
    if not paths:
        return None
    path_index = max(0, min(int(path_index), len(paths) - 1))
    return paths[path_index]
