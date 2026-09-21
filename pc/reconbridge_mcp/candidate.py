"""候选方法排序。

只做确定性的启发式排序，不负责设备交互。分数用于减少人工筛选范围，并保留 reasons
解释每一项为什么排在前面。
"""
from __future__ import annotations

import re
from typing import Any


def normalize_class_name(name: str) -> str:
    value = (name or "").strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    return value.replace("/", ".")


def method_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        normalize_class_name(str(item.get("class", ""))),
        str(item.get("method", "")),
        str(item.get("descriptor", "")),
    )


def _tokens(query: str) -> list[str]:
    return [
        token.casefold()
        for token in re.split(r"[^0-9A-Za-z_\u4e00-\u9fff]+", query)
        if len(token) >= 2
    ]


def _graph_method_stats(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    stats: dict[tuple[str, str], dict[str, Any]] = {}
    nodes = graph.get("nodes") or {}
    edges = graph.get("edges") or []

    for node_id, node in nodes.items():
        if node.get("type") != "method":
            continue
        cls = normalize_class_name(str(node.get("class_name", "")))
        method = str(node.get("method_name", ""))
        key = (cls, method)
        slot = stats.setdefault(key, {"degree": 0, "runtime_confirmed": False, "runtime_hits": 0})
        slot["runtime_confirmed"] = bool(slot["runtime_confirmed"] or node.get("runtime_confirmed"))
        slot["runtime_hits"] = max(int(slot["runtime_hits"]), int(node.get("runtime_hits", 0) or 0))
        slot["node_ids"] = list(set(slot.get("node_ids", [])) | {node_id})

    for edge in edges:
        for endpoint in ("source", "target"):
            node = nodes.get(edge.get(endpoint))
            if not node or node.get("type") != "method":
                continue
            key = (
                normalize_class_name(str(node.get("class_name", ""))),
                str(node.get("method_name", "")),
            )
            slot = stats.setdefault(key, {"degree": 0, "runtime_confirmed": False, "runtime_hits": 0})
            slot["degree"] = int(slot.get("degree", 0)) + 1
    return stats


def rank(
    query: str,
    candidates: list[dict[str, Any]],
    graph: dict[str, Any] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """对候选方法做可解释排序。"""
    query_folded = query.casefold().strip()
    tokens = _tokens(query)
    graph_stats = _graph_method_stats(graph or {})
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}

    for raw in candidates:
        if not raw.get("method"):
            continue
        key = method_key(raw)
        if not key[0] or not key[1]:
            continue
        current = dedup.get(key)
        if current is None:
            current = {
                **raw,
                "class": key[0],
                "method": key[1],
                "descriptor": key[2],
                "_sources": set(),
                "_matched_strings": set(),
            }
            dedup[key] = current
        source = str(raw.get("_source", "search"))
        current["_sources"].add(source)
        if raw.get("matched_string"):
            current["_matched_strings"].add(str(raw["matched_string"]))

    ranked: list[dict[str, Any]] = []
    for key, item in dedup.items():
        score = 0
        reasons: list[str] = []
        cls, method, _descriptor = key
        cls_folded = cls.casefold()
        method_folded = method.casefold()
        strings = sorted(item.pop("_matched_strings"))
        sources = sorted(item.pop("_sources"))

        if "string_xref" in sources:
            score += 45
            reasons.append("字符串交叉引用直接指向该方法")
        if "method_name" in sources:
            score += 25
            reasons.append("方法名搜索命中")

        if query_folded:
            if method_folded == query_folded:
                score += 35
                reasons.append("方法名与查询完全一致")
            elif query_folded in method_folded:
                score += 20
                reasons.append("方法名包含查询")
            if query_folded in cls_folded:
                score += 12
                reasons.append("类名包含查询")

        token_hits = sum(
            1 for token in tokens
            if token in method_folded or token in cls_folded
        )
        if token_hits:
            bonus = min(15, token_hits * 5)
            score += bonus
            reasons.append(f"类名/方法名命中 {token_hits} 个查询词")

        if strings:
            exact = any(s.casefold() == query_folded for s in strings)
            contains = any(query_folded and query_folded in s.casefold() for s in strings)
            if exact:
                score += 25
                reasons.append("实际字符串与查询完全一致")
            elif contains:
                score += 15
                reasons.append("实际字符串包含查询")
            score += min(10, len(strings) * 2)
            reasons.append(f"关联 {len(strings)} 条字符串证据")

        stats = graph_stats.get((cls, method), {})
        if stats.get("runtime_confirmed"):
            score += 100
            reasons.append("已有运行时命中证据")
        runtime_hits = int(stats.get("runtime_hits", 0) or 0)
        if runtime_hits:
            score += min(20, runtime_hits * 2)
            reasons.append(f"历史运行时命中 {runtime_hits} 次")
        degree = int(stats.get("degree", 0) or 0)
        if degree:
            score += min(15, degree)
            reasons.append(f"证据图已有 {degree} 条关联关系")

        # 常见编译器/内部生成方法降权，但不直接过滤，避免漏掉真正入口。
        lowered = method_folded
        if lowered.startswith("access$") or "$lambda" in lowered or lowered.startswith("lambda$"):
            score -= 12
            reasons.append("编译器生成方法，轻度降权")
        if cls_folded.startswith(("java.", "android.", "kotlin.")):
            score -= 10
            reasons.append("框架/标准库类，轻度降权")

        ranked.append({
            **item,
            "score": score,
            "reasons": reasons,
            "matched_strings": strings[:8],
            "sources": sources,
            "runtime_confirmed": bool(stats.get("runtime_confirmed")),
            "runtime_hits": runtime_hits,
        })

    ranked.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            str(item.get("class", "")),
            str(item.get("method", "")),
            str(item.get("descriptor", "")),
        )
    )

    for index, item in enumerate(ranked[: max(1, min(int(limit), 100))], 1):
        item["rank"] = index
    return ranked[: max(1, min(int(limit), 100))]
