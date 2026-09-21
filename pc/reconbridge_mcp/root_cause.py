"""综合静态 Value Lineage 与 Runtime Lineage 的根因候选排序。"""
from __future__ import annotations

from typing import Any


def _method_key(node: dict[str, Any]) -> str:
    return (
        f"method:{node.get('class_name', '')}#"
        f"{node.get('method_name', '')}{node.get('descriptor', '')}"
    )


def _origin_key(node: dict[str, Any]) -> str:
    return f"origin:{node.get('kind', '')}:{node.get('label', '')}"


def _candidate_key(node: dict[str, Any]) -> str:
    if node.get("type") == "method":
        return _method_key(node)
    if node.get("type") == "origin":
        return _origin_key(node)
    return ""


def _add(
    breakdown: list[dict[str, Any]],
    key: str,
    points: int,
    reason: str,
) -> None:
    if not points:
        return
    breakdown.append(
        {
            "key": key,
            "points": int(points),
            "reason": reason,
        }
    )


def _next_action(candidate: dict[str, Any]) -> str:
    if candidate.get("is_first_runtime_difference"):
        return (
            "优先 inspect_method / trace_target 检查该方法的入参、对象字段与返回值构造；"
            "它是当前证据里最早出现 A/B 稳定值差异的位置"
        )

    if candidate.get("is_writer") and candidate.get("writer_changed"):
        return (
            "该 writer 已真实改变目标字段；继续检查它的赋值右值、参数和上游 callee，"
            "确认具体输入如何转换为字段状态"
        )

    if candidate.get("candidate_type") == "origin":
        kind = str(candidate.get("kind", ""))
        if kind == "preferences":
            return "搜索具体 preference key 的读写点，并确认写入时机/默认值"
        if kind == "network_or_repository":
            return "继续展开 Repository/API 返回对象，必要时用 deep/paths 抓响应内部字段"
        if kind == "database_or_cache":
            return "检查 DAO/缓存 key 与更新时机，确认 A/B 是否读取了不同持久化状态"
        if kind == "intent_or_state":
            return "检查 Intent/Bundle/SavedState 的写入方与调用入口参数"
        return "继续沿该静态来源节点向上检查真实生产者"

    if candidate.get("candidate_type") == "method":
        return "检查该方法的 callers/callees、参数和值构造逻辑，并用 trace_target 补精细运行时证据"

    return "继续补充运行时证据"


def rank_root_causes(
    lineage: dict[str, Any],
    runtime_comparison: dict[str, Any] | None = None,
    selected_path_index: int = 0,
    limit: int = 5,
) -> dict[str, Any]:
    """综合静态来源、路径支持和 A/B 运行时证据排序根因候选。"""
    paths = lineage.get("origin_paths") or []
    if not paths:
        return {
            "ok": False,
            "error": "Value Lineage 没有 origin_paths，无法做根因排序",
            "candidates": [],
        }

    selected_path_index = max(
        0,
        min(int(selected_path_index), len(paths) - 1),
    )
    selected_path = paths[selected_path_index]
    selected_nodes = selected_path.get("nodes") or []

    support: dict[str, int] = {}
    node_by_key: dict[str, dict[str, Any]] = {}
    path_indexes_by_key: dict[str, list[int]] = {}

    for path_index, path in enumerate(paths):
        seen: set[str] = set()
        for node in path.get("nodes") or []:
            key = _candidate_key(node)
            if not key:
                continue
            node_by_key.setdefault(key, dict(node))
            path_indexes_by_key.setdefault(key, []).append(path_index)
            if key in seen:
                continue
            seen.add(key)
            support[key] = support.get(key, 0) + 1

    selected_method_indexes: dict[str, int] = {}
    for path_index, node in enumerate(selected_nodes):
        key = _candidate_key(node)
        if node.get("type") == "method" and key:
            selected_method_indexes[key] = path_index

    runtime = runtime_comparison or {}
    runtime_available = bool(runtime_comparison and runtime.get("comparable"))
    runtime_rows = {
        int(item.get("path_index", -1)): item
        for item in (runtime.get("method_values") or [])
        if int(item.get("path_index", -1)) >= 0
    }
    first = runtime.get("first_stable_value_difference") or {}
    first_index = (
        int(first.get("path_index", -1))
        if isinstance(first, dict)
        else -1
    )
    full_both = bool(
        runtime.get("a_full_sequence")
        and runtime.get("b_full_sequence")
    )

    method_nodes = [
        (idx, node)
        for idx, node in enumerate(selected_nodes)
        if node.get("type") == "method"
    ]
    writer_key = ""
    if selected_nodes and selected_nodes[-1].get("type") == "field" and method_nodes:
        writer_key = _candidate_key(method_nodes[-1][1])

    writer_changed = bool(
        (runtime.get("a_writer_change") or {}).get("changed")
        or (runtime.get("b_writer_change") or {}).get("changed")
    )

    candidates: list[dict[str, Any]] = []
    for key, node in node_by_key.items():
        node_type = str(node.get("type", ""))
        if node_type not in {"method", "origin"}:
            continue

        breakdown: list[dict[str, Any]] = []
        static_support = int(support.get(key, 0))
        support_points = min(12, static_support * 3)
        _add(
            breakdown,
            "path_support",
            support_points,
            f"出现在 {static_support} 条静态来源路径中",
        )

        is_writer = key == writer_key
        is_first = False
        row: dict[str, Any] = {}

        if node_type == "origin":
            confidence = float(node.get("confidence", 0) or 0)
            origin_points = min(25, round(confidence * 25))
            _add(
                breakdown,
                "static_origin_confidence",
                origin_points,
                f"静态来源分类置信度 {confidence:.2f}",
            )
            if full_both and selected_path_index in path_indexes_by_key.get(key, []):
                _add(
                    breakdown,
                    "runtime_path_support",
                    5,
                    "该来源所在选中路径在 A/B 两侧均形成完整运行时方法序列",
                )
        else:
            if bool(node.get("runtime_confirmed")):
                hits = int(node.get("runtime_hits", 0) or 0)
                _add(
                    breakdown,
                    "previous_runtime_confirmation",
                    min(12, 8 + min(hits, 4)),
                    f"Evidence Graph 已有运行时命中 {hits} 次",
                )

            path_index = selected_method_indexes.get(key, -1)
            row = runtime_rows.get(path_index, {})
            a_hits = int(row.get("a_hit_count", 0) or 0)
            b_hits = int(row.get("b_hit_count", 0) or 0)
            if a_hits > 0 and b_hits > 0:
                _add(
                    breakdown,
                    "both_scenarios_hit",
                    15,
                    f"A/B 两个场景都真实命中（{a_hits}/{b_hits}）",
                )

            if full_both and path_index >= 0:
                _add(
                    breakdown,
                    "full_runtime_sequence",
                    5,
                    "A/B 两侧都观察到完整 Runtime Value Lineage 顺序",
                )

            if path_index == first_index and first_index >= 0:
                is_first = True
                _add(
                    breakdown,
                    "first_stable_runtime_difference",
                    45,
                    "这是链上最早出现 A/B 稳定返回值差异的方法",
                )
            elif row.get("values_comparable") and row.get("same_value") is False:
                _add(
                    breakdown,
                    "later_runtime_difference",
                    22,
                    "A/B 在该方法上也出现稳定返回值差异",
                )
            elif row.get("values_comparable") and row.get("same_value") is True:
                _add(
                    breakdown,
                    "same_runtime_value",
                    -10,
                    "A/B 在该方法上得到相同稳定值，降低其作为分叉根因的优先级",
                )

            if is_writer and writer_changed:
                _add(
                    breakdown,
                    "writer_changed_field",
                    25,
                    "该 writer 在运行时真实改变了目标条件字段",
                )

        raw_score = sum(int(item["points"]) for item in breakdown)
        score = max(0, min(100, raw_score))

        if is_first and runtime_available:
            evidence_level = "runtime_divergence"
        elif is_writer and writer_changed:
            evidence_level = "runtime_writer"
        elif any(item["key"] == "both_scenarios_hit" for item in breakdown):
            evidence_level = "runtime_supported"
        elif node_type == "origin":
            evidence_level = "static_source"
        else:
            evidence_level = "static_method"

        candidate = {
            "candidate_key": key,
            "candidate_type": node_type,
            "label": str(node.get("label", "")),
            "score": score,
            "raw_score": raw_score,
            "score_breakdown": breakdown,
            "evidence_level": evidence_level,
            "path_support": static_support,
            "path_indexes": sorted(set(path_indexes_by_key.get(key, []))),
            "is_first_runtime_difference": is_first,
            "is_writer": is_writer,
            "writer_changed": bool(is_writer and writer_changed),
        }

        if node_type == "method":
            candidate.update(
                {
                    "class": str(node.get("class_name", "")),
                    "method": str(node.get("method_name", "")),
                    "descriptor": str(node.get("descriptor", "")),
                    "runtime_confirmed": bool(node.get("runtime_confirmed")),
                    "runtime_hits": int(node.get("runtime_hits", 0) or 0),
                    "a_value": row.get("a_value"),
                    "b_value": row.get("b_value"),
                    "a_hit_count": int(row.get("a_hit_count", 0) or 0),
                    "b_hit_count": int(row.get("b_hit_count", 0) or 0),
                }
            )
        else:
            candidate.update(
                {
                    "kind": str(node.get("kind", "")),
                    "confidence": float(node.get("confidence", 0) or 0),
                    "expression": str(node.get("expression", "")),
                }
            )

        candidate["next_action"] = _next_action(candidate)
        candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            0 if item.get("is_first_runtime_difference") else 1,
            0 if item.get("candidate_type") == "method" else 1,
            str(item.get("label", "")),
        )
    )

    limit = max(1, min(int(limit), 20))
    for rank, item in enumerate(candidates[:limit], 1):
        item["rank"] = rank

    top = candidates[0] if candidates else None
    quality = {
        "runtime_available": runtime_available,
        "a_full_sequence": bool(runtime.get("a_full_sequence")),
        "b_full_sequence": bool(runtime.get("b_full_sequence")),
        "first_runtime_difference_found": first_index >= 0,
        "lineage_ambiguities": len(lineage.get("ambiguities") or []),
        "lineage_unresolved_calls": len(lineage.get("unresolved_calls") or []),
        "path_count": len(paths),
        "selected_path_index": selected_path_index,
    }

    return {
        "ok": True,
        "selected_path_index": selected_path_index,
        "selected_path": selected_path,
        "quality": quality,
        "candidate_count": len(candidates),
        "top_candidate": top,
        "candidates": candidates[:limit],
        "summary": (
            (
                f"当前最高优先级根因节点：{top.get('label', '')} "
                f"(score={top.get('score', 0)}, {top.get('evidence_level', '')})"
            )
            if top
            else "当前没有可排序的根因节点"
        ),
    }
