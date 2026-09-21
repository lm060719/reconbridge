"""自动 Investigation Pipeline 的纯逻辑部分。"""
from __future__ import annotations

import re
from typing import Any

_INTENT_WORDS = (
    "帮我",
    "请",
    "找到",
    "找出",
    "查找",
    "搜索",
    "定位",
    "分析",
    "看看",
    "识别",
    "相关",
    "对应",
    "实现",
    "代码",
    "逻辑",
    "功能",
    "方法",
    "函数",
    "调用",
    "流程",
    "判断",
    "位置",
    "哪里",
)

_GENERIC_CHINESE = {
    "状态",
    "方法",
    "函数",
    "代码",
    "逻辑",
    "功能",
    "判断",
    "调用",
    "流程",
}


def _append_unique(items: list[str], value: str, *, minimum: int = 2) -> None:
    value = value.strip(" \t\r\n,，。！？:：;；()（）[]【】{}<>《》")
    if len(value) < minimum:
        return
    if value not in items:
        items.append(value)


def plan_queries(goal: str, max_queries: int = 4) -> list[str]:
    """从自然语言目标里提炼少量、可直接喂给 DEX 搜索的关键词。"""
    goal = goal.strip()
    if not goal:
        return []

    max_queries = max(1, min(int(max_queries), 8))
    planned: list[str] = []

    # 引号里的词通常是 UI 文案、字段名或用户最明确的搜索目标。
    for match in re.finditer(r'["“”\'‘’]([^"“”\'‘’]{2,80})["“”\'‘’]', goal):
        _append_unique(planned, match.group(1))

    # Java/Kotlin 风格标识符、包名、类名。
    for token in re.findall(r"[A-Za-z_$][A-Za-z0-9_.$]{2,}", goal):
        _append_unique(planned, token)

    # 去掉常见意图词，留下业务语义短语。
    cleaned = goal
    for word in _INTENT_WORDS:
        cleaned = cleaned.replace(word, " ")
    for chunk in re.findall(r"[\u4e00-\u9fff]{2,16}", cleaned):
        _append_unique(planned, chunk)

    # 对较长中文短语补一个前缀业务词，避免“会员状态”找不到而整句又过严。
    for chunk in list(planned):
        if re.fullmatch(r"[\u4e00-\u9fff]{4,16}", chunk):
            for size in (4, 3, 2):
                prefix = chunk[:size]
                if prefix not in _GENERIC_CHINESE:
                    _append_unique(planned, prefix)
                    break

    # 最后保留原始 goal 作兜底，但不让它抢占前面的精炼词。
    _append_unique(planned, goal)

    return planned[:max_queries]


def merge_rankings(
    rankings: list[tuple[str, list[dict[str, Any]]]],
    limit: int = 10,
) -> list[dict[str, Any]]:
    """合并多组关键词排序；同一方法去重，并对跨关键词反复命中做轻量加权。"""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}

    for query, items in rankings:
        for item in items:
            key = (
                str(item.get("class", "")),
                str(item.get("method", "")),
                str(item.get("descriptor", "")),
            )
            if not key[0] or not key[1]:
                continue

            score = int(item.get("score", 0) or 0)
            current = merged.get(key)
            if current is None:
                current = {
                    **item,
                    "score": score,
                    "matched_queries": [query],
                    "reasons": list(item.get("reasons", [])),
                    "matched_strings": list(item.get("matched_strings", [])),
                    "sources": list(item.get("sources", [])),
                }
                merged[key] = current
                continue

            if query not in current["matched_queries"]:
                current["matched_queries"].append(query)
                current["score"] += 8
                current["reasons"].append(f"同时被多个查询词命中：{query}")

            current["score"] = max(current["score"], score) + max(
                0,
                len(current["matched_queries"]) - 1,
            ) * 2
            current["runtime_confirmed"] = bool(
                current.get("runtime_confirmed") or item.get("runtime_confirmed")
            )
            current["runtime_hits"] = max(
                int(current.get("runtime_hits", 0) or 0),
                int(item.get("runtime_hits", 0) or 0),
            )

            for field in ("matched_strings", "sources", "reasons"):
                for value in item.get(field, []):
                    if value not in current[field]:
                        current[field].append(value)

    result = list(merged.values())
    result.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            -len(item.get("matched_queries", [])),
            str(item.get("class", "")),
            str(item.get("method", "")),
        )
    )

    limit = max(1, min(int(limit), 50))
    result = result[:limit]
    for index, item in enumerate(result, 1):
        item["rank"] = index
    return result


def compact_candidate(item: dict[str, Any]) -> dict[str, Any]:
    """流水线最终响应只保留决策需要的字段，避免大量上下文回传。"""
    return {
        "rank": item.get("rank"),
        "class": item.get("class"),
        "method": item.get("method"),
        "descriptor": item.get("descriptor", ""),
        "score": item.get("score", 0),
        "reasons": list(item.get("reasons", []))[:8],
        "matched_strings": list(item.get("matched_strings", []))[:5],
        "matched_queries": list(item.get("matched_queries", []))[:5],
        "runtime_confirmed": bool(item.get("runtime_confirmed")),
        "runtime_hits": int(item.get("runtime_hits", 0) or 0),
        "verification_hits": int(item.get("verification_hits", 0) or 0),
        "verified": bool(item.get("verified")),
    }
