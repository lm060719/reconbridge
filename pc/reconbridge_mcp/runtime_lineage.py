"""跨方法 Value Lineage 的运行时验证与 A/B 比较。"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from . import writer_probe


_EXTERNAL_PREFIXES = (
    "java.",
    "javax.",
    "android.",
    "androidx.",
    "kotlin.",
    "kotlinx.",
)


def _normalize_class_name(name: str) -> str:
    value = (name or "").strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    return value.replace("/", ".")


def _canonical(value: Any) -> dict[str, Any]:
    if value is None:
        return {"type": "null", "value": None, "canonical": "null"}
    if isinstance(value, bool):
        return {
            "type": "boolean",
            "value": value,
            "canonical": "true" if value else "false",
        }
    if isinstance(value, int) and not isinstance(value, bool):
        return {"type": "integer", "value": value, "canonical": str(value)}
    if isinstance(value, float):
        return {"type": "number", "value": value, "canonical": repr(value)}
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            text = str(value)
        return {
            "type": "json",
            "value": value,
            "canonical": text[:8000],
        }

    text = str(value).strip()
    lowered = text.casefold()
    if lowered == "true":
        return {"type": "boolean", "value": True, "canonical": "true"}
    if lowered == "false":
        return {"type": "boolean", "value": False, "canonical": "false"}
    if lowered in {"null", "none"}:
        return {"type": "null", "value": None, "canonical": "null"}
    return {
        "type": "string",
        "value": text[:8000],
        "canonical": text[:8000],
    }


def path_fingerprint(path: dict[str, Any]) -> str:
    stable = {
        "nodes": [
            {
                "type": item.get("type"),
                "class_name": item.get("class_name"),
                "method_name": item.get("method_name"),
                "descriptor": item.get("descriptor"),
                "field_name": item.get("field_name"),
                "field_type": item.get("field_type"),
                "kind": item.get("kind"),
                "label": item.get("label"),
            }
            for item in (path.get("nodes") or [])
        ],
        "relations": list(path.get("relations") or []),
    }
    raw = json.dumps(
        stable,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def path_methods(
    path: dict[str, Any],
    max_hooks: int = 16,
    include_external: bool = False,
) -> list[dict[str, Any]]:
    """提取 origin→sink 路径里的唯一方法，保持数据流顺序。"""
    max_hooks = max(1, min(int(max_hooks), 32))
    methods: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for path_index, node in enumerate(path.get("nodes") or []):
        if node.get("type") != "method":
            continue
        class_name = _normalize_class_name(str(node.get("class_name", "")))
        method_name = str(node.get("method_name", ""))
        if not class_name or not method_name or method_name == "<clinit>":
            continue
        if (
            not include_external
            and class_name.startswith(_EXTERNAL_PREFIXES)
        ):
            continue

        key = (class_name, method_name)
        if key in seen:
            continue
        seen.add(key)
        methods.append(
            {
                "path_index": path_index,
                "class": class_name,
                "method": method_name,
                "descriptor": str(node.get("descriptor", "")),
                "label": str(
                    node.get("label")
                    or f"{class_name}.{method_name}"
                ),
            }
        )
        if len(methods) >= max_hooks:
            break
    return methods


def terminal_field(path: dict[str, Any]) -> dict[str, Any] | None:
    nodes = path.get("nodes") or []
    if not nodes:
        return None
    node = nodes[-1]
    if node.get("type") != "field":
        return None
    return {
        "class": _normalize_class_name(str(node.get("class_name", ""))),
        "field": str(node.get("field_name", "")),
        "type": str(node.get("field_type", "")),
        "label": str(node.get("label", "")),
        "path_index": len(nodes) - 1,
    }


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


def _summarize_returns(events: list[dict[str, Any]]) -> dict[str, Any]:
    values: list[dict[str, Any]] = []
    for event in events:
        if str(event.get("phase", "")) != "after":
            continue
        if "ret" not in event:
            continue
        item = _canonical(event.get("ret"))
        values.append(
            {
                **item,
                "ts": event.get("ts"),
                "tid": event.get("tid"),
            }
        )

    distinct: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for item in values:
        key = f"{item['type']}:{item['canonical']}"
        if key not in distinct:
            distinct[key] = {
                "type": item["type"],
                "value": item["value"],
                "canonical": item["canonical"],
            }
            counts[key] = 0
        counts[key] += 1

    rows = [
        {
            **distinct[key],
            "count": counts[key],
        }
        for key in sorted(distinct)
    ]
    stable = len(rows) == 1 and bool(values)
    return {
        "sample_count": len(values),
        "distinct_count": len(rows),
        "stable": stable,
        "stable_value": rows[0] if stable else None,
        "distinct_values": rows[:12],
        "samples": values[:20],
    }


def analyze_capture(
    path: dict[str, Any],
    events: list[dict[str, Any]],
    hook_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """分析一次多方法 lineage 运行时采集。"""
    methods = path_methods(
        path,
        max_hooks=max(1, len(hook_map)),
        include_external=True,
    )
    ordered = _sort_events(events)

    events_by_hook: dict[str, list[dict[str, Any]]] = {
        hook_id: []
        for hook_id in hook_map
    }
    by_method: dict[tuple[str, str], str] = {}
    for hook_id, meta in hook_map.items():
        by_method[(meta["class"], meta["method"])] = hook_id

    for event in ordered:
        hook_id = str(event.get("hook_id", ""))
        if hook_id not in events_by_hook:
            key = (
                _normalize_class_name(str(event.get("class", ""))),
                str(event.get("method", "")),
            )
            hook_id = by_method.get(key, "")
        if hook_id in events_by_hook:
            events_by_hook[hook_id].append(event)

    observations: list[dict[str, Any]] = []
    method_hits: dict[int, int] = {}
    for hook_id, meta in hook_map.items():
        hook_events = events_by_hook.get(hook_id, [])
        after_hits = [
            item
            for item in hook_events
            if str(item.get("phase", "")) == "after"
        ]
        method_hits[int(meta["path_index"])] = len(after_hits)
        observations.append(
            {
                "hook_id": hook_id,
                "path_index": int(meta["path_index"]),
                "class": meta["class"],
                "method": meta["method"],
                "descriptor": meta.get("descriptor", ""),
                "label": meta.get("label", ""),
                "hit_count": len(after_hits),
                "returns": _summarize_returns(hook_events),
            }
        )
    observations.sort(key=lambda item: int(item["path_index"]))

    # 在每个 tid 中找“按数据流 path_index 递增”的 after 事件子序列。
    after_events: list[dict[str, Any]] = []
    for event in ordered:
        if str(event.get("phase", "")) != "after":
            continue
        hook_id = str(event.get("hook_id", ""))
        meta = hook_map.get(hook_id)
        if meta is None:
            key = (
                _normalize_class_name(str(event.get("class", ""))),
                str(event.get("method", "")),
            )
            mapped = by_method.get(key, "")
            meta = hook_map.get(mapped)
        if meta is None:
            continue
        after_events.append(
            {
                "ts": float(event.get("ts", 0) or 0),
                "tid": event.get("tid"),
                "path_index": int(meta["path_index"]),
                "label": meta.get("label", ""),
                "class": meta["class"],
                "method": meta["method"],
                "ret": _canonical(event.get("ret"))
                if "ret" in event
                else None,
            }
        )

    expected = [int(item["path_index"]) for item in methods]
    grouped: dict[Any, list[dict[str, Any]]] = {}
    for event in after_events:
        grouped.setdefault(event.get("tid"), []).append(event)

    best_tid: Any = None
    best_sequence: list[dict[str, Any]] = []
    for tid, thread_events in grouped.items():
        position = 0
        sequence: list[dict[str, Any]] = []
        for event in thread_events:
            if position >= len(expected):
                break
            if int(event["path_index"]) == expected[position]:
                sequence.append(event)
                position += 1
        if len(sequence) > len(best_sequence):
            best_tid = tid
            best_sequence = sequence

    # 值比较优先限定到主业务线程，避免后台同名方法调用把稳定值冲成 unstable。
    for observation in observations:
        hook_id = str(observation.get("hook_id", ""))
        hook_events = events_by_hook.get(hook_id, [])
        observation["returns_all_threads"] = observation.get("returns")
        if best_tid is not None:
            primary_events = [
                event
                for event in hook_events
                if event.get("tid") == best_tid
            ]
            if primary_events:
                observation["returns"] = _summarize_returns(primary_events)
                observation["primary_thread_hit_count"] = len(
                    [
                        event
                        for event in primary_events
                        if str(event.get("phase", "")) == "after"
                    ]
                )

    timeline: list[dict[str, Any]] = []
    previous_ts: float | None = None
    for event in best_sequence:
        delta_ms = None
        if previous_ts is not None:
            delta_ms = round(float(event["ts"]) - previous_ts, 3)
        timeline.append(
            {
                **event,
                "delta_ms": delta_ms,
            }
        )
        previous_ts = float(event["ts"])

    field = terminal_field(path)
    writer_change: dict[str, Any] | None = None
    if field and methods:
        writer = methods[-1]
        writer_hook_id = next(
            (
                hook_id
                for hook_id, meta in hook_map.items()
                if int(meta["path_index"]) == int(writer["path_index"])
            ),
            "",
        )
        if writer_hook_id:
            writer_events = events_by_hook.get(writer_hook_id, [])
            if best_tid is not None:
                writer_events = [
                    event
                    for event in writer_events
                    if event.get("tid") == best_tid
                ]
            writer_change = writer_probe.analyze_writer_events(
                writer_events,
                str(field.get("field", "")),
            )

    hit_nodes = sum(1 for count in method_hits.values() if count > 0)
    method_count = len(expected)
    ordered_count = len(best_sequence)

    return {
        "event_count": len(ordered),
        "method_count": method_count,
        "observed_methods": hit_nodes,
        "method_coverage": (
            round(hit_nodes / method_count, 3)
            if method_count
            else 0.0
        ),
        "ordered_methods": ordered_count,
        "ordered_coverage": (
            round(ordered_count / method_count, 3)
            if method_count
            else 0.0
        ),
        "full_method_sequence_observed": (
            bool(method_count)
            and ordered_count == method_count
        ),
        "primary_tid": best_tid,
        "observations": observations,
        "timeline": timeline[:100],
        "terminal_field": field,
        "writer_change": writer_change,
    }


def compare_captures(
    capture_a: dict[str, Any],
    capture_b: dict[str, Any],
) -> dict[str, Any]:
    fp_a = str(capture_a.get("lineage_fingerprint", ""))
    fp_b = str(capture_b.get("lineage_fingerprint", ""))
    comparable = bool(fp_a and fp_a == fp_b)

    analysis_a = capture_a.get("analysis") or {}
    analysis_b = capture_b.get("analysis") or {}
    obs_a = {
        int(item["path_index"]): item
        for item in analysis_a.get("observations") or []
    }
    obs_b = {
        int(item["path_index"]): item
        for item in analysis_b.get("observations") or []
    }

    rows: list[dict[str, Any]] = []
    first_difference: dict[str, Any] | None = None
    for path_index in sorted(set(obs_a) | set(obs_b)):
        left = obs_a.get(path_index) or {}
        right = obs_b.get(path_index) or {}
        ret_a = left.get("returns") or {}
        ret_b = right.get("returns") or {}
        value_a = ret_a.get("stable_value")
        value_b = ret_b.get("stable_value")

        comparable_value = bool(
            ret_a.get("stable")
            and ret_b.get("stable")
            and isinstance(value_a, dict)
            and isinstance(value_b, dict)
        )
        same_value: bool | None = None
        if comparable_value:
            same_value = (
                value_a.get("type") == value_b.get("type")
                and value_a.get("canonical") == value_b.get("canonical")
            )

        row = {
            "path_index": path_index,
            "label": left.get("label") or right.get("label") or "",
            "a_hit_count": int(left.get("hit_count", 0) or 0),
            "b_hit_count": int(right.get("hit_count", 0) or 0),
            "a_value": value_a,
            "b_value": value_b,
            "values_comparable": comparable_value,
            "same_value": same_value,
        }
        rows.append(row)

        if (
            first_difference is None
            and comparable_value
            and same_value is False
        ):
            first_difference = row

    field_a = analysis_a.get("writer_change") or {}
    field_b = analysis_b.get("writer_change") or {}

    return {
        "ok": comparable,
        "comparable": comparable,
        "lineage_fingerprint_a": fp_a,
        "lineage_fingerprint_b": fp_b,
        "a": capture_a.get("scenario", ""),
        "b": capture_b.get("scenario", ""),
        "a_full_sequence": bool(
            analysis_a.get("full_method_sequence_observed")
        ),
        "b_full_sequence": bool(
            analysis_b.get("full_method_sequence_observed")
        ),
        "method_values": rows,
        "first_stable_value_difference": first_difference,
        "a_writer_change": field_a,
        "b_writer_change": field_b,
        "summary": (
            "两侧使用同一条 Lineage；"
            f"A 方法覆盖 {analysis_a.get('method_coverage', 0)}，"
            f"B 方法覆盖 {analysis_b.get('method_coverage', 0)}；"
            + (
                "已找到最早稳定值差异"
                if first_difference
                else "未找到可比较的最早稳定值差异"
            )
        ),
        "error": (
            None
            if comparable
            else "A/B 不是同一条 Value Lineage，无法可靠比较运行时值"
        ),
    }
