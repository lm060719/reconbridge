"""A/B 分叉条件的运行时探针值提取与比较。"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical(value: Any) -> dict[str, Any]:
    """把 tracer 返回值归一化成可稳定比较的 JSON 形态。"""
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

    text = str(value).strip()
    lowered = text.casefold()
    if lowered == "true":
        return {"type": "boolean", "value": True, "canonical": "true"}
    if lowered == "false":
        return {"type": "boolean", "value": False, "canonical": "false"}
    if lowered in {"null", "none"}:
        return {"type": "null", "value": None, "canonical": "null"}

    try:
        parsed = json.loads(text)
        if isinstance(parsed, (bool, int, float)) or parsed is None:
            return _canonical(parsed)
        if isinstance(parsed, str):
            return {
                "type": "string",
                "value": parsed,
                "canonical": parsed,
            }
    except (json.JSONDecodeError, TypeError):
        pass

    return {"type": "string", "value": text, "canonical": text}


def probe_fingerprint(probe: dict[str, Any]) -> str:
    stable = {
        "kind": probe.get("kind"),
        "class": probe.get("class"),
        "method": probe.get("method"),
        "field": probe.get("field"),
        "expression": probe.get("expression"),
        "condition_rank": probe.get("condition_rank"),
        "condition_line": probe.get("condition_line"),
        "condition": probe.get("condition"),
    }
    raw = json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def extract_values(
    events: list[dict[str, Any]],
    probe: dict[str, Any],
) -> list[dict[str, Any]]:
    """从 tracer 事件中抽取字段值或条件方法返回值。"""
    kind = str(probe.get("kind", ""))
    values: list[dict[str, Any]] = []

    if kind == "field":
        field_name = str(probe.get("field", ""))
        for event in events:
            for field in event.get("fields") or []:
                if str(field.get("name", "")) != field_name:
                    continue
                normalized = _canonical(field.get("value"))
                values.append(
                    {
                        **normalized,
                        "ts": event.get("ts"),
                        "tid": event.get("tid"),
                        "phase": event.get("phase"),
                    }
                )
    elif kind == "condition_method":
        for event in events:
            if "ret" not in event:
                continue
            normalized = _canonical(event.get("ret"))
            values.append(
                {
                    **normalized,
                    "ts": event.get("ts"),
                    "tid": event.get("tid"),
                    "phase": event.get("phase"),
                }
            )

    return values


def summarize_values(
    events: list[dict[str, Any]],
    probe: dict[str, Any],
) -> dict[str, Any]:
    values = extract_values(events, probe)
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

    distinct_values = [
        {
            **distinct[key],
            "count": counts[key],
        }
        for key in sorted(distinct)
    ]
    stable = len(distinct_values) == 1 and bool(values)
    stable_value = distinct_values[0] if stable else None

    return {
        "probe_fingerprint": probe_fingerprint(probe),
        "sample_count": len(values),
        "distinct_count": len(distinct_values),
        "stable": stable,
        "stable_value": stable_value,
        "distinct_values": distinct_values[:20],
        "samples": [
            {
                "type": item["type"],
                "value": item["value"],
                "canonical": item["canonical"],
                "ts": item.get("ts"),
                "tid": item.get("tid"),
            }
            for item in values[:20]
        ],
    }


def _stable_bool(summary: dict[str, Any]) -> bool | None:
    value = summary.get("stable_value")
    if not isinstance(value, dict) or value.get("type") != "boolean":
        return None
    return bool(value.get("value"))


def compare_captures(
    capture_a: dict[str, Any],
    capture_b: dict[str, Any],
    branch_orientation: str = "",
) -> dict[str, Any]:
    fp_a = str(capture_a.get("probe_fingerprint", ""))
    fp_b = str(capture_b.get("probe_fingerprint", ""))
    comparable = bool(fp_a and fp_a == fp_b)

    summary_a = capture_a.get("summary") or {}
    summary_b = capture_b.get("summary") or {}
    a_stable = bool(summary_a.get("stable"))
    b_stable = bool(summary_b.get("stable"))
    a_value = summary_a.get("stable_value")
    b_value = summary_b.get("stable_value")

    if not comparable:
        status = "probe_mismatch"
        explanation = "A/B 使用的条件探针不同，不能可靠比较"
    elif not summary_a.get("sample_count") or not summary_b.get("sample_count"):
        status = "missing_samples"
        explanation = "至少一个场景没有捕获到条件值"
    elif not a_stable or not b_stable:
        status = "unstable"
        explanation = "至少一个场景在单次采集中出现多个不同条件值，暂不能归因到一个稳定分支条件"
    else:
        a_key = f"{a_value.get('type')}:{a_value.get('canonical')}" if isinstance(a_value, dict) else ""
        b_key = f"{b_value.get('type')}:{b_value.get('canonical')}" if isinstance(b_value, dict) else ""
        if a_key == b_key:
            status = "same_value"
            explanation = "A/B 在该探针上得到相同稳定值，当前探针不能解释首次分叉"
        else:
            status = "values_differ"
            explanation = "A/B 在首次分叉处得到不同且稳定的条件值"

    orientation_match: bool | None = None
    bool_a = _stable_bool(summary_a)
    bool_b = _stable_bool(summary_b)
    if comparable and bool_a is not None and bool_b is not None:
        if branch_orientation == "a_false_b_true":
            orientation_match = (bool_a is False and bool_b is True)
        elif branch_orientation == "a_true_b_false":
            orientation_match = (bool_a is True and bool_b is False)

        if orientation_match is True:
            status = "branch_orientation_confirmed"
            explanation = "A/B 布尔值与源码分支方向完全一致，动态观测支持该条件解释首次分叉"
        elif orientation_match is False and branch_orientation:
            status = "branch_orientation_conflict"
            explanation = "A/B 布尔值与源码推断的 true/false 分支方向不一致，需要检查反编译控制流或采集时机"

    evidence_level = (
        "direct"
        if status == "branch_orientation_confirmed"
        else "correlated"
        if status == "values_differ"
        else "conflicting"
        if status == "branch_orientation_conflict"
        else "inconclusive"
    )

    return {
        "ok": comparable,
        "comparable": comparable,
        "probe_fingerprint_a": fp_a,
        "probe_fingerprint_b": fp_b,
        "status": status,
        "evidence_level": evidence_level,
        "branch_orientation": branch_orientation,
        "orientation_match": orientation_match,
        "a": {
            "scenario": capture_a.get("scenario", ""),
            "sample_count": summary_a.get("sample_count", 0),
            "stable": a_stable,
            "value": a_value,
            "distinct_values": summary_a.get("distinct_values", []),
        },
        "b": {
            "scenario": capture_b.get("scenario", ""),
            "sample_count": summary_b.get("sample_count", 0),
            "stable": b_stable,
            "value": b_value,
            "distinct_values": summary_b.get("distinct_values", []),
        },
        "explanation": explanation,
    }
