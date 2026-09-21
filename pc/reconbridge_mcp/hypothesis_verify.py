"""Root Cause 假设实验规划、单场景摘要与 A/B 验证。"""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from typing import Any


_PRIMITIVES = {
    "B": "byte",
    "C": "char",
    "D": "double",
    "F": "float",
    "I": "int",
    "J": "long",
    "S": "short",
    "Z": "boolean",
    "V": "void",
}


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
            "canonical": text[:12000],
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
        "value": text[:12000],
        "canonical": text[:12000],
    }


def _parse_type(descriptor: str, start: int) -> tuple[dict[str, Any], int]:
    if start >= len(descriptor):
        raise ValueError("descriptor ended unexpectedly")

    char = descriptor[start]
    if char in _PRIMITIVES:
        name = _PRIMITIVES[char]
        return {
            "descriptor": char,
            "java_name": name,
            "primitive": char != "V",
            "array": False,
            "precise_param_supported": True,
        }, start + 1

    if char == "L":
        end = descriptor.find(";", start)
        if end < 0:
            raise ValueError("unterminated object descriptor")
        raw = descriptor[start : end + 1]
        return {
            "descriptor": raw,
            "java_name": raw[1:-1].replace("/", "."),
            "primitive": False,
            "array": False,
            "precise_param_supported": True,
        }, end + 1

    if char == "[":
        component, end = _parse_type(descriptor, start + 1)
        raw = descriptor[start:end]
        return {
            "descriptor": raw,
            "java_name": component["java_name"] + "[]",
            "primitive": False,
            "array": True,
            # 当前 tracer resolveType 直接 ClassLoader.loadClass(name)，
            # 对 Java [] 语法数组名不可靠，因此数组签名退回全部同名重载。
            "precise_param_supported": False,
        }, end

    raise ValueError(f"unsupported descriptor token: {char}")


def parse_method_descriptor(descriptor: str) -> dict[str, Any]:
    descriptor = (descriptor or "").strip()
    if not descriptor.startswith("(") or ")" not in descriptor:
        return {
            "ok": False,
            "descriptor": descriptor,
            "params": [],
            "return": None,
            "precise_params": False,
        }

    close = descriptor.find(")")
    params: list[dict[str, Any]] = []
    index = 1
    try:
        while index < close:
            item, index = _parse_type(descriptor, index)
            params.append(item)
        ret, end = _parse_type(descriptor, close + 1)
        if end != len(descriptor):
            raise ValueError("trailing descriptor data")
    except ValueError:
        return {
            "ok": False,
            "descriptor": descriptor,
            "params": [],
            "return": None,
            "precise_params": False,
        }

    return {
        "ok": True,
        "descriptor": descriptor,
        "params": params,
        "return": ret,
        "precise_params": all(
            bool(item.get("precise_param_supported"))
            for item in params
        ),
    }


def _field_render(field_type: str) -> str:
    if not field_type:
        return "tostring"
    if field_type[0] in _PRIMITIVES:
        return "tostring"
    return "deep"


def _return_render(parsed: dict[str, Any]) -> str:
    ret = parsed.get("return") or {}
    if ret.get("primitive") or ret.get("java_name") == "void":
        return "tostring"
    return "deep"


def _referenced_fields(
    source_text: str,
    class_fields: list[dict[str, Any]],
    limit: int,
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    total = 0
    text = source_text or ""
    for field in class_fields:
        name = str(field.get("field", ""))
        if not name:
            continue
        if not re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text):
            continue
        total += 1
        if len(rows) >= limit:
            continue
        field_type = str(field.get("type", ""))
        rows.append(
            {
                "target": "this",
                "name": name,
                "type": field_type,
                "render": _field_render(field_type),
                "max": 2500,
            }
        )
    return rows, total


def plan_experiment(
    candidate: dict[str, Any],
    method_context: dict[str, Any],
    max_args: int = 8,
    max_fields: int = 6,
) -> dict[str, Any]:
    """为一个方法根因候选生成尽量小但可比较的输入/输出实验。"""
    if candidate.get("candidate_type") != "method":
        return {
            "ok": False,
            "error": "只有方法根因候选可以自动执行假设验证",
            "candidate": candidate,
        }

    max_args = max(0, min(int(max_args), 16))
    max_fields = max(0, min(int(max_fields), 12))
    descriptor = str(candidate.get("descriptor", ""))
    parsed = parse_method_descriptor(descriptor)

    params = parsed.get("params") or []
    precise_params = (
        [str(item["java_name"]) for item in params]
        if parsed.get("ok") and parsed.get("precise_params")
        else None
    )

    capture_args: list[dict[str, Any]] = []
    for index, item in enumerate(params[:max_args]):
        capture_args.append(
            {
                "index": index,
                "type": item.get("java_name", ""),
                "render": "tostring" if item.get("primitive") else "deep",
                "max": 3000,
            }
        )

    source = method_context.get("source") or {}
    relations = method_context.get("relations") or {}
    fields, referenced_field_count = _referenced_fields(
        str(source.get("text", "")),
        relations.get("class_fields") or [],
        max_fields,
    )

    ret = parsed.get("return") or {}
    capture_return = bool(
        not parsed.get("ok")
        or ret.get("java_name") != "void"
    )

    arg_coverage_complete = bool(
        parsed.get("ok")
        and len(params) <= max_args
    )
    field_coverage_complete = referenced_field_count <= max_fields
    input_coverage_complete = bool(
        arg_coverage_complete and field_coverage_complete
    )

    candidate_key = str(candidate.get("candidate_key", ""))
    stable = {
        "candidate_key": candidate_key,
        "class": candidate.get("class"),
        "method": candidate.get("method"),
        "descriptor": descriptor,
        "params": precise_params,
        "args": capture_args,
        "fields": fields,
        "capture_return": capture_return,
        "return_render": _return_render(parsed),
    }
    raw = json.dumps(
        stable,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    fingerprint = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:24]

    return {
        "ok": True,
        "hypothesis_fingerprint": fingerprint,
        "candidate_key": candidate_key,
        "candidate": candidate,
        "class": str(candidate.get("class", "")),
        "method": str(candidate.get("method", "")),
        "descriptor": descriptor,
        "params": precise_params,
        "overload_precision": (
            "exact"
            if precise_params is not None
            else "degraded_all_overloads"
        ),
        "capture_args": capture_args,
        "capture_fields": fields,
        "capture_return": capture_return,
        "return_render": _return_render(parsed),
        "input_coverage": {
            "descriptor_parsed": bool(parsed.get("ok")),
            "argument_count": len(params),
            "captured_argument_count": len(capture_args),
            "arguments_complete": arg_coverage_complete,
            "referenced_field_count": referenced_field_count,
            "captured_field_count": len(fields),
            "fields_complete": field_coverage_complete,
            "complete": input_coverage_complete,
        },
        "hypothesis": (
            "如果 A/B 在进入该方法前的可观测参数/关键字段相同，但方法输出不同，"
            "则支持“差异在该方法内部产生”；若入口输入已经不同，则更可能只是承接上游差异。"
        ),
    }


def _summarize(values: list[Any]) -> dict[str, Any]:
    normalized = [_canonical(value) for value in values]
    distinct: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for item in normalized:
        key = f"{item['type']}:{item['canonical']}"
        if key not in distinct:
            distinct[key] = item
            counts[key] = 0
        counts[key] += 1

    rows = [
        {
            **distinct[key],
            "count": counts[key],
        }
        for key in sorted(distinct)
    ]
    stable = len(rows) == 1 and bool(normalized)
    return {
        "sample_count": len(normalized),
        "distinct_count": len(rows),
        "stable": stable,
        "stable_value": rows[0] if stable else None,
        "distinct_values": rows[:12],
    }


def _best_tid(events: list[dict[str, Any]]) -> Any:
    grouped: dict[Any, dict[str, int]] = {}
    for event in events:
        tid = event.get("tid")
        phase = str(event.get("phase", ""))
        row = grouped.setdefault(
            tid,
            {"before": 0, "after": 0},
        )
        if phase in row:
            row[phase] += 1

    best_tid = None
    best_key = (-1, -1)
    for tid, counts in grouped.items():
        pair_count = min(counts["before"], counts["after"])
        score = (pair_count, counts["before"] + counts["after"])
        if score > best_key:
            best_key = score
            best_tid = tid
    return best_tid


def analyze_capture(
    events: list[dict[str, Any]],
    plan: dict[str, Any],
) -> dict[str, Any]:
    """压缩一次假设实验，只保留稳定输入/输出和值域摘要。"""
    primary_tid = _best_tid(events)
    selected = [
        event
        for event in events
        if primary_tid is None or event.get("tid") == primary_tid
    ]
    before = [
        event for event in selected
        if str(event.get("phase", "")) == "before"
    ]
    after = [
        event for event in selected
        if str(event.get("phase", "")) == "after"
    ]

    arg_indexes = [
        int(item.get("index", -1))
        for item in (plan.get("capture_args") or [])
        if int(item.get("index", -1)) >= 0
    ]
    if not arg_indexes:
        for event in before:
            for item in event.get("args") or []:
                try:
                    index = int(item.get("index", -1))
                except (TypeError, ValueError):
                    continue
                if index >= 0 and index not in arg_indexes:
                    arg_indexes.append(index)
        arg_indexes.sort()

    args: dict[str, Any] = {}
    for index in arg_indexes:
        values = []
        for event in before:
            for item in event.get("args") or []:
                if int(item.get("index", -1)) == index:
                    values.append(item.get("value"))
                    break
        args[str(index)] = _summarize(values)

    field_names = [
        str(item.get("name", ""))
        for item in (plan.get("capture_fields") or [])
        if item.get("name")
    ]
    fields_before: dict[str, Any] = {}
    fields_after: dict[str, Any] = {}
    for name in field_names:
        before_values = []
        after_values = []
        for event in before:
            for item in event.get("fields") or []:
                if str(item.get("name", "")) == name:
                    before_values.append(item.get("value"))
                    break
        for event in after:
            for item in event.get("fields") or []:
                if str(item.get("name", "")) == name:
                    after_values.append(item.get("value"))
                    break
        fields_before[name] = _summarize(before_values)
        fields_after[name] = _summarize(after_values)

    ret = _summarize(
        [
            event.get("ret")
            for event in after
            if "ret" in event
        ]
    )

    return {
        "event_count": len(events),
        "primary_tid": primary_tid,
        "before_count": len(before),
        "after_count": len(after),
        "args": args,
        "fields_before": fields_before,
        "fields_after": fields_after,
        "return": ret,
        "input_coverage": plan.get("input_coverage", {}),
    }


def _compare_summary(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    left_value = left.get("stable_value")
    right_value = right.get("stable_value")
    comparable = bool(
        left.get("stable")
        and right.get("stable")
        and isinstance(left_value, dict)
        and isinstance(right_value, dict)
    )
    same = None
    if comparable:
        same = (
            left_value.get("type") == right_value.get("type")
            and left_value.get("canonical")
            == right_value.get("canonical")
        )
    return {
        "comparable": comparable,
        "same": same,
        "a_value": left_value,
        "b_value": right_value,
    }


def compare_captures(
    capture_a: dict[str, Any],
    capture_b: dict[str, Any],
) -> dict[str, Any]:
    fp_a = str(capture_a.get("hypothesis_fingerprint", ""))
    fp_b = str(capture_b.get("hypothesis_fingerprint", ""))
    comparable = bool(fp_a and fp_a == fp_b)
    if not comparable:
        return {
            "ok": False,
            "comparable": False,
            "status": "hypothesis_mismatch",
            "score_adjustment": 0,
            "error": "A/B 使用的 Root Cause 假设实验不同，不能可靠比较",
        }

    analysis_a = capture_a.get("analysis") or {}
    analysis_b = capture_b.get("analysis") or {}

    inputs: list[dict[str, Any]] = []
    differing_inputs: list[dict[str, Any]] = []
    same_inputs: list[dict[str, Any]] = []

    arg_keys = sorted(
        set((analysis_a.get("args") or {}))
        | set((analysis_b.get("args") or {})),
        key=lambda value: int(value),
    )
    for key in arg_keys:
        row = {
            "kind": "arg",
            "name": f"args[{key}]",
            **_compare_summary(
                (analysis_a.get("args") or {}).get(key, {}),
                (analysis_b.get("args") or {}).get(key, {}),
            ),
        }
        inputs.append(row)
        if row["comparable"] and row["same"] is False:
            differing_inputs.append(row)
        elif row["comparable"] and row["same"] is True:
            same_inputs.append(row)

    field_keys = sorted(
        set((analysis_a.get("fields_before") or {}))
        | set((analysis_b.get("fields_before") or {}))
    )
    for key in field_keys:
        row = {
            "kind": "field_before",
            "name": key,
            **_compare_summary(
                (analysis_a.get("fields_before") or {}).get(key, {}),
                (analysis_b.get("fields_before") or {}).get(key, {}),
            ),
        }
        inputs.append(row)
        if row["comparable"] and row["same"] is False:
            differing_inputs.append(row)
        elif row["comparable"] and row["same"] is True:
            same_inputs.append(row)

    outputs: list[dict[str, Any]] = []
    ret_cmp = _compare_summary(
        analysis_a.get("return") or {},
        analysis_b.get("return") or {},
    )
    if ret_cmp["comparable"]:
        outputs.append(
            {
                "kind": "return",
                "name": "return",
                **ret_cmp,
            }
        )

    after_keys = sorted(
        set((analysis_a.get("fields_after") or {}))
        | set((analysis_b.get("fields_after") or {}))
    )
    for key in after_keys:
        cmp = _compare_summary(
            (analysis_a.get("fields_after") or {}).get(key, {}),
            (analysis_b.get("fields_after") or {}).get(key, {}),
        )
        if cmp["comparable"]:
            outputs.append(
                {
                    "kind": "field_after",
                    "name": key,
                    **cmp,
                }
            )

    differing_outputs = [
        item for item in outputs
        if item.get("same") is False
    ]
    same_outputs = [
        item for item in outputs
        if item.get("same") is True
    ]
    comparable_inputs = [
        item for item in inputs
        if item.get("comparable")
    ]

    coverage_a = analysis_a.get("input_coverage") or {}
    coverage_b = analysis_b.get("input_coverage") or {}
    planned_input_count = max(
        int(coverage_a.get("captured_argument_count", 0) or 0)
        + int(coverage_a.get("captured_field_count", 0) or 0),
        int(coverage_b.get("captured_argument_count", 0) or 0)
        + int(coverage_b.get("captured_field_count", 0) or 0),
    )
    observed_input_complete = bool(
        planned_input_count > 0
        and len(comparable_inputs) == planned_input_count
    )
    input_coverage_complete = bool(
        coverage_a.get("complete")
        and coverage_b.get("complete")
        and observed_input_complete
    )

    if differing_outputs and differing_inputs:
        status = "upstream_input_difference"
        score_adjustment = -30
        explanation = (
            "A/B 输出不同，但进入候选方法前已经存在可观测输入差异；"
            "该方法更像承接上游差异，而不是当前最小可证实的产生点"
        )
    elif (
        differing_outputs
        and comparable_inputs
        and not differing_inputs
        and input_coverage_complete
    ):
        status = "internal_generation_supported"
        score_adjustment = 30
        explanation = (
            "A/B 可观测入口输入一致且覆盖完整，但方法输出不同；"
            "运行时证据支持差异在该方法内部产生"
        )
    elif differing_outputs and comparable_inputs and not differing_inputs:
        status = "internal_generation_partial"
        score_adjustment = 15
        explanation = (
            "已捕获的 A/B 入口输入一致而输出不同，但输入覆盖不完整；"
            "支持内部产生假设，但仍可能存在未观测字段/全局状态"
        )
    elif differing_outputs:
        status = "output_difference_without_inputs"
        score_adjustment = 8
        explanation = (
            "A/B 输出不同，但没有足够可比较的入口输入；"
            "只能确认差异在此处可见，尚不能证明在此产生"
        )
    elif outputs and same_outputs and not differing_outputs:
        status = "not_reproduced"
        score_adjustment = -25
        explanation = (
            "本轮假设实验中 A/B 输出相同，没有复现该候选的差异"
        )
    else:
        status = "inconclusive"
        score_adjustment = 0
        explanation = (
            "输入或输出缺少稳定可比较值，当前实验不足以判断差异产生位置"
        )

    return {
        "ok": True,
        "comparable": True,
        "hypothesis_fingerprint": fp_a,
        "candidate_key": str(capture_a.get("candidate_key", "")),
        "status": status,
        "score_adjustment": score_adjustment,
        "input_coverage_complete": input_coverage_complete,
        "planned_input_count": planned_input_count,
        "comparable_input_count": len(comparable_inputs),
        "observed_input_complete": observed_input_complete,
        "differing_inputs": differing_inputs,
        "same_inputs": same_inputs,
        "outputs": outputs,
        "differing_outputs": differing_outputs,
        "explanation": explanation,
        "a": capture_a.get("scenario", ""),
        "b": capture_b.get("scenario", ""),
    }
