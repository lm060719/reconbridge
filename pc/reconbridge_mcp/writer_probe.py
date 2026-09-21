"""字段 writer 的运行时 before/after 变化分析。"""
from __future__ import annotations

import json
from collections import deque
from typing import Any


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
    except (json.JSONDecodeError, TypeError):
        pass

    return {"type": "string", "value": text, "canonical": text}


def _field_value(event: dict[str, Any], field_name: str) -> dict[str, Any] | None:
    for field in event.get("fields") or []:
        if str(field.get("name", "")) != field_name:
            continue
        return _canonical(field.get("value"))
    return None


def analyze_writer_events(
    events: list[dict[str, Any]],
    field_name: str,
) -> dict[str, Any]:
    """按 tid 配对 before/after，提取 writer 对字段造成的值变化。"""
    ordered = sorted(
        enumerate(events),
        key=lambda pair: (
            float(pair[1].get("ts", 0) or 0),
            int(pair[1].get("seq", 0) or 0),
            pair[0],
        ),
    )
    pending: dict[Any, deque[dict[str, Any]]] = {}
    transitions: list[dict[str, Any]] = []

    for _, event in ordered:
        phase = str(event.get("phase", ""))
        tid = event.get("tid")
        value = _field_value(event, field_name)
        if value is None:
            continue

        if phase == "before":
            pending.setdefault(tid, deque()).append(
                {
                    "ts": event.get("ts"),
                    "seq": event.get("seq"),
                    "value": value,
                }
            )
            continue

        if phase != "after":
            continue
        queue = pending.get(tid)
        if not queue:
            continue
        before = queue.popleft()
        changed = (
            before["value"]["type"] != value["type"]
            or before["value"]["canonical"] != value["canonical"]
        )
        transitions.append(
            {
                "tid": tid,
                "before": before["value"],
                "after": value,
                "changed": changed,
                "before_ts": before.get("ts"),
                "after_ts": event.get("ts"),
            }
        )

    changed = [item for item in transitions if item["changed"]]
    distinct_changes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in changed:
        key = (
            str(item["before"]["canonical"]),
            str(item["after"]["canonical"]),
        )
        if key in seen:
            continue
        seen.add(key)
        distinct_changes.append(
            {
                "before": item["before"],
                "after": item["after"],
            }
        )

    return {
        "event_count": len(events),
        "paired_calls": len(transitions),
        "changed_calls": len(changed),
        "changed": bool(changed),
        "transitions": transitions[:50],
        "distinct_changes": distinct_changes[:20],
    }
