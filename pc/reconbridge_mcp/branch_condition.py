"""A/B 场景首次分叉的源码条件定位。

输入 JADX 方法源码片段和场景差分结果，提取 if/else、switch、Kotlin when 与三元表达式，
并根据 A/B 下一跳方法是否出现在各分支体中做可解释排序。
"""
from __future__ import annotations

import re
from typing import Any

_LINE_PREFIX_RE = re.compile(r"^\s*\d+\s*\|\s?")
_CALL_SITE_RE = re.compile(
    r"((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)\s*\("
)
_IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_KEYWORDS = {
    "if", "else", "switch", "case", "default", "return", "throw", "new",
    "for", "while", "do", "try", "catch", "finally", "synchronized",
    "when", "true", "false", "null", "this", "super", "instanceof",
}


def strip_numbered_source(text: str) -> tuple[str, list[int]]:
    """去掉 source_method_context 添加的行号前缀，同时保留原始行号映射。"""
    clean_lines: list[str] = []
    line_numbers: list[int] = []
    for raw in (text or "").splitlines():
        match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw)
        if match:
            line_numbers.append(int(match.group(1)))
            clean_lines.append(match.group(2))
        else:
            line_numbers.append(len(line_numbers) + 1)
            clean_lines.append(_LINE_PREFIX_RE.sub("", raw))
    return "\n".join(clean_lines), line_numbers


def _simple_method(label: str | None) -> str:
    if not label:
        return ""
    return str(label).rsplit(".", 1)[-1]


def _call_sites(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _CALL_SITE_RE.finditer(text or ""):
        expression = match.group(1)
        name = expression.rsplit(".", 1)[-1]
        if name in _KEYWORDS or expression in seen:
            continue
        seen.add(expression)
        receiver = expression.rsplit(".", 1)[0] if "." in expression else ""
        out.append(
            {
                "expression": expression,
                "receiver": receiver,
                "method": name,
            }
        )
    return out


def _calls(text: str) -> list[str]:
    return [item["method"] for item in _call_sites(text)]


def _identifiers(text: str) -> list[str]:
    out: list[str] = []
    for token in _IDENT_RE.findall(text or ""):
        if token in _KEYWORDS or token[0].isdigit() or token in out:
            continue
        out.append(token)
    return out


def _match_pair(text: str, start: int, open_char: str, close_char: str) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        ch = text[index]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {'"', "'"}:
            quote = ch
            continue
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _line_number(text: str, offset: int, line_numbers: list[int]) -> int:
    local_index = text.count("\n", 0, max(0, offset))
    if 0 <= local_index < len(line_numbers):
        return line_numbers[local_index]
    return local_index + 1


def _skip_space(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _statement_end(text: str, start: int) -> int:
    """找无花括号单语句的分号；最多扫描到下一行/较短窗口。"""
    quote = ""
    escaped = False
    paren = 0
    limit = min(len(text), start + 1200)
    for index in range(start, limit):
        ch = text[index]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {'"', "'"}:
            quote = ch
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == ";" and paren == 0:
            return index
    return min(len(text) - 1, limit - 1)


def _body_after(text: str, start: int) -> tuple[str, int]:
    index = _skip_space(text, start)
    if index < len(text) and text[index] == "{":
        end = _match_pair(text, index, "{", "}")
        if end >= 0:
            return text[index + 1 : end], end + 1
    end = _statement_end(text, index)
    return text[index : end + 1], end + 1


def _extract_if_candidates(
    text: str,
    line_numbers: list[int],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in re.finditer(r"\bif\s*\(", text):
        open_paren = text.find("(", match.start())
        close_paren = _match_pair(text, open_paren, "(", ")")
        if close_paren < 0:
            continue
        condition = text[open_paren + 1 : close_paren].strip()
        true_body, after_true = _body_after(text, close_paren + 1)

        false_body = ""
        after = _skip_space(text, after_true)
        else_match = re.match(r"else\b", text[after:])
        if else_match:
            false_body, _ = _body_after(text, after + else_match.end())

        out.append(
            {
                "type": "if",
                "line": _line_number(text, match.start(), line_numbers),
                "condition": condition,
                "identifiers": _identifiers(condition),
                "condition_calls": _calls(condition),
                "condition_call_sites": _call_sites(condition),
                "true_calls": _calls(true_body),
                "false_calls": _calls(false_body),
                "true_preview": " ".join(true_body.strip().split())[:600],
                "false_preview": " ".join(false_body.strip().split())[:600],
            }
        )
    return out


def _extract_switch_candidates(
    text: str,
    line_numbers: list[int],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in re.finditer(r"\bswitch\s*\(", text):
        open_paren = text.find("(", match.start())
        close_paren = _match_pair(text, open_paren, "(", ")")
        if close_paren < 0:
            continue
        expr = text[open_paren + 1 : close_paren].strip()
        brace = _skip_space(text, close_paren + 1)
        if brace >= len(text) or text[brace] != "{":
            continue
        end = _match_pair(text, brace, "{", "}")
        if end < 0:
            continue
        body = text[brace + 1 : end]
        markers = list(re.finditer(r"(?m)^\s*(case\s+[^:]+|default)\s*:", body))
        branches: list[dict[str, Any]] = []
        for index, marker in enumerate(markers):
            start = marker.end()
            stop = markers[index + 1].start() if index + 1 < len(markers) else len(body)
            branch_body = body[start:stop]
            branches.append(
                {
                    "label": marker.group(1).strip(),
                    "calls": _calls(branch_body),
                    "preview": " ".join(branch_body.strip().split())[:500],
                }
            )
        out.append(
            {
                "type": "switch",
                "line": _line_number(text, match.start(), line_numbers),
                "condition": expr,
                "identifiers": _identifiers(expr),
                "condition_calls": _calls(expr),
                "condition_call_sites": _call_sites(expr),
                "branches": branches,
            }
        )
    return out


def _extract_when_candidates(
    text: str,
    line_numbers: list[int],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in re.finditer(r"\bwhen\s*\(", text):
        open_paren = text.find("(", match.start())
        close_paren = _match_pair(text, open_paren, "(", ")")
        if close_paren < 0:
            continue
        expr = text[open_paren + 1 : close_paren].strip()
        brace = _skip_space(text, close_paren + 1)
        if brace >= len(text) or text[brace] != "{":
            continue
        end = _match_pair(text, brace, "{", "}")
        if end < 0:
            continue
        body = text[brace + 1 : end]
        branches: list[dict[str, Any]] = []
        for raw in body.splitlines():
            if "->" not in raw:
                continue
            label, branch_body = raw.split("->", 1)
            branches.append(
                {
                    "label": label.strip(),
                    "calls": _calls(branch_body),
                    "preview": " ".join(branch_body.strip().split())[:500],
                }
            )
        out.append(
            {
                "type": "when",
                "line": _line_number(text, match.start(), line_numbers),
                "condition": expr,
                "identifiers": _identifiers(expr),
                "condition_calls": _calls(expr),
                "branches": branches,
            }
        )
    return out


def _extract_ternary_candidates(
    text: str,
    line_numbers: list[int],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line_index, line in enumerate(text.splitlines()):
        if "?" not in line or ":" not in line:
            continue
        match = re.search(
            r"(?P<cond>[A-Za-z_$][^?;{}]{0,240})\?"
            r"(?P<yes>[^:;{}]{1,240}):(?P<no>[^;{}]{1,240})",
            line,
        )
        if not match:
            continue
        condition = match.group("cond").strip()
        out.append(
            {
                "type": "ternary",
                "line": (
                    line_numbers[line_index]
                    if line_index < len(line_numbers)
                    else line_index + 1
                ),
                "condition": condition,
                "identifiers": _identifiers(condition),
                "condition_calls": _calls(condition),
                "condition_call_sites": _call_sites(condition),
                "true_calls": _calls(match.group("yes")),
                "false_calls": _calls(match.group("no")),
                "true_preview": match.group("yes").strip()[:500],
                "false_preview": match.group("no").strip()[:500],
            }
        )
    return out


def extract_conditions(source_text: str) -> list[dict[str, Any]]:
    clean, line_numbers = strip_numbered_source(source_text)
    candidates: list[dict[str, Any]] = []
    candidates.extend(_extract_if_candidates(clean, line_numbers))
    candidates.extend(_extract_switch_candidates(clean, line_numbers))
    candidates.extend(_extract_when_candidates(clean, line_numbers))
    candidates.extend(_extract_ternary_candidates(clean, line_numbers))

    seen: set[tuple[str, int, str]] = set()
    result: list[dict[str, Any]] = []
    for item in sorted(candidates, key=lambda row: (int(row["line"]), row["type"])):
        key = (str(item["type"]), int(item["line"]), str(item["condition"]))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _branch_matches(
    candidate: dict[str, Any],
    a_method: str,
    b_method: str,
) -> tuple[bool, bool, bool]:
    """返回 A/B 是否分别映射到不同分支，以及是否方向相反。"""
    if candidate["type"] in {"if", "ternary"}:
        true_calls = set(candidate.get("true_calls") or [])
        false_calls = set(candidate.get("false_calls") or [])
        forward = bool(a_method and b_method and a_method in true_calls and b_method in false_calls)
        reverse = bool(a_method and b_method and b_method in true_calls and a_method in false_calls)
        any_match = bool(
            (a_method and (a_method in true_calls or a_method in false_calls))
            or (b_method and (b_method in true_calls or b_method in false_calls))
        )
        return forward or reverse, any_match, reverse

    branches = candidate.get("branches") or []
    a_branch = next((index for index, branch in enumerate(branches) if a_method in branch.get("calls", [])), None)
    b_branch = next((index for index, branch in enumerate(branches) if b_method in branch.get("calls", [])), None)
    separated = a_branch is not None and b_branch is not None and a_branch != b_branch
    return separated, a_branch is not None or b_branch is not None, False


def rank_conditions(
    source_text: str,
    a_next: str | None,
    b_next: str | None,
    class_fields: list[dict[str, Any]] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """按“能否解释 A/B 下一跳 + 条件是否依赖字段/方法”给条件候选排序。"""
    a_method = _simple_method(a_next)
    b_method = _simple_method(b_next)
    field_names = {
        str(item.get("field", ""))
        for item in (class_fields or [])
        if item.get("field")
    }

    ranked: list[dict[str, Any]] = []
    for item in extract_conditions(source_text):
        score = 0
        reasons: list[str] = []
        separated, any_branch_match, reverse = _branch_matches(item, a_method, b_method)

        if separated:
            score += 120
            reasons.append("A/B 下一跳分别出现在该条件的不同分支")
        elif any_branch_match:
            score += 45
            reasons.append("A 或 B 下一跳出现在该条件分支体")

        identifiers = set(item.get("identifiers") or [])
        matched_fields = sorted(identifiers & field_names)
        if matched_fields:
            score += min(45, 15 * len(matched_fields))
            reasons.append("条件直接引用类字段: " + ", ".join(matched_fields[:4]))

        condition_calls = item.get("condition_calls") or []
        if condition_calls:
            score += min(30, 10 * len(condition_calls))
            reasons.append("条件调用方法: " + ", ".join(condition_calls[:4]))

        condition_lower = str(item.get("condition", "")).lower()
        boolean_hints = (
            "is", "has", "can", "should", "enable", "allow", "valid",
            "vip", "member", "premium", "auth", "login", "status",
        )
        if any(hint in condition_lower for hint in boolean_hints):
            score += 8
            reasons.append("条件名称具有布尔/状态判断特征")

        if item["type"] in {"switch", "when"} and len(item.get("branches") or []) >= 2:
            score += 5
            reasons.append("多分支控制结构")

        row = {
            **item,
            "score": score,
            "reasons": reasons,
            "matched_fields": matched_fields,
            "a_next_method": a_method,
            "b_next_method": b_method,
            "branch_orientation": (
                "a_false_b_true"
                if reverse
                else "a_true_b_false"
                if separated and item["type"] in {"if", "ternary"}
                else ""
            ),
        }
        ranked.append(row)

    ranked.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            int(item.get("line", 0)),
        )
    )
    limit = max(1, min(int(limit), 50))
    for index, item in enumerate(ranked[:limit], 1):
        item["rank"] = index
    return ranked[:limit]


def build_probe_plan(
    class_name: str,
    method_name: str,
    ranked_conditions: list[dict[str, Any]],
    max_items: int = 8,
) -> list[dict[str, Any]]:
    """根据条件候选生成下一步可直接执行的 trace 计划，不做篡改。"""
    max_items = max(1, min(int(max_items), 20))
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for condition in ranked_conditions:
        for field in condition.get("matched_fields") or []:
            key = ("field", field)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "kind": "field",
                    "condition_rank": condition.get("rank"),
                    "condition_line": condition.get("line"),
                    "condition": condition.get("condition", ""),
                    "class": class_name,
                    "method": method_name,
                    "field": field,
                    "tool": "trace_java",
                    "suggested_args": {
                        "class_name": class_name,
                        "method": method_name,
                        "when": "before",
                        "fields": [
                            {
                                "target": "this",
                                "name": field,
                                "render": "tostring",
                            }
                        ],
                    },
                }
            )
            if len(out) >= max_items:
                return out

        call_sites = condition.get("condition_call_sites") or [
            {"expression": called, "receiver": "", "method": called}
            for called in condition.get("condition_calls") or []
        ]
        for site in call_sites:
            called = str(site.get("method", ""))
            receiver = str(site.get("receiver", ""))
            if not called:
                continue
            key = ("method", str(site.get("expression", called)))
            if key in seen:
                continue
            seen.add(key)

            same_class = receiver in {"", "this", "super"}
            if same_class:
                out.append(
                    {
                        "kind": "condition_method",
                        "condition_rank": condition.get("rank"),
                        "condition_line": condition.get("line"),
                        "condition": condition.get("condition", ""),
                        "expression": site.get("expression", called),
                        "class": class_name,
                        "method": called,
                        "tool": "trace_target",
                        "suggested_args": {
                            "class_name": class_name,
                            "method": called,
                        },
                    }
                )
            else:
                out.append(
                    {
                        "kind": "condition_call_expression",
                        "condition_rank": condition.get("rank"),
                        "condition_line": condition.get("line"),
                        "condition": condition.get("condition", ""),
                        "expression": site.get("expression", called),
                        "receiver": receiver,
                        "method": called,
                        "tool": None,
                        "note": "接收者不是 this/super，需先解析接收者实际类型后再 Hook",
                    }
                )
            if len(out) >= max_items:
                return out
    return out
