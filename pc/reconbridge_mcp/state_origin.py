"""条件字段/条件方法的静态值来源解释。"""
from __future__ import annotations

import re
from typing import Any


_CALL_RE = re.compile(
    r"((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)\s*\("
)
_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]*$")


def strip_numbered_source(text: str) -> str:
    lines: list[str] = []
    for raw in (text or "").splitlines():
        match = re.match(r"^\s*\d+\s*\|\s?(.*)$", raw)
        lines.append(match.group(1) if match else raw)
    return "\n".join(lines)


def call_sites(expression: str) -> list[str]:
    out: list[str] = []
    for match in _CALL_RE.finditer(expression or ""):
        value = match.group(1)
        if value not in out:
            out.append(value)
    return out


def classify_expression(expression: str) -> list[dict[str, Any]]:
    """对一个赋值/return 右值做保守来源分类。"""
    expr = (expression or "").strip()
    lowered = expr.casefold()
    hints: list[dict[str, Any]] = []

    def add(kind: str, confidence: float, reason: str) -> None:
        if any(item["kind"] == kind for item in hints):
            return
        hints.append(
            {
                "kind": kind,
                "confidence": round(float(confidence), 2),
                "reason": reason,
            }
        )

    if re.search(r"\b(true|false|null|\d+(?:\.\d+)?)\b", expr):
        add("literal_or_constant", 0.45, "右值包含字面量/常量")

    if any(token in lowered for token in (
        "sharedpreferences", "getboolean(", "getstring(", "getint(",
        "getlong(", "getfloat(", "preferences", "pref.",
    )):
        add("preferences", 0.95, "右值看起来来自 SharedPreferences/偏好存储")

    if any(token in lowered for token in (
        "getintent(", "getbooleanextra(", "getstringextra(", "getintextra(",
        "bundle", "savedstatehandle", "savedstate",
    )):
        add("intent_or_state", 0.9, "右值看起来来自 Intent/Bundle/SavedState")

    if any(token in lowered for token in (
        "dao.", "database", "room", "sqlite", "cursor", "contentresolver",
        "query(", "loadfromdb", "repository.getcached", "cache.",
    )):
        add("database_or_cache", 0.82, "右值包含数据库/缓存访问特征")

    if any(token in lowered for token in (
        "api.", "service.", "retrofit", "okhttp", "response", "repository.",
        "remote", "fetch", "request", "network", "queryvip", "getmemberinfo",
    )):
        add("network_or_repository", 0.82, "右值包含 Repository/API/网络结果特征")

    if any(token in lowered for token in (
        "user.", "profile.", "account.", "member", "premium", "vip",
        "subscription", "entitlement",
    )):
        add("user_or_membership_model", 0.75, "右值引用用户/会员/订阅模型")

    calls = call_sites(expr)
    if calls:
        add("method_result", 0.7, "右值来自方法调用: " + ", ".join(calls[:4]))

    if _IDENT_RE.fullmatch(expr):
        if "." in expr:
            add("object_field_or_getter_result", 0.55, "右值是对象属性/成员引用")
        else:
            add("local_or_parameter", 0.5, "右值是局部变量或方法参数")

    if not hints:
        add("unknown_expression", 0.2, "未识别到明确来源模式")

    hints.sort(key=lambda item: -float(item["confidence"]))
    return hints


def extract_field_assignments(
    source_text: str,
    field_name: str,
) -> list[dict[str, Any]]:
    """从 JADX 方法源码中提取写入目标字段的赋值表达式。"""
    clean = strip_numbered_source(source_text)
    lines = clean.splitlines()
    field = re.escape(field_name)
    pattern = re.compile(
        rf"(?<![=!<>])(?:(?:this\.|[A-Za-z_$][\w$]*\.)?{field})\s*=\s*(?!=)(.+?)(?:;|$)"
    )

    out: list[dict[str, Any]] = []
    for index, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        for match in pattern.finditer(line):
            expr = match.group(1).strip()
            if not expr:
                continue
            out.append(
                {
                    "line_offset": index,
                    "statement": stripped[:800],
                    "expression": expr[:800],
                    "calls": call_sites(expr),
                    "source_hints": classify_expression(expr),
                }
            )
    return out


def extract_return_sources(source_text: str) -> list[dict[str, Any]]:
    """提取条件方法的 return 表达式及来源。"""
    clean = strip_numbered_source(source_text)
    out: list[dict[str, Any]] = []
    for index, line in enumerate(clean.splitlines(), 1):
        match = re.search(r"\breturn\s+(.+?)(?:;|$)", line)
        if not match:
            continue
        expr = match.group(1).strip()
        if not expr:
            continue
        out.append(
            {
                "line_offset": index,
                "statement": line.strip()[:800],
                "expression": expr[:800],
                "calls": call_sites(expr),
                "source_hints": classify_expression(expr),
            }
        )
    return out


def rank_field_writers(
    field_name: str,
    writers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """对带 source 上下文的 writer 列表做可解释排序。"""
    ranked: list[dict[str, Any]] = []
    for writer in writers:
        row = dict(writer)
        source = row.get("source") or {}
        assignments = (
            extract_field_assignments(str(source.get("text", "")), field_name)
            if source.get("available")
            else []
        )

        score = 0
        reasons: list[str] = []
        if assignments:
            score += 100
            reasons.append("JADX 源码中找到目标字段直接赋值")
        if row.get("runtime_confirmed"):
            score += 35
            reasons.append("该 writer 已有运行时命中证据")

        best_hint: dict[str, Any] | None = None
        for assignment in assignments:
            for hint in assignment.get("source_hints") or []:
                if best_hint is None or float(hint["confidence"]) > float(best_hint["confidence"]):
                    best_hint = hint
        if best_hint:
            score += int(float(best_hint["confidence"]) * 40)
            reasons.append(best_hint["reason"])

        row["assignments"] = assignments
        row["score"] = score
        row["reasons"] = reasons
        row["best_source_hint"] = best_hint
        ranked.append(row)

    ranked.sort(
        key=lambda item: (
            -int(item.get("score", 0)),
            str(item.get("class", "")),
            str(item.get("method", "")),
            int(item.get("offset", 0) or 0),
        )
    )
    for index, item in enumerate(ranked, 1):
        item["rank"] = index
    return ranked


def analyze_condition_method_source(source_text: str) -> dict[str, Any]:
    returns = extract_return_sources(source_text)
    hints: list[dict[str, Any]] = []
    for item in returns:
        for hint in item.get("source_hints") or []:
            if hint["kind"] not in {row["kind"] for row in hints}:
                hints.append(hint)
    hints.sort(key=lambda item: -float(item["confidence"]))
    return {
        "return_count": len(returns),
        "returns": returns,
        "source_hints": hints,
        "best_source_hint": hints[0] if hints else None,
    }
