"""APK DEX 持久索引。

首次由受资源限制的 Androguard worker 建库；后续搜索、字符串 xref 和方法调用关系
全部直接查询 SQLite，不再重复解析 APK。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .settings import settings

SCHEMA_VERSION = 2


def apk_cache_key(apk: Path) -> str:
    stat = apk.stat()
    raw = f"{apk.resolve()}|{stat.st_size}|{stat.st_mtime_ns}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def index_path_for_apk(apk_path: str | Path) -> Path:
    apk = Path(apk_path)
    root = settings.workdir / ".index" / "dex"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{apk_cache_key(apk)}.sqlite3"


def index_is_ready(apk_path: str | Path) -> bool:
    apk = Path(apk_path)
    if not apk.exists():
        return False
    path = index_path_for_apk(apk)
    if not path.exists():
        return False

    try:
        with sqlite3.connect(path) as conn:
            rows = dict(conn.execute("SELECT key, value FROM meta"))
        stat = apk.stat()
        return (
            int(rows.get("schema_version", "0")) == SCHEMA_VERSION
            and int(rows.get("apk_size", "-1")) == stat.st_size
            and int(rows.get("apk_mtime_ns", "-1")) == stat.st_mtime_ns
            and rows.get("complete") == "1"
        )
    except (OSError, sqlite3.Error, ValueError):
        return False


def index_status(apk_path: str | Path) -> dict[str, Any]:
    apk = Path(apk_path)
    path = index_path_for_apk(apk) if apk.exists() else None
    result: dict[str, Any] = {
        "ready": bool(apk.exists() and index_is_ready(apk)),
        "path": str(path) if path else "",
        "bytes": path.stat().st_size if path and path.exists() else 0,
        "schema_version": SCHEMA_VERSION,
    }
    if not result["ready"]:
        return result

    try:
        with sqlite3.connect(path) as conn:
            for table in (
                "classes",
                "methods",
                "fields",
                "strings",
                "string_method_xrefs",
                "method_calls",
            ):
                result[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    except sqlite3.Error:
        result["ready"] = False
    return result


def _like_term(value: str) -> str:
    return f"%{value}%"


def _class_variants(class_name: str) -> list[str]:
    value = (class_name or "").strip()
    if not value:
        return [""]
    variants = [value]
    if value.startswith("L") and value.endswith(";"):
        dotted = value[1:-1].replace("/", ".")
        if dotted not in variants:
            variants.append(dotted)
    elif "/" in value:
        descriptor = value if value.startswith("L") else f"L{value};"
        dotted = value.strip("L;").replace("/", ".")
        for item in (descriptor, dotted):
            if item not in variants:
                variants.append(item)
    else:
        descriptor = "L" + value.replace(".", "/") + ";"
        if descriptor not in variants:
            variants.append(descriptor)
    return variants


def _method_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "class": row["class_name"],
        "method": row["method_name"],
        "descriptor": row["descriptor"],
        "access": row["access"],
    }


def query_index(apk_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    apk = Path(apk_path)
    if not index_is_ready(apk):
        return {"ok": False, "error": "DEX 持久索引尚未建立"}

    path = index_path_for_apk(apk)
    find = str(query.get("find", "method"))
    limit = max(1, min(int(query.get("max_results", 100)), 5000))
    results: list[dict[str, Any]] = []

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row

        if find == "string":
            term = str(query.get("string", ""))
            rows = conn.execute(
                """
                SELECT value
                FROM strings
                WHERE value LIKE ? ESCAPE '\\'
                ORDER BY length(value), value
                LIMIT ?
                """,
                (_like_term(term), limit),
            )
            results = [{"string": row["value"]} for row in rows]

        elif find == "class":
            term = str(query.get("class_name", ""))
            rows = conn.execute(
                """
                SELECT name
                FROM classes
                WHERE name LIKE ? ESCAPE '\\'
                ORDER BY length(name), name
                LIMIT ?
                """,
                (_like_term(term), limit),
            )
            results = [{"class": row["name"]} for row in rows]

        elif find == "field":
            class_term = str(query.get("class_name", ""))
            field_term = str(query.get("field_name", ""))
            rows = conn.execute(
                """
                SELECT class_name, field_name, type
                FROM fields
                WHERE class_name LIKE ? ESCAPE '\\'
                  AND field_name LIKE ? ESCAPE '\\'
                ORDER BY class_name, field_name
                LIMIT ?
                """,
                (_like_term(class_term), _like_term(field_term), limit),
            )
            results = [
                {"class": row["class_name"], "field": row["field_name"], "type": row["type"]}
                for row in rows
            ]

        else:
            using = query.get("using_strings")
            if using:
                seen: set[tuple[str, str, str]] = set()
                for keyword in using:
                    rows = conn.execute(
                        """
                        SELECT m.class_name, m.method_name, m.descriptor, m.access, s.value
                        FROM strings s
                        JOIN string_method_xrefs x ON x.string_id = s.id
                        JOIN methods m ON m.id = x.method_id
                        WHERE s.value LIKE ? ESCAPE '\\'
                        ORDER BY m.class_name, m.method_name
                        LIMIT ?
                        """,
                        (_like_term(str(keyword)), limit * 4),
                    )
                    for row in rows:
                        key = (row["class_name"], row["method_name"], row["descriptor"])
                        if key in seen:
                            continue
                        seen.add(key)
                        results.append({
                            "class": row["class_name"],
                            "method": row["method_name"],
                            "descriptor": row["descriptor"],
                            "access": row["access"],
                            "matched_string": row["value"],
                            "matched_query": keyword,
                        })
                        if len(results) >= limit:
                            break
                    if len(results) >= limit:
                        break
            else:
                class_term = str(query.get("class_name", ""))
                method_term = str(query.get("method_name", ""))
                rows = conn.execute(
                    """
                    SELECT class_name, method_name, descriptor, access
                    FROM methods
                    WHERE class_name LIKE ? ESCAPE '\\'
                      AND method_name LIKE ? ESCAPE '\\'
                    ORDER BY class_name, method_name, descriptor
                    LIMIT ?
                    """,
                    (_like_term(class_term), _like_term(method_term), limit),
                )
                results = [_method_dict(row) for row in rows]

    return {
        "ok": True,
        "backend": "sqlite-index",
        "find": find,
        "count": len(results),
        "results": results,
        "index_path": str(path),
        "cache_hit": True,
    }


def method_relations(
    apk_path: str | Path,
    class_name: str,
    method_name: str,
    descriptor: str = "",
    limit: int = 30,
) -> dict[str, Any]:
    """返回一个方法的调用者、被调用方法、关联字符串和同类字段。"""
    apk = Path(apk_path)
    if not index_is_ready(apk):
        return {"ok": False, "error": "DEX 持久索引尚未建立"}

    limit = max(1, min(int(limit), 100))
    path = index_path_for_apk(apk)
    variants = _class_variants(class_name)
    placeholders = ",".join("?" for _ in variants)
    params: list[Any] = [*variants, method_name]
    descriptor_sql = ""
    if descriptor:
        descriptor_sql = " AND descriptor = ?"
        params.append(descriptor)

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        targets = list(
            conn.execute(
                f"""
                SELECT id, class_name, method_name, descriptor, access
                FROM methods
                WHERE class_name IN ({placeholders})
                  AND method_name = ?
                  {descriptor_sql}
                ORDER BY descriptor
                LIMIT 20
                """,
                params,
            )
        )
        if not targets:
            return {
                "ok": False,
                "error": "索引中找不到目标方法",
                "class": class_name,
                "method": method_name,
                "descriptor": descriptor,
            }

        target_ids = [int(row["id"]) for row in targets]
        target_placeholders = ",".join("?" for _ in target_ids)

        callers = list(
            conn.execute(
                f"""
                SELECT DISTINCT m.class_name, m.method_name, m.descriptor, m.access,
                       SUM(c.call_count) AS call_count
                FROM method_calls c
                JOIN methods m ON m.id = c.caller_method_id
                WHERE c.callee_method_id IN ({target_placeholders})
                GROUP BY m.class_name, m.method_name, m.descriptor, m.access
                ORDER BY call_count DESC, m.class_name, m.method_name
                LIMIT ?
                """,
                [*target_ids, limit],
            )
        )
        callees = list(
            conn.execute(
                f"""
                SELECT DISTINCT m.class_name, m.method_name, m.descriptor, m.access,
                       SUM(c.call_count) AS call_count
                FROM method_calls c
                JOIN methods m ON m.id = c.callee_method_id
                WHERE c.caller_method_id IN ({target_placeholders})
                GROUP BY m.class_name, m.method_name, m.descriptor, m.access
                ORDER BY call_count DESC, m.class_name, m.method_name
                LIMIT ?
                """,
                [*target_ids, limit],
            )
        )
        strings = list(
            conn.execute(
                f"""
                SELECT DISTINCT s.value
                FROM string_method_xrefs x
                JOIN strings s ON s.id = x.string_id
                WHERE x.method_id IN ({target_placeholders})
                ORDER BY length(s.value), s.value
                LIMIT ?
                """,
                [*target_ids, limit],
            )
        )

        class_variants: list[str] = []
        for row in targets:
            for value in _class_variants(str(row["class_name"])):
                if value not in class_variants:
                    class_variants.append(value)
        class_placeholders = ",".join("?" for _ in class_variants)
        fields = list(
            conn.execute(
                f"""
                SELECT class_name, field_name, type
                FROM fields
                WHERE class_name IN ({class_placeholders})
                ORDER BY field_name
                LIMIT ?
                """,
                [*class_variants, limit],
            )
        )

    return {
        "ok": True,
        "backend": "sqlite-index",
        "targets": [_method_dict(row) for row in targets],
        "callers": [
            {**_method_dict(row), "call_count": int(row["call_count"] or 0)}
            for row in callers
        ],
        "callees": [
            {**_method_dict(row), "call_count": int(row["call_count"] or 0)}
            for row in callees
        ],
        "strings": [row["value"] for row in strings],
        "class_fields": [
            {
                "class": row["class_name"],
                "field": row["field_name"],
                "type": row["type"],
            }
            for row in fields
        ],
        "index_path": str(path),
    }


def write_meta(conn: sqlite3.Connection, apk: Path, counts: dict[str, int]) -> None:
    stat = apk.stat()
    meta = {
        "schema_version": str(SCHEMA_VERSION),
        "apk_path": str(apk.resolve()),
        "apk_size": str(stat.st_size),
        "apk_mtime_ns": str(stat.st_mtime_ns),
        "counts": json.dumps(counts, ensure_ascii=False, sort_keys=True),
        "complete": "1",
    }
    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        meta.items(),
    )
