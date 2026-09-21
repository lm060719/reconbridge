"""Androguard 隔离 worker。

重型 APK 解析始终放在短生命周期子进程中。优先任务是一次性建立 SQLite
持久索引；旧的直接查询能力保留为兼容兜底。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from .dex_index import write_meta


def _quiet_loguru() -> None:
    try:
        from loguru import logger as loguru_logger
        loguru_logger.remove()
    except Exception:
        pass


def _pat(pattern: str) -> str:
    if not pattern or pattern == ".*":
        return ".*"
    if re.search(r"[\\^$.|?*+()\[\]{}]", pattern):
        return pattern
    return ".*" + re.escape(pattern) + ".*"


def _method_row(method_analysis) -> dict[str, str]:
    method = (
        method_analysis.get_method()
        if hasattr(method_analysis, "get_method")
        else method_analysis
    )
    return {
        "class": str(method.get_class_name()),
        "method": str(method.get_name()),
        "descriptor": str(method.get_descriptor()) if hasattr(method, "get_descriptor") else "",
        "access": (
            str(method.get_access_flags_string())
            if hasattr(method, "get_access_flags_string")
            else ""
        ),
    }


def _field_row(field_analysis) -> dict[str, str]:
    field = (
        field_analysis.get_field()
        if hasattr(field_analysis, "get_field")
        else field_analysis
    )
    return {
        "class": str(field.get_class_name()),
        "field": str(field.get_name()),
        "type": str(field.get_descriptor()) if hasattr(field, "get_descriptor") else "",
    }


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=FILE;

        CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE classes (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE methods (
            id INTEGER PRIMARY KEY,
            class_name TEXT NOT NULL,
            method_name TEXT NOT NULL,
            descriptor TEXT NOT NULL,
            access TEXT NOT NULL,
            UNIQUE(class_name, method_name, descriptor)
        );

        CREATE TABLE fields (
            id INTEGER PRIMARY KEY,
            class_name TEXT NOT NULL,
            field_name TEXT NOT NULL,
            type TEXT NOT NULL,
            UNIQUE(class_name, field_name, type)
        );

        CREATE TABLE strings (
            id INTEGER PRIMARY KEY,
            value TEXT NOT NULL UNIQUE
        );

        CREATE TABLE string_method_xrefs (
            string_id INTEGER NOT NULL,
            method_id INTEGER NOT NULL,
            UNIQUE(string_id, method_id)
        );

        CREATE TABLE method_calls (
            caller_method_id INTEGER NOT NULL,
            callee_method_id INTEGER NOT NULL,
            call_count INTEGER NOT NULL DEFAULT 1,
            UNIQUE(caller_method_id, callee_method_id)
        );

        CREATE INDEX idx_classes_name ON classes(name);
        CREATE INDEX idx_methods_name ON methods(method_name);
        CREATE INDEX idx_methods_class ON methods(class_name);
        CREATE INDEX idx_fields_name ON fields(field_name);
        CREATE INDEX idx_fields_class ON fields(class_name);
        CREATE INDEX idx_strings_value ON strings(value);
        CREATE INDEX idx_xrefs_string ON string_method_xrefs(string_id);
        CREATE INDEX idx_xrefs_method ON string_method_xrefs(method_id);
        CREATE INDEX idx_calls_caller ON method_calls(caller_method_id);
        CREATE INDEX idx_calls_callee ON method_calls(callee_method_id);
        """
    )


def build_index(apk_path: str, index_path: str) -> dict[str, Any]:
    _quiet_loguru()
    try:
        from androguard.misc import AnalyzeAPK
    except Exception:
        return {"ok": False, "error": "androguard 未安装", "hint": "pip install androguard"}

    apk = Path(apk_path)
    target = Path(index_path)
    if not apk.exists():
        return {"ok": False, "error": f"apk 不存在: {apk_path}"}

    target.parent.mkdir(parents=True, exist_ok=True)
    building = target.with_suffix(target.suffix + ".building")
    building.unlink(missing_ok=True)

    try:
        _apk_obj, _dex_list, analysis = AnalyzeAPK(str(apk))
    except MemoryError:
        return {"ok": False, "error": "androguard 建索引阶段内存不足"}
    except Exception as exc:
        return {"ok": False, "error": f"androguard 解析失败: {exc}"}

    counts = {
        "classes": 0,
        "methods": 0,
        "fields": 0,
        "strings": 0,
        "string_method_xrefs": 0,
        "method_calls": 0,
    }

    try:
        with sqlite3.connect(building) as conn:
            _create_schema(conn)
            conn.execute("BEGIN")

            for item in analysis.find_classes(".*"):
                name = str(getattr(item, "name", ""))
                if not name:
                    continue
                cur = conn.execute("INSERT OR IGNORE INTO classes(name) VALUES (?)", (name,))
                counts["classes"] += max(0, cur.rowcount)

            method_items = list(analysis.find_methods(classname=".*", methodname=".*"))
            for item in method_items:
                row = _method_row(item)
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO methods(class_name, method_name, descriptor, access)
                    VALUES (?, ?, ?, ?)
                    """,
                    (row["class"], row["method"], row["descriptor"], row["access"]),
                )
                counts["methods"] += max(0, cur.rowcount)

            method_ids = {
                (str(row[1]), str(row[2]), str(row[3])): int(row[0])
                for row in conn.execute(
                    "SELECT id, class_name, method_name, descriptor FROM methods"
                )
            }

            # Androguard 的 MethodAnalysis.get_xref_to() 表示“当前方法调用了谁”。
            # 把调用边一次性持久化，后续 callers/callees 全部直接查 SQLite。
            for item in method_items:
                caller = _method_row(item)
                caller_key = (
                    caller["class"],
                    caller["method"],
                    caller["descriptor"],
                )
                caller_id = method_ids.get(caller_key)
                if caller_id is None or not hasattr(item, "get_xref_to"):
                    continue

                try:
                    xrefs = item.get_xref_to()
                except Exception:
                    continue

                for xref in xrefs:
                    if len(xref) < 2:
                        continue
                    callee = _method_row(xref[1])
                    callee_key = (
                        callee["class"],
                        callee["method"],
                        callee["descriptor"],
                    )
                    callee_id = method_ids.get(callee_key)
                    if callee_id is None:
                        cur = conn.execute(
                            """
                            INSERT OR IGNORE INTO methods(
                                class_name, method_name, descriptor, access
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (
                                callee["class"],
                                callee["method"],
                                callee["descriptor"],
                                callee["access"],
                            ),
                        )
                        counts["methods"] += max(0, cur.rowcount)
                        row_id = conn.execute(
                            """
                            SELECT id
                            FROM methods
                            WHERE class_name = ? AND method_name = ? AND descriptor = ?
                            """,
                            callee_key,
                        ).fetchone()
                        if not row_id:
                            continue
                        callee_id = int(row_id[0])
                        method_ids[callee_key] = callee_id

                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO method_calls(
                            caller_method_id, callee_method_id, call_count
                        ) VALUES (?, ?, 1)
                        """,
                        (caller_id, callee_id),
                    )
                    if cur.rowcount:
                        counts["method_calls"] += 1
                    else:
                        conn.execute(
                            """
                            UPDATE method_calls
                            SET call_count = call_count + 1
                            WHERE caller_method_id = ? AND callee_method_id = ?
                            """,
                            (caller_id, callee_id),
                        )

            for item in analysis.find_fields(classname=".*", fieldname=".*"):
                row = _field_row(item)
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO fields(class_name, field_name, type)
                    VALUES (?, ?, ?)
                    """,
                    (row["class"], row["field"], row["type"]),
                )
                counts["fields"] += max(0, cur.rowcount)

            for string_analysis in analysis.find_strings(".*"):
                value = str(string_analysis.get_value())
                cur = conn.execute(
                    "INSERT OR IGNORE INTO strings(value) VALUES (?)",
                    (value,),
                )
                counts["strings"] += max(0, cur.rowcount)
                string_row = conn.execute(
                    "SELECT id FROM strings WHERE value = ?",
                    (value,),
                ).fetchone()
                if not string_row:
                    continue
                string_id = int(string_row[0])

                for xref in string_analysis.get_xref_from():
                    if len(xref) < 2:
                        continue
                    method = _method_row(xref[1])
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO methods(class_name, method_name, descriptor, access)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            method["class"],
                            method["method"],
                            method["descriptor"],
                            method["access"],
                        ),
                    )
                    method_row = conn.execute(
                        """
                        SELECT id
                        FROM methods
                        WHERE class_name = ? AND method_name = ? AND descriptor = ?
                        """,
                        (method["class"], method["method"], method["descriptor"]),
                    ).fetchone()
                    if not method_row:
                        continue

                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO string_method_xrefs(string_id, method_id)
                        VALUES (?, ?)
                        """,
                        (string_id, int(method_row[0])),
                    )
                    counts["string_method_xrefs"] += max(0, cur.rowcount)

            write_meta(conn, apk, counts)
            conn.commit()

        os.replace(building, target)
        return {
            "ok": True,
            "operation": "build_index",
            "backend": "androguard-worker",
            "index_path": str(target),
            "index_bytes": target.stat().st_size,
            "counts": counts,
        }
    except MemoryError:
        building.unlink(missing_ok=True)
        return {"ok": False, "error": "建立 SQLite 索引时内存不足"}
    except Exception as exc:
        building.unlink(missing_ok=True)
        return {"ok": False, "error": f"建立 SQLite 索引失败: {exc}"}


def run_search(apk_path: str, query: dict[str, Any]) -> dict[str, Any]:
    """兼容旧路径：直接用 Androguard 执行一次查询。"""
    _quiet_loguru()
    try:
        from androguard.misc import AnalyzeAPK
    except Exception:
        return {"ok": False, "error": "androguard 未安装", "hint": "pip install androguard"}

    apk = Path(apk_path)
    if not apk.exists():
        return {"ok": False, "error": f"apk 不存在: {apk_path}"}

    find = query.get("find", "method")
    limit = max(1, min(int(query.get("max_results", 100)), 5000))
    results: list[dict[str, Any]] = []

    try:
        _apk_obj, _dex_list, analysis = AnalyzeAPK(str(apk))
    except MemoryError:
        return {"ok": False, "error": "androguard 内存不足，任务已被资源限制器终止"}
    except Exception as exc:
        return {"ok": False, "error": f"androguard 解析失败: {exc}"}

    try:
        if find == "string":
            pattern = query.get("string", ".*")
            for item in analysis.find_strings(pattern):
                results.append({"string": item.get_value()})
                if len(results) >= limit:
                    break
        elif find == "class":
            pattern = _pat(query.get("class_name", ".*"))
            for item in analysis.find_classes(pattern):
                results.append({"class": item.name})
                if len(results) >= limit:
                    break
        elif find == "field":
            field_pattern = _pat(query.get("field_name", ".*"))
            class_pattern = _pat(query.get("class_name", ".*"))
            for item in analysis.find_fields(classname=class_pattern, fieldname=field_pattern):
                row = _field_row(item)
                results.append({"class": row["class"], "field": row["field"], "type": row["type"]})
                if len(results) >= limit:
                    break
        else:
            using = query.get("using_strings")
            if using:
                seen = set()
                for keyword in using:
                    for string_analysis in analysis.find_strings(keyword):
                        for xref in string_analysis.get_xref_from():
                            row = _method_row(xref[1])
                            key = (row["class"], row["method"], row["descriptor"])
                            if key in seen:
                                continue
                            seen.add(key)
                            row["matched_string"] = str(string_analysis.get_value())
                            row["matched_query"] = keyword
                            results.append(row)
                            if len(results) >= limit:
                                break
                        if len(results) >= limit:
                            break
                    if len(results) >= limit:
                        break
            else:
                class_pattern = _pat(query.get("class_name", ".*"))
                method_pattern = _pat(query.get("method_name", ".*"))
                for item in analysis.find_methods(
                    classname=class_pattern,
                    methodname=method_pattern,
                ):
                    results.append(_method_row(item))
                    if len(results) >= limit:
                        break
    except MemoryError:
        return {"ok": False, "error": "androguard 查询阶段内存不足"}
    except Exception as exc:
        return {"ok": False, "error": f"查询失败: {exc}", "query": query}

    return {
        "ok": True,
        "backend": "androguard-worker",
        "find": find,
        "count": len(results),
        "results": results,
    }


def main(args: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if args is None else args)
    if len(args) != 2:
        return 2

    request_path = Path(args[0])
    response_path = Path(args[1])
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        operation = request.get("operation", "search")
        if operation == "build_index":
            result = build_index(request["apk_path"], request["index_path"])
        else:
            result = run_search(request["apk_path"], request.get("query") or {})
    except Exception as exc:
        result = {"ok": False, "error": f"dex worker 失败: {exc}"}

    response_path.write_text(
        json.dumps(result, ensure_ascii=False),
        encoding="utf-8",
    )
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
