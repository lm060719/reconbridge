"""Androguard 隔离 worker。

AnalyzeAPK 会为多 DEX APK 构建很大的对象图，因此绝不能在长期驻留的 MCP
主进程中执行。worker 每次只处理一个查询，结果写盘后立即退出，让操作系统回收全部堆。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


def _pat(pattern: str) -> str:
    if not pattern or pattern == ".*":
        return ".*"
    if re.search(r"[\\^$.|?*+()\[\]{}]", pattern):
        return pattern
    return ".*" + re.escape(pattern) + ".*"


def run_search(apk_path: str, query: dict[str, Any]) -> dict[str, Any]:
    try:
        from loguru import logger as loguru_logger
        loguru_logger.remove()
    except Exception:
        pass

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

    def meth_row(method_analysis) -> dict[str, Any]:
        method = (
            method_analysis.get_method()
            if hasattr(method_analysis, "get_method")
            else method_analysis
        )
        return {
            "class": method.get_class_name(),
            "method": method.get_name(),
            "descriptor": method.get_descriptor() if hasattr(method, "get_descriptor") else "",
            "access": (
                method.get_access_flags_string()
                if hasattr(method, "get_access_flags_string")
                else ""
            ),
        }

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
            for item in analysis.find_fields(
                classname=class_pattern,
                fieldname=field_pattern,
            ):
                field = item.get_field()
                results.append(
                    {
                        "class": field.get_class_name(),
                        "field": field.get_name(),
                        "type": field.get_descriptor(),
                    }
                )
                if len(results) >= limit:
                    break
        else:
            using = query.get("using_strings")
            if using:
                seen = set()
                stop = False
                for keyword in using:
                    for string_analysis in analysis.find_strings(keyword):
                        for xref in string_analysis.get_xref_from():
                            row = meth_row(xref[1])
                            key = (row["class"], row["method"], row["descriptor"])
                            if key in seen:
                                continue
                            seen.add(key)
                            row["matched_string"] = keyword
                            results.append(row)
                            if len(results) >= limit:
                                stop = True
                                break
                        if stop:
                            break
                    if stop:
                        break
            else:
                class_pattern = _pat(query.get("class_name", ".*"))
                method_pattern = _pat(query.get("method_name", ".*"))
                for item in analysis.find_methods(
                    classname=class_pattern,
                    methodname=method_pattern,
                ):
                    results.append(meth_row(item))
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
