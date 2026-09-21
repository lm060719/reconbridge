"""ReconBridge MCP Server —— 把 M1 静态接口 + PC 本地反编译工具链暴露为 Claude Code 可调用的工具。

传输：stdio。运行：`python -m reconbridge_mcp`（见 __main__.py）。
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .client import ReconError, client, _fold_stack
from .settings import settings
from . import branch_condition, candidate, condition_probe, external, hypothesis_verify, investigation, pipeline, root_cause, runtime_lineage, runtime_path, scenario_path, writer_probe

mcp = FastMCP("reconbridge")


_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*$")


def _validate_package_name(package_name: str) -> str:
    if not package_name or not _PKG_NAME_RE.match(package_name):
        raise ReconError(f"Invalid package_name: '{package_name}'")
    return package_name


def _pkg_dir(package_name: str, sub: str) -> Path:
    _validate_package_name(package_name)
    d = (settings.workdir / package_name / sub).resolve()
    try:
        d.relative_to(settings.workdir.resolve())
    except ValueError:
        raise ReconError(f"Package path escapes workdir: {package_name}")
    d.mkdir(parents=True, exist_ok=True)
    return d



# =====================================================================
# 高层任务模式：围绕一个目标持续分析，减少原子工具往返
# =====================================================================

def _rank_target_candidates(
    state: dict[str, Any],
    query: str,
    limit: int = 10,
    pool_limit: int = 80,
) -> dict:
    apk = state.get("primary_apk", "")
    if not apk:
        return {"ok": False, "error": "当前会话没有 APK，无法生成候选方法"}

    pool_limit = max(10, min(int(pool_limit), 300))
    combined: list[dict[str, Any]] = []
    searches = [
        (
            "string_xref",
            {"find": "method", "using_strings": [query], "max_results": pool_limit},
        ),
        (
            "method_name",
            {"find": "method", "method_name": query, "max_results": pool_limit},
        ),
        (
            "class_name",
            {
                "find": "method",
                "class_name": query,
                "method_name": "",
                "max_results": pool_limit,
            },
        ),
    ]

    backends: set[str] = set()
    errors: list[str] = []
    for source, dex_query in searches:
        result = external.dexkit_search(apk, dex_query)
        if not result.get("ok"):
            errors.append(f"{source}: {result.get('error', '搜索失败')}")
            continue
        backends.add(str(result.get("backend", "")))
        for item in result.get("results", []):
            row = dict(item)
            row["_source"] = source
            combined.append(row)

    graph = state.get("evidence_graph") or {}
    ranked = candidate.rank(
        query,
        combined,
        graph=graph,
        limit=limit,
    )
    return {
        "ok": bool(ranked) or not errors,
        "query": query,
        "candidate_count": len(ranked),
        "candidates": ranked,
        "pool_size": len(combined),
        "backends": sorted(x for x in backends if x),
        "errors": errors,
    }


def _verify_ranked_candidates(
    session_id: str,
    state: dict[str, Any],
    query: str,
    ranked: list[dict[str, Any]],
    seconds: float = 15.0,
    max_events: int = 200,
    restart: bool = True,
    hot: bool = False,
    stack: bool = False,
    cleanup: bool = True,
) -> dict:
    """一次装载多候选观测 Hook，并在共享窗口里按 hook_id 归因。"""
    if not ranked:
        return {
            "ok": False,
            "query": query,
            "error": "没有可验证的候选方法",
            "tested": 0,
            "confirmed": [],
            "missed": [],
        }

    # 当前批量验证不传 params，同一 class+method 的多个 descriptor 会实际挂到同一组重载。
    # 因此验证阶段只保留排名最高的一项，避免重复 Hook 与重复事件。
    unique_ranked: list[dict[str, Any]] = []
    seen_methods: set[tuple[str, str]] = set()
    for item in ranked:
        key = (
            candidate.normalize_class_name(str(item.get("class", ""))),
            str(item.get("method", "")),
        )
        if key in seen_methods:
            continue
        seen_methods.add(key)
        unique_ranked.append(item)
    ranked = unique_ranked

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    targets: list[dict[str, Any]] = []
    hook_ids: list[str] = []
    by_hook: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(ranked, 1):
        class_name = candidate.normalize_class_name(str(item.get("class", "")))
        method_name = str(item.get("method", ""))
        safe_class = re.sub(r"[^A-Za-z0-9_]", "_", class_name.rsplit(".", 1)[-1])[:20] or "class"
        safe_method = re.sub(r"[^A-Za-z0-9_]", "_", method_name)[:24] or "method"
        hook_id = f"rbv_{session_id}_{index}_{safe_class}_{safe_method}"
        hook_ids.append(hook_id)
        by_hook[hook_id] = item
        investigation.add_temporary_hook(session_id, hook_id)
        targets.append(
            {
                "kind": "java",
                "id": hook_id,
                "class": class_name,
                "method": method_name,
                "capture": {
                    "this": "class",
                    "when": "after",
                    "all_args": False,
                    "stack": stack,
                },
            }
        )

    config: dict[str, Any] = {
        "package": state["package"],
        "restart": bool(restart and not hot),
        "debug": False,
        "targets": targets,
    }
    if hot:
        config["restart"] = False
        config["mode"] = "append"

    posted: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    collect_error = ""
    try:
        posted = client.post_json("/hook", config)
        events = client.collect_sse(
            seconds=max(0.5, float(seconds)),
            max_events=max(1, min(int(max_events), 1000)),
            fold_stack=True,
            include_recent=True,
            since_seq=cursor,
        )
    except Exception as exc:
        collect_error = str(exc)
    finally:
        if cleanup:
            for hook_id in hook_ids:
                try:
                    unhook(state["package"], hook_id)
                except Exception:
                    pass
                finally:
                    investigation.remove_temporary_hook(session_id, hook_id)

    try:
        latest = int(client.get_recent(limit=0).get("latest_seq", cursor) or cursor)
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    events_by_hook: dict[str, list[dict[str, Any]]] = {
        hook_id: [] for hook_id in hook_ids
    }
    for event in events:
        hook_id = str(event.get("hook_id", ""))
        if hook_id in events_by_hook:
            events_by_hook[hook_id].append(event)
            continue

        event_class = candidate.normalize_class_name(str(event.get("class", "")))
        event_method = str(event.get("method", ""))
        for candidate_hook, item in by_hook.items():
            if (
                candidate.normalize_class_name(str(item.get("class", ""))) == event_class
                and str(item.get("method", "")) == event_method
            ):
                events_by_hook[candidate_hook].append(event)
                break

    verified: list[dict[str, Any]] = []
    for hook_id in hook_ids:
        item = dict(by_hook[hook_id])
        matched_events = events_by_hook.get(hook_id, [])
        hits = len(matched_events)
        item["hook_id"] = hook_id
        item["verification_hits"] = hits
        item["verified"] = hits > 0
        verified.append(item)

        if hits:
            investigation.record_trace_evidence(
                session_id,
                candidate.normalize_class_name(str(item.get("class", ""))),
                str(item.get("method", "")),
                matched_events,
            )

    verified.sort(
        key=lambda item: (
            -int(item.get("verification_hits", 0)),
            -int(item.get("score", 0)),
            int(item.get("rank", 999)),
        )
    )
    confirmed = [item for item in verified if item["verified"]]
    missed = [item for item in verified if not item["verified"]]

    investigation.add_discovery(
        session_id,
        {
            "type": "candidate_verification",
            "query": query,
            "tested": len(verified),
            "confirmed": len(confirmed),
            "events": len(events),
        },
    )

    return {
        "ok": not bool(collect_error),
        "query": query,
        "posted": posted,
        "tested": len(verified),
        "confirmed_count": len(confirmed),
        "confirmed": confirmed,
        "missed": missed,
        "event_count": len(events),
        "events": events[:100],
        "event_cursor": latest,
        "cleanup": cleanup,
        "error": collect_error or None,
    }


def _verify_static_call_path(
    session_id: str,
    state: dict[str, Any],
    path: dict[str, Any],
    seconds: float = 15.0,
    max_events: int = 400,
    max_hooks: int = 12,
    restart: bool = True,
    hot: bool = False,
    stack: bool = False,
    cleanup: bool = True,
) -> dict:
    """一次性观测代表路径上的方法入口，并还原真实执行时间线。"""
    methods = runtime_path.path_methods(path, max_hooks=max_hooks)
    if not methods:
        return {
            "ok": False,
            "error": "代表路径里没有可动态验证的 Java 方法",
            "analysis": {},
            "events": [],
        }

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    targets: list[dict[str, Any]] = []
    hook_ids: list[str] = []
    hook_map: dict[str, dict[str, Any]] = {}

    for index, item in enumerate(methods, 1):
        safe_class = re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            item["class"].rsplit(".", 1)[-1],
        )[:18] or "class"
        safe_method = re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            item["method"],
        )[:22] or "method"
        hook_id = f"rbp_{session_id}_{index}_{safe_class}_{safe_method}"
        hook_ids.append(hook_id)
        hook_map[hook_id] = item
        investigation.add_temporary_hook(session_id, hook_id)

        # 路径顺序必须看方法入口；after 会让嵌套调用天然逆序。
        targets.append(
            {
                "kind": "java",
                "id": hook_id,
                "class": item["class"],
                "method": item["method"],
                "capture": {
                    "this": "class",
                    "when": "before",
                    "all_args": False,
                    "stack": stack,
                },
            }
        )

    config: dict[str, Any] = {
        "package": state["package"],
        "restart": bool(restart and not hot),
        "debug": False,
        "targets": targets,
    }
    if hot:
        config["restart"] = False
        config["mode"] = "append"

    posted: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    collect_error = ""

    try:
        posted = client.post_json("/hook", config)
        events = client.collect_sse(
            seconds=max(0.5, float(seconds)),
            max_events=max(1, min(int(max_events), 2000)),
            fold_stack=True,
            include_recent=True,
            since_seq=cursor,
        )
    except Exception as exc:
        collect_error = str(exc)
    finally:
        if cleanup:
            for hook_id in hook_ids:
                try:
                    unhook(state["package"], hook_id)
                except Exception:
                    pass
                finally:
                    investigation.remove_temporary_hook(session_id, hook_id)

    try:
        latest = int(client.get_recent(limit=0).get("latest_seq", cursor) or cursor)
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    analysis = runtime_path.analyze_path(path, events, hook_map)

    # 每个路径节点的事件继续进入通用 Evidence Graph。
    for hook_id, meta in hook_map.items():
        matched = [
            event
            for event in events
            if (
                str(event.get("hook_id", "")) == hook_id
                or (
                    candidate.normalize_class_name(str(event.get("class", ""))) == meta["class"]
                    and str(event.get("method", "")) == meta["method"]
                )
            )
        ]
        if matched:
            investigation.record_trace_evidence(
                session_id,
                meta["class"],
                meta["method"],
                matched,
            )

    investigation.record_runtime_path_evidence(session_id, path, analysis)
    investigation.add_discovery(
        session_id,
        {
            "type": "runtime_call_path",
            "path": path.get("text", ""),
            "events": analysis.get("event_count", 0),
            "node_coverage": analysis.get("node_coverage", 0),
            "edge_coverage": analysis.get("edge_coverage", 0),
            "full_path_observed": analysis.get("full_path_observed", False),
        },
    )

    return {
        "ok": not bool(collect_error),
        "posted": posted,
        "analysis": analysis,
        "events": events[:200],
        "event_cursor": latest,
        "hooked_methods": methods,
        "cleanup": cleanup,
        "error": collect_error or None,
    }


def _capture_call_graph_scenario(
    session_id: str,
    state: dict[str, Any],
    name: str,
    call_graph: dict[str, Any],
    seconds: float = 20.0,
    quiet_ms: int = 1500,
    max_events: int = 800,
    max_hooks: int = 24,
    include_external: bool = False,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict:
    """用同一张局部调用图上的方法集合采集一次可比较业务场景。"""
    methods = scenario_path.graph_methods(
        call_graph,
        max_hooks=max_hooks,
        include_external=include_external,
    )
    if not methods:
        return {
            "ok": False,
            "error": "调用图中没有可用于场景采集的 Java 方法",
            "analysis": {},
        }

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    targets: list[dict[str, Any]] = []
    hook_ids: list[str] = []
    hook_map: dict[str, dict[str, Any]] = {}

    for index, item in enumerate(methods, 1):
        safe_class = re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            item["class"].rsplit(".", 1)[-1],
        )[:18] or "class"
        safe_method = re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            item["method"],
        )[:22] or "method"
        hook_id = f"rbsc_{session_id}_{index}_{safe_class}_{safe_method}"
        hook_ids.append(hook_id)
        hook_map[hook_id] = item
        investigation.add_temporary_hook(session_id, hook_id)
        targets.append(
            {
                "kind": "java",
                "id": hook_id,
                "class": item["class"],
                "method": item["method"],
                "capture": {
                    "this": "class",
                    "when": "before",
                    "all_args": False,
                    "stack": False,
                },
            }
        )

    config: dict[str, Any] = {
        "package": state["package"],
        "restart": bool(restart and not hot),
        "debug": False,
        "targets": targets,
    }
    if hot:
        config["restart"] = False
        config["mode"] = "append"

    posted: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    collect_error = ""

    try:
        posted = client.post_json("/hook", config)
        events = client.collect_sse(
            seconds=max(0.5, float(seconds)),
            max_events=max(1, min(int(max_events), 3000)),
            fold_stack=True,
            include_recent=True,
            since_seq=cursor,
            quiet_ms=max(0, int(quiet_ms)),
        )
    except Exception as exc:
        collect_error = str(exc)
    finally:
        if cleanup:
            for hook_id in hook_ids:
                try:
                    unhook(state["package"], hook_id)
                except Exception:
                    pass
                finally:
                    investigation.remove_temporary_hook(session_id, hook_id)

    try:
        latest = int(client.get_recent(limit=0).get("latest_seq", cursor) or cursor)
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    analysis = scenario_path.analyze_graph_scenario(
        call_graph,
        events,
        hook_map,
    )

    for hook_id, meta in hook_map.items():
        matched = [
            event
            for event in events
            if (
                str(event.get("hook_id", "")) == hook_id
                or (
                    candidate.normalize_class_name(str(event.get("class", ""))) == meta["class"]
                    and str(event.get("method", "")) == meta["method"]
                )
            )
        ]
        if matched:
            investigation.record_trace_evidence(
                session_id,
                meta["class"],
                meta["method"],
                matched,
            )

    payload = {
        "name": name,
        "package": state["package"],
        "captured_at": int(time.time() * 1000),
        "target": {
            "class": call_graph.get("targets", [{}])[0].get("class", ""),
            "method": call_graph.get("targets", [{}])[0].get("method", ""),
            "descriptor": call_graph.get("targets", [{}])[0].get("descriptor", ""),
        },
        "graph_fingerprint": scenario_path.graph_fingerprint(call_graph),
        "hook_fingerprint": scenario_path.hook_fingerprint(methods),
        "graph": {
            "node_count": call_graph.get("node_count", 0),
            "edge_count": call_graph.get("edge_count", 0),
            "limits": call_graph.get("limits", {}),
        },
        "hooked_methods": methods,
        "analysis": analysis,
    }
    saved = investigation.save_call_scenario(session_id, name, payload)
    investigation.add_discovery(
        session_id,
        {
            "type": "call_graph_scenario",
            "name": name,
            "target": payload["target"],
            "events": analysis.get("event_count", 0),
            "observed_nodes": analysis.get("observed_nodes", 0),
            "primary_tid": analysis.get("primary_tid"),
        },
    )

    return {
        "ok": not bool(collect_error),
        "name": name,
        "posted": posted,
        "analysis": analysis,
        "saved": saved,
        "event_cursor": latest,
        "hooked_method_count": len(methods),
        "cleanup": cleanup,
        "error": collect_error or None,
    }


@mcp.tool()
def open_target(package_name: str, auto_pull: bool = True, note: str = "") -> dict:
    """开启一个持久化分析会话，并自动绑定该包现有 APK/JADX/so 产物。

    默认在本地没有 APK 时尝试从设备拉取；即使设备暂时不可用，也会保留会话并返回 warning。
    后续优先直接使用 investigate；需要手工展开具体方法时用 inspect_method / trace_target。
    """
    _validate_package_name(package_name)
    state = investigation.create(package_name, note=note)
    warning = ""
    if auto_pull and not state.get("primary_apk"):
        try:
            pull_apk(package_name)
            state = investigation.load(state["session_id"], refresh=True)
        except Exception as exc:
            warning = f"自动拉取 APK 失败: {exc}"

    result = investigation.status(state["session_id"])
    result["workflow"] = "open_target -> investigate；已知具体方法后用 inspect_method / trace_target"
    if warning:
        result["warning"] = warning
    return result


@mcp.tool()
def investigation_status(session_id: str) -> dict:
    """查看分析会话当前绑定的 APK、JADX 目录、发现记录和运行时游标。"""
    try:
        return investigation.status(session_id)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}


@mcp.tool()
def prepare_index(session_id: str, force: bool = False) -> dict:
    """预热当前目标的 DEX SQLite 索引；首次解析 APK，之后所有新查询直接查数据库。"""
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "当前会话没有 APK，无法建立 DEX 索引",
        }

    result = external.ensure_dex_index(apk, force=force)
    return {
        **result,
        "session_id": session_id,
        "package": state["package"],
    }


@mcp.tool()
def prepare_target(session_id: str, force: bool = False) -> dict:
    """为会话准备 JADX 源码。已有反编译产物时直接复用，否则只反编译当前主 APK。"""
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    jadx_dirs = state["artifacts"].get("jadx_dirs", [])
    if jadx_dirs and not force:
        return {
            "ok": True,
            "session_id": session_id,
            "package": state["package"],
            "reused": True,
            "jadx_dirs": jadx_dirs,
        }

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "error": "当前会话没有 APK；先确保设备可连接后重新 open_target(auto_pull=true)，或使用 pull_apk",
        }

    result = external.decompile_apk(apk)
    refreshed = investigation.status(session_id)
    return {
        **result,
        "session_id": session_id,
        "package": state["package"],
        "reused": False,
        "jadx_ready": refreshed["jadx_ready"],
        "jadx_dirs": refreshed["jadx_dirs"],
    }


@mcp.tool()
def search_target(session_id: str, query: str, kind: str = "auto", limit: int = 20) -> dict:
    """在当前分析目标中统一搜索源码 / 字符串 / 类 / 方法 / 字段。

    kind: auto|source|string|method|class|field。auto 会优先复用已有 JADX 源码；没有源码或未命中时，
    自动使用 SQLite DEX 持久索引。索引首次由受内存限制的 Androguard worker 建立，后续新查询不再解析 APK。
    """
    query = query.strip()
    if not query:
        return {"ok": False, "error": "query 不能为空", "session_id": session_id}
    limit = max(1, min(int(limit), 100))
    kind = kind.lower().strip()
    if kind not in {"auto", "source", "string", "method", "class", "field"}:
        return {"ok": False, "error": f"不支持的 kind: {kind}", "session_id": session_id}

    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    package = state["package"]
    if kind in {"auto", "source"} and state["artifacts"].get("jadx_dirs"):
        source = investigation.source_search(session_id, query, limit=limit)
        if kind == "source" or source["count"] > 0:
            investigation.add_discovery(session_id, {
                "type": "search", "query": query, "strategy": source["strategy"], "count": source["count"]
            })
            investigation.record_search_evidence(
                session_id,
                query,
                source["strategy"],
                source.get("results", []),
            )
            return {"ok": True, "session_id": session_id, "package": package, **source}
    elif kind == "source":
        return {
            "ok": False,
            "session_id": session_id,
            "package": package,
            "error": "当前没有 JADX 源码；先调用 prepare_target",
        }

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": package,
            "error": "当前会话没有 APK，无法执行 DEX 搜索",
        }

    if kind == "string":
        dex_query = {"find": "string", "string": query, "max_results": limit}
    elif kind == "class":
        dex_query = {"find": "class", "class_name": query, "max_results": limit}
    elif kind == "field":
        dex_query = {"find": "field", "field_name": query, "max_results": limit}
    elif kind == "method":
        dex_query = {"find": "method", "method_name": query, "max_results": limit}
    else:
        # 自然语言/界面文本最常见的定位方式：先找引用该字符串的方法。
        dex_query = {"find": "method", "using_strings": [query], "max_results": limit}

    result = external.dexkit_search(apk, dex_query)

    # auto 的字符串引用搜索没有结果时，再退回方法名搜索；两次都直接复用同一个 SQLite 索引。
    if kind == "auto" and result.get("ok") and not result.get("results"):
        result = external.dexkit_search(
            apk,
            {"find": "method", "method_name": query, "max_results": limit},
        )

    strategy = f"dex-{result.get('backend', 'worker')}"
    if result.get("ok"):
        investigation.add_discovery(session_id, {
            "type": "search", "query": query, "strategy": strategy, "count": result.get("count", 0)
        })
        investigation.record_search_evidence(
            session_id,
            query,
            strategy,
            result.get("results", []),
        )
    return {
        **result,
        "session_id": session_id,
        "package": package,
        "strategy": strategy,
    }


@mcp.tool()
def inspect_method(
    session_id: str,
    class_name: str,
    method: str,
    descriptor: str = "",
    relation_limit: int = 20,
    include_source: bool = True,
    auto_prepare_source: bool = True,
) -> dict:
    """展开一个已知 Java 方法：调用者、被调用方法、关联字符串、同类字段和 JADX 源码上下文。

    include_source=True 且当前没有 JADX 产物时，默认自动反编译一次主 APK；之后会复用已有源码。
    """
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "当前会话没有 APK，无法展开方法上下文",
        }

    index_result = external.ensure_dex_index(apk)
    source_prepare: dict[str, Any] | None = None

    if include_source and auto_prepare_source and not state["artifacts"].get("jadx_dirs"):
        source_prepare = external.decompile_apk(apk)
        state = investigation.load(session_id, refresh=True)

    context = investigation.method_context(
        session_id,
        class_name,
        method,
        descriptor=descriptor,
        relation_limit=max(1, min(int(relation_limit), 100)),
        include_source=include_source,
    )
    investigation.record_method_context_evidence(
        session_id,
        candidate.normalize_class_name(class_name),
        method,
        descriptor,
        context,
    )
    investigation.add_discovery(
        session_id,
        {
            "type": "method_context",
            "class": candidate.normalize_class_name(class_name),
            "method": method,
            "descriptor": descriptor,
            "callers": len((context.get("relations") or {}).get("callers", [])),
            "callees": len((context.get("relations") or {}).get("callees", [])),
            "source": bool((context.get("source") or {}).get("available")),
        },
    )

    return {
        "ok": bool((context.get("relations") or {}).get("ok")) or bool((context.get("source") or {}).get("available")),
        "session_id": session_id,
        "package": state["package"],
        "index": {
            "ok": index_result.get("ok"),
            "reused": index_result.get("reused"),
            "built": index_result.get("built"),
            "error": index_result.get("error"),
        },
        "source_prepare": source_prepare,
        **context,
    }


@mcp.tool()
def inspect_call_graph(
    session_id: str,
    class_name: str,
    method: str,
    descriptor: str = "",
    upstream_depth: int = 2,
    downstream_depth: int = 2,
    max_nodes: int = 120,
    max_edges: int = 300,
    max_paths: int = 20,
    expand_external: bool = False,
) -> dict:
    """递归展开一个 Java 方法的静态调用图，并叠加会话里已有的 runtime 命中证据。

    默认向上/向下各追 2 层；Java/Android/Kotlin 等外部框架方法会显示但不继续递归，
    避免调用图爆炸。representative_paths 直接给出“入口 → 目标 → 下游”的代表链。
    """
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "当前会话没有 APK，无法展开调用图",
        }

    prepared = external.ensure_dex_index(apk)
    if not prepared.get("ok"):
        return {
            **prepared,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
        }

    graph = investigation.call_graph_context(
        session_id,
        class_name,
        method,
        descriptor=descriptor,
        upstream_depth=upstream_depth,
        downstream_depth=downstream_depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_paths=max_paths,
        expand_external=expand_external,
    )
    investigation.add_discovery(
        session_id,
        {
            "type": "call_graph",
            "class": candidate.normalize_class_name(class_name),
            "method": method,
            "descriptor": descriptor,
            "nodes": graph.get("node_count", 0),
            "edges": graph.get("edge_count", 0),
            "runtime_confirmed_nodes": graph.get("runtime_confirmed_nodes", 0),
        },
    )
    return {
        **graph,
        "session_id": session_id,
        "package": state["package"],
    }


@mcp.tool()
def verify_call_path(
    session_id: str,
    class_name: str,
    method: str,
    descriptor: str = "",
    path_index: int = 0,
    upstream_depth: int = 2,
    downstream_depth: int = 2,
    seconds: float = 15.0,
    max_events: int = 400,
    max_hooks: int = 12,
    restart: bool = True,
    hot: bool = False,
    stack: bool = False,
    cleanup: bool = True,
    include_events: bool = False,
) -> dict:
    """一次性动态验证一条代表业务路径，并按方法入口时间还原真实执行顺序。

    默认先围绕目标方法生成 2 层上游 + 2 层下游调用图，选择 representative_paths[path_index]，
    给路径上的唯一 Java 方法统一挂 before Hook。触发一次目标行为后返回节点/边覆盖率、同线程有序链、
    相邻入口 delta_ms 和完整路径是否真实出现。
    """
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "当前会话没有 APK，无法动态验证调用路径",
        }

    prepared = external.ensure_dex_index(apk)
    if not prepared.get("ok"):
        return {
            **prepared,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
        }

    graph = investigation.call_graph_context(
        session_id,
        class_name,
        method,
        descriptor=descriptor,
        upstream_depth=max(0, min(int(upstream_depth), 5)),
        downstream_depth=max(0, min(int(downstream_depth), 5)),
        max_nodes=160,
        max_edges=480,
        max_paths=40,
        expand_external=False,
    )
    if not graph.get("ok"):
        return {
            **graph,
            "session_id": session_id,
            "package": state["package"],
        }

    selected_path = runtime_path.choose_path(graph, path_index=path_index)
    if selected_path is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "调用图中没有可验证的代表路径",
            "call_graph": {
                "node_count": graph.get("node_count", 0),
                "edge_count": graph.get("edge_count", 0),
            },
        }

    result = _verify_static_call_path(
        session_id,
        state,
        selected_path,
        seconds=seconds,
        max_events=max_events,
        max_hooks=max_hooks,
        restart=restart,
        hot=hot,
        stack=stack,
        cleanup=cleanup,
    )
    payload = {
        **result,
        "session_id": session_id,
        "package": state["package"],
        "selected_path_index": max(0, int(path_index)),
        "selected_path": {
            "text": selected_path.get("text", ""),
            "length": selected_path.get("length", 0),
            "nodes": selected_path.get("nodes", []),
        },
        "call_graph": {
            "node_count": graph.get("node_count", 0),
            "edge_count": graph.get("edge_count", 0),
            "representative_path_count": len(graph.get("representative_paths", [])),
        },
    }
    if not include_events:
        payload.pop("events", None)
    return payload


@mcp.tool()
def capture_call_graph_scenario(
    session_id: str,
    name: str,
    class_name: str,
    method: str,
    descriptor: str = "",
    upstream_depth: int = 2,
    downstream_depth: int = 2,
    seconds: float = 20.0,
    quiet_ms: int = 1500,
    max_events: int = 800,
    max_hooks: int = 24,
    include_external: bool = False,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict:
    """围绕同一目标方法采集一次可做 A/B 差分的真实调用图场景。

    会先生成局部静态调用图，再给图中的应用方法统一挂 before Hook。调用后在窗口内执行一次场景操作；
    命中会压缩为真实方法集合、静态边覆盖和主线程顺序并单独存盘。A/B 比较时会校验静态图和 Hook 集合指纹。
    """
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "当前会话没有 APK，无法采集调用图场景",
        }

    prepared = external.ensure_dex_index(apk)
    if not prepared.get("ok"):
        return {
            **prepared,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
        }

    graph = investigation.call_graph_context(
        session_id,
        class_name,
        method,
        descriptor=descriptor,
        upstream_depth=max(0, min(int(upstream_depth), 5)),
        downstream_depth=max(0, min(int(downstream_depth), 5)),
        max_nodes=max(40, min(int(max_hooks) * 4, 300)),
        max_edges=max(120, min(int(max_hooks) * 12, 900)),
        max_paths=30,
        expand_external=False,
    )
    if not graph.get("ok"):
        return {
            **graph,
            "session_id": session_id,
            "package": state["package"],
        }

    result = _capture_call_graph_scenario(
        session_id,
        state,
        name,
        graph,
        seconds=seconds,
        quiet_ms=quiet_ms,
        max_events=max_events,
        max_hooks=max_hooks,
        include_external=include_external,
        restart=restart,
        hot=hot,
        cleanup=cleanup,
    )
    return {
        **result,
        "session_id": session_id,
        "package": state["package"],
        "target": {
            "class": candidate.normalize_class_name(class_name),
            "method": method,
            "descriptor": descriptor,
        },
        "call_graph": {
            "node_count": graph.get("node_count", 0),
            "edge_count": graph.get("edge_count", 0),
        },
    }


@mcp.tool()
def list_call_graph_scenarios(session_id: str) -> dict:
    """列出当前 Investigation 会话保存的调用图动态场景。"""
    try:
        state = investigation.load(session_id)
        items = investigation.list_call_scenarios(session_id)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}
    return {
        "ok": True,
        "session_id": session_id,
        "package": state["package"],
        "count": len(items),
        "scenarios": items,
    }


@mcp.tool()
def diff_call_graph_scenarios(session_id: str, a: str, b: str) -> dict:
    """比较两个调用图场景，直接找共同链路、仅 A/仅 B、首次分叉和共享边耗时差。

    两个场景必须来自相同静态调用图和相同 Hook 集合；否则返回 comparable=false，
    避免把采集范围变化误判成业务分支变化。
    """
    try:
        state = investigation.load(session_id)
        scenario_a = investigation.load_call_scenario(session_id, a)
        scenario_b = investigation.load_call_scenario(session_id, b)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    result = scenario_path.diff_graph_scenarios(scenario_a, scenario_b)
    investigation.add_discovery(
        session_id,
        {
            "type": "call_graph_scenario_diff",
            "a": a,
            "b": b,
            "comparable": result.get("comparable", False),
            "only_in_a": len(result.get("only_in_a", [])),
            "only_in_b": len(result.get("only_in_b", [])),
            "common_prefix": len(
                (result.get("first_divergence") or {}).get("common_prefix", [])
            ),
        },
    )

    divergence = result.get("first_divergence") or {}
    if result.get("comparable"):
        if divergence.get("a_next") or divergence.get("b_next"):
            result["next_action"] = (
                "下一步调用 analyze_scenario_divergence，自动回到公共前缀最后一个方法，"
                "定位 if/switch/字段条件并生成 trace 探针计划"
            )
        else:
            result["next_action"] = (
                "主线程顺序没有明显分叉；优先查看 only_edges 与 shared_edge_timing，"
                "或扩大调用图深度后重新采集"
            )

    return {
        **result,
        "session_id": session_id,
        "package": state["package"],
    }


@mcp.tool()
def analyze_scenario_divergence(
    session_id: str,
    a: str,
    b: str,
    auto_prepare_source: bool = True,
    max_conditions: int = 20,
    max_probe_items: int = 8,
) -> dict:
    """从 A/B 调用图场景首次分叉自动定位源码条件。

    会取公共主线程前缀最后一个方法作为分支点，自动读取 JADX 方法体，结合 A/B 下一跳
    对 if/else、switch、Kotlin when 和三元表达式排序，并给出只读 trace 探针建议。
    """
    try:
        state = investigation.load(session_id, refresh=True)
        scenario_a = investigation.load_call_scenario(session_id, a)
        scenario_b = investigation.load_call_scenario(session_id, b)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    diff = scenario_path.diff_graph_scenarios(scenario_a, scenario_b)
    if not diff.get("comparable"):
        return {
            **diff,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": diff.get("error") or "两个场景不可比较",
        }

    divergence = diff.get("first_divergence") or {}
    common_prefix = divergence.get("common_prefix") or []
    if not common_prefix:
        return {
            **diff,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "两个场景没有共同主线程前缀，无法确定源码分支点",
            "next_action": "扩大调用图范围或确认两次操作确实从同一业务入口触发",
        }

    branch_label = str(common_prefix[-1])
    branch_meta: dict[str, Any] | None = None
    for item in scenario_a.get("hooked_methods") or []:
        label = (
            f"{candidate.normalize_class_name(str(item.get('class', '')))}."
            f"{item.get('method', '')}"
        )
        if label == branch_label:
            branch_meta = item
            break

    if branch_meta is None:
        if "." not in branch_label:
            return {
                **diff,
                "ok": False,
                "session_id": session_id,
                "package": state["package"],
                "error": f"无法解析分支点方法: {branch_label}",
            }
        class_name, method_name = branch_label.rsplit(".", 1)
        descriptor = ""
    else:
        class_name = candidate.normalize_class_name(
            str(branch_meta.get("class", ""))
        )
        method_name = str(branch_meta.get("method", ""))
        descriptor = str(branch_meta.get("descriptor", ""))

    apk = state.get("primary_apk", "")
    source_prepare: dict[str, Any] | None = None
    if (
        auto_prepare_source
        and apk
        and not state["artifacts"].get("jadx_dirs")
    ):
        source_prepare = external.decompile_apk(apk)
        state = investigation.load(session_id, refresh=True)

    context = investigation.method_context(
        session_id,
        class_name,
        method_name,
        descriptor=descriptor,
        relation_limit=50,
        include_source=True,
    )
    source = context.get("source") or {}
    relations = context.get("relations") or {}
    if not source.get("available"):
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "diff": diff,
            "branch_point": {
                "label": branch_label,
                "class": class_name,
                "method": method_name,
                "descriptor": descriptor,
            },
            "source_prepare": source_prepare,
            "method_context": context,
            "error": "已定位首次分叉方法，但 JADX 源码不可用，无法分析条件表达式",
            "next_action": "检查 JADX 反编译结果，或用 trace_target/trace_java 直接观测分支点方法",
        }

    ranked = branch_condition.rank_conditions(
        str(source.get("text", "")),
        divergence.get("a_next"),
        divergence.get("b_next"),
        class_fields=relations.get("class_fields") or [],
        limit=max(1, min(int(max_conditions), 50)),
    )
    probe_plan = branch_condition.build_probe_plan(
        class_name,
        method_name,
        ranked,
        max_items=max(1, min(int(max_probe_items), 20)),
    )
    for item in probe_plan:
        args = item.get("suggested_args") or {}
        args["package"] = state["package"]
        item["suggested_args"] = args

    top = ranked[0] if ranked else None
    investigation.add_discovery(
        session_id,
        {
            "type": "scenario_divergence_condition",
            "a": a,
            "b": b,
            "branch_point": branch_label,
            "a_next": divergence.get("a_next"),
            "b_next": divergence.get("b_next"),
            "condition_count": len(ranked),
            "top_condition": top.get("condition") if top else "",
            "top_line": top.get("line") if top else None,
            "top_score": top.get("score") if top else 0,
        },
    )

    if top:
        next_action = (
            "分别调用 capture_divergence_probe 采集场景 A/B 的同一探针；"
            "第二侧采完会自动比较，也可用 compare_divergence_probes 重算"
        )
    else:
        next_action = (
            "源码中没有识别到常规 if/switch/when/三元条件；"
            "检查异常控制流、早返回、回调/异步状态，或对分支点使用 trace_target"
        )

    return {
        "ok": True,
        "session_id": session_id,
        "package": state["package"],
        "a": a,
        "b": b,
        "branch_point": {
            "label": branch_label,
            "class": class_name,
            "method": method_name,
            "descriptor": descriptor,
        },
        "divergence": divergence,
        "source_prepare": source_prepare,
        "source": {
            "path": source.get("path", ""),
            "declaration_line": source.get("declaration_line"),
            "start_line": source.get("start_line"),
            "end_line": source.get("end_line"),
        },
        "top_condition": top,
        "conditions": ranked,
        "probe_plan": probe_plan,
        "next_action": next_action,
    }


def _select_divergence_probe(
    analysis: dict[str, Any],
    condition_rank: int,
    probe_index: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]]]:
    conditions = analysis.get("conditions") or []
    condition_rank = max(1, int(condition_rank))
    condition = next(
        (item for item in conditions if int(item.get("rank", 0) or 0) == condition_rank),
        None,
    )
    if condition is None:
        return None, None, []

    executable = [
        item
        for item in (analysis.get("probe_plan") or [])
        if int(item.get("condition_rank", 0) or 0) == condition_rank
        and item.get("tool")
    ]
    if not executable:
        return condition, None, []

    probe_index = max(0, min(int(probe_index), len(executable) - 1))
    probe = dict(executable[probe_index])
    probe["condition_type"] = condition.get("type", "")
    probe["branch_orientation"] = condition.get("branch_orientation", "")
    probe["a_next_method"] = condition.get("a_next_method", "")
    probe["b_next_method"] = condition.get("b_next_method", "")
    return condition, probe, executable


def _run_divergence_probe(
    session_id: str,
    state: dict[str, Any],
    scenario_name: str,
    probe: dict[str, Any],
    seconds: float = 15.0,
    max_events: int = 120,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict[str, Any]:
    kind = str(probe.get("kind", ""))
    class_name = str(probe.get("class", ""))
    method_name = str(probe.get("method", ""))
    if kind not in {"field", "condition_method"}:
        return {
            "ok": False,
            "error": f"当前探针类型不可自动执行: {kind}",
        }
    if not class_name or not method_name:
        return {
            "ok": False,
            "error": "探针缺少 class/method",
        }

    probe_key = condition_probe.probe_fingerprint(probe)
    safe_scenario = re.sub(r"[^A-Za-z0-9_]", "_", scenario_name)[:16] or "scenario"
    safe_method = re.sub(r"[^A-Za-z0-9_]", "_", method_name)[:20] or "method"
    hook_id = f"rbcp_{session_id}_{probe_key[:8]}_{safe_scenario}_{safe_method}"

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    investigation.add_temporary_hook(session_id, hook_id)
    try:
        if kind == "field":
            result = trace_java(
                package=state["package"],
                class_name=class_name,
                method=method_name,
                capture_args=[],
                fields=[
                    {
                        "target": "this",
                        "name": str(probe.get("field", "")),
                        "render": "tostring",
                    }
                ],
                this="class",
                ret=False,
                when="both",
                stack=False,
                hook_id=hook_id,
                restart=restart,
                seconds=max(0.5, float(seconds)),
                max_events=max(1, min(int(max_events), 500)),
                include_recent=True,
                since_seq=cursor,
                hot=hot,
            )
        else:
            result = trace_java(
                package=state["package"],
                class_name=class_name,
                method=method_name,
                capture_args=[],
                this="class",
                ret=True,
                when="after",
                stack=False,
                hook_id=hook_id,
                restart=restart,
                seconds=max(0.5, float(seconds)),
                max_events=max(1, min(int(max_events), 500)),
                include_recent=True,
                since_seq=cursor,
                hot=hot,
            )
    finally:
        if cleanup:
            try:
                unhook(state["package"], hook_id)
            finally:
                investigation.remove_temporary_hook(session_id, hook_id)

    events = result.get("events", [])
    summary = condition_probe.summarize_values(events, probe)

    try:
        latest = int(client.get_recent(limit=0).get("latest_seq", cursor) or cursor)
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    if events:
        investigation.record_trace_evidence(
            session_id,
            class_name,
            method_name,
            events,
        )

    capture = {
        "scenario": scenario_name,
        "captured_at": int(time.time() * 1000),
        "probe_fingerprint": probe_key,
        "probe": probe,
        "summary": summary,
        "hook_id": hook_id,
        "event_cursor": latest,
    }
    saved = investigation.save_condition_probe(
        session_id,
        scenario_name,
        probe_key,
        capture,
    )
    investigation.add_discovery(
        session_id,
        {
            "type": "divergence_condition_probe",
            "scenario": scenario_name,
            "kind": kind,
            "class": class_name,
            "method": method_name,
            "field": probe.get("field", ""),
            "condition": probe.get("condition", ""),
            "samples": summary.get("sample_count", 0),
            "stable": summary.get("stable", False),
            "stable_value": (
                (summary.get("stable_value") or {}).get("canonical")
                if summary.get("stable")
                else None
            ),
        },
    )

    return {
        "ok": True,
        "scenario": scenario_name,
        "probe_fingerprint": probe_key,
        "probe": probe,
        "summary": summary,
        "saved": saved,
        "posted": result.get("posted"),
        "event_count": len(events),
        "event_cursor": latest,
        "cleanup": cleanup,
    }


@mcp.tool()
def capture_divergence_probe(
    session_id: str,
    a: str,
    b: str,
    capture_for: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    seconds: float = 15.0,
    max_events: int = 120,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict:
    """采集 A/B 首次分叉条件的一个运行时值探针。

    capture_for 必须等于 a 或 b。字段探针会在分支点方法 before+after 读取 this.field，
    用于检查方法边界值是否稳定；条件方法探针会在 after 捕获返回值。第二侧采完后自动尝试比较。
    """
    if capture_for not in {a, b}:
        return {
            "ok": False,
            "session_id": session_id,
            "error": "capture_for 必须等于场景 a 或 b",
        }

    analysis = analyze_scenario_divergence(
        session_id,
        a,
        b,
        auto_prepare_source=True,
        max_conditions=max(20, int(condition_rank)),
        max_probe_items=20,
    )
    if not analysis.get("ok"):
        return analysis

    condition, probe, executable = _select_divergence_probe(
        analysis,
        condition_rank=condition_rank,
        probe_index=probe_index,
    )
    if condition is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": analysis.get("package"),
            "error": f"找不到 condition_rank={condition_rank}",
            "available_conditions": analysis.get("conditions", [])[:20],
        }
    if probe is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": analysis.get("package"),
            "error": "该条件没有可安全自动执行的探针",
            "condition": condition,
            "probe_plan": [
                item
                for item in (analysis.get("probe_plan") or [])
                if int(item.get("condition_rank", 0) or 0) == int(condition_rank)
            ],
            "next_action": "对象接收者条件需要先解析实际类型；也可手工 trace 分支点或对应对象方法",
        }

    state = investigation.load(session_id, refresh=True)
    result = _run_divergence_probe(
        session_id,
        state,
        capture_for,
        probe,
        seconds=seconds,
        max_events=max_events,
        restart=restart,
        hot=hot,
        cleanup=cleanup,
    )
    result.update(
        {
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "capture_for": capture_for,
            "condition": condition,
            "selected_probe_index": max(
                0,
                min(int(probe_index), max(0, len(executable) - 1)),
            ),
        }
    )

    probe_key = result.get("probe_fingerprint", "")
    if result.get("ok") and probe_key:
        other_name = b if capture_for == a else a
        other = investigation.load_condition_probe(
            session_id,
            other_name,
            probe_key,
        )
        current = investigation.load_condition_probe(
            session_id,
            capture_for,
            probe_key,
        )
        if other and current:
            capture_a = current if capture_for == a else other
            capture_b = current if capture_for == b else other
            comparison = condition_probe.compare_captures(
                capture_a,
                capture_b,
                branch_orientation=str(condition.get("branch_orientation", "")),
            )
            result["comparison"] = comparison

    return result


@mcp.tool()
def compare_divergence_probes(
    session_id: str,
    a: str,
    b: str,
    condition_rank: int = 1,
    probe_index: int = 0,
) -> dict:
    """比较已经采集的 A/B 条件探针值，并判断是否与源码 true/false 分支方向一致。"""
    analysis = analyze_scenario_divergence(
        session_id,
        a,
        b,
        auto_prepare_source=True,
        max_conditions=max(20, int(condition_rank)),
        max_probe_items=20,
    )
    if not analysis.get("ok"):
        return analysis

    condition, probe, executable = _select_divergence_probe(
        analysis,
        condition_rank=condition_rank,
        probe_index=probe_index,
    )
    if condition is None or probe is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": analysis.get("package"),
            "error": "所选条件没有可比较的自动探针",
            "condition": condition,
            "probe_plan": analysis.get("probe_plan", []),
        }

    probe_key = condition_probe.probe_fingerprint(probe)
    capture_a = investigation.load_condition_probe(session_id, a, probe_key)
    capture_b = investigation.load_condition_probe(session_id, b, probe_key)
    missing = [
        name
        for name, capture in ((a, capture_a), (b, capture_b))
        if capture is None
    ]
    if missing:
        return {
            "ok": False,
            "session_id": session_id,
            "package": analysis.get("package"),
            "a": a,
            "b": b,
            "condition": condition,
            "probe": probe,
            "probe_fingerprint": probe_key,
            "missing": missing,
            "error": "尚未完成两侧同一条件探针采集",
            "next_action": (
                "分别调用 capture_divergence_probe，capture_for="
                + " / ".join(missing)
            ),
        }

    comparison = condition_probe.compare_captures(
        capture_a,
        capture_b,
        branch_orientation=str(condition.get("branch_orientation", "")),
    )
    investigation.add_discovery(
        session_id,
        {
            "type": "divergence_condition_probe_comparison",
            "a": a,
            "b": b,
            "condition": condition.get("condition", ""),
            "condition_line": condition.get("line"),
            "probe_kind": probe.get("kind", ""),
            "probe_field": probe.get("field", ""),
            "probe_method": probe.get("method", ""),
            "status": comparison.get("status"),
            "evidence_level": comparison.get("evidence_level"),
            "a_value": (
                ((comparison.get("a") or {}).get("value") or {}).get("canonical")
            ),
            "b_value": (
                ((comparison.get("b") or {}).get("value") or {}).get("canonical")
            ),
        },
    )

    if comparison.get("status") == "branch_orientation_confirmed":
        next_action = (
            "该条件的运行时值与 A/B 源码分支方向一致；可继续 inspect_method/trace_target "
            "追查这个状态值是在哪里被赋值或计算出来的"
        )
    elif comparison.get("status") == "values_differ":
        next_action = (
            "A/B 值稳定且不同，但当前条件不是可直接验证方向的布尔分支；"
            "结合 switch/when case 或继续追该字段来源"
        )
    elif comparison.get("status") == "same_value":
        next_action = (
            "该探针两边值相同，优先换 condition_rank/probe_index 检查同一分叉点的其他条件依赖"
        )
    else:
        next_action = (
            "当前证据不足或存在冲突；增加采集次数、检查触发时机，或手工 trace 条件依赖"
        )

    return {
        **comparison,
        "session_id": session_id,
        "package": analysis.get("package"),
        "condition": condition,
        "probe": probe,
        "selected_probe_index": max(
            0,
            min(int(probe_index), max(0, len(executable) - 1)),
        ),
        "next_action": next_action,
    }


@mcp.tool()
def inspect_condition_origin(
    session_id: str,
    a: str,
    b: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_limit: int = 30,
) -> dict:
    """从已确认的 A/B 分叉条件继续追踪字段 writer/readers 或条件方法返回值来源。"""
    analysis = analyze_scenario_divergence(
        session_id,
        a,
        b,
        auto_prepare_source=True,
        max_conditions=max(20, int(condition_rank)),
        max_probe_items=20,
    )
    if not analysis.get("ok"):
        return analysis

    condition, probe, executable = _select_divergence_probe(
        analysis,
        condition_rank=condition_rank,
        probe_index=probe_index,
    )
    if condition is None or probe is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": analysis.get("package"),
            "error": "所选条件没有可自动追踪的安全探针",
            "condition": condition,
            "probe_plan": analysis.get("probe_plan", []),
        }

    state = investigation.load(session_id, refresh=True)
    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": "当前会话没有 APK",
        }

    prepared = external.ensure_dex_index(apk)
    if not prepared.get("ok"):
        return {
            **prepared,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
        }

    kind = str(probe.get("kind", ""))
    if kind == "field":
        origin = investigation.field_origin_context(
            session_id,
            str(probe.get("class", "")),
            str(probe.get("field", "")),
            limit=max(1, min(int(writer_limit), 100)),
            include_source=True,
        )
        if origin.get("ok"):
            investigation.record_field_origin_evidence(session_id, origin)

        top_writer = origin.get("top_writer") if origin.get("ok") else None
        next_action = (
            "调用 verify_condition_writer 对排名靠前的 writer 做 before/after 字段值验证，"
            "确认谁在真实行为里改变了该状态"
            if top_writer
            else "静态索引没有找到 writer；检查字段是否由 native/反射/序列化框架写入"
        )
        investigation.add_discovery(
            session_id,
            {
                "type": "condition_field_origin",
                "a": a,
                "b": b,
                "field": probe.get("field", ""),
                "class": probe.get("class", ""),
                "writers": origin.get("writer_count", 0),
                "readers": origin.get("reader_count", 0),
                "top_writer": (
                    f"{top_writer.get('class', '')}.{top_writer.get('method', '')}"
                    if isinstance(top_writer, dict)
                    else ""
                ),
            },
        )
        return {
            "ok": bool(origin.get("ok")),
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "condition": condition,
            "probe": probe,
            "selected_probe_index": max(
                0,
                min(int(probe_index), max(0, len(executable) - 1)),
            ),
            "origin_kind": "field",
            "field_origin": origin,
            "next_action": next_action,
        }

    if kind == "condition_method":
        origin = investigation.condition_method_origin_context(
            session_id,
            str(probe.get("class", "")),
            str(probe.get("method", "")),
        )
        context = origin.get("context") or {}
        if context:
            investigation.record_method_context_evidence(
                session_id,
                str(probe.get("class", "")),
                str(probe.get("method", "")),
                "",
                context,
            )
        investigation.add_discovery(
            session_id,
            {
                "type": "condition_method_origin",
                "a": a,
                "b": b,
                "class": probe.get("class", ""),
                "method": probe.get("method", ""),
                "best_source": (
                    (origin.get("value_source") or {}).get("best_source_hint")
                    or {}
                ).get("kind", ""),
            },
        )
        return {
            "ok": bool(origin.get("ok")),
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "condition": condition,
            "probe": probe,
            "origin_kind": "condition_method",
            "method_origin": origin,
            "next_action": (
                "优先检查 return 表达式与 callees；若返回值来自对象字段或 repository/API，"
                "继续 inspect_method 对对应 callee 展开来源"
            ),
        }

    return {
        "ok": False,
        "session_id": session_id,
        "package": state["package"],
        "condition": condition,
        "probe": probe,
        "error": f"暂不支持自动追踪的 probe kind: {kind}",
    }


@mcp.tool()
def verify_condition_writer(
    session_id: str,
    a: str,
    b: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    seconds: float = 15.0,
    max_events: int = 160,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict:
    """动态验证字段 writer 是否真的在一次行为中改变已确认的分叉条件字段。"""
    origin_result = inspect_condition_origin(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_limit=max(30, int(writer_rank)),
    )
    if not origin_result.get("ok"):
        return origin_result
    if origin_result.get("origin_kind") != "field":
        return {
            **origin_result,
            "ok": False,
            "error": "verify_condition_writer 仅用于字段条件；条件方法请继续追其 return/callee 来源",
        }

    field_origin = origin_result.get("field_origin") or {}
    writers = field_origin.get("writers") or []
    writer_rank = max(1, int(writer_rank))
    writer = next(
        (item for item in writers if int(item.get("rank", 0) or 0) == writer_rank),
        None,
    )
    if writer is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": origin_result.get("package"),
            "error": f"找不到 writer_rank={writer_rank}",
            "writers": writers[:20],
        }

    field = field_origin.get("field") or {}
    field_class = candidate.normalize_class_name(str(field.get("class", "")))
    writer_class = candidate.normalize_class_name(str(writer.get("class", "")))
    field_name = str(field.get("name", ""))
    if writer_class != field_class:
        return {
            "ok": False,
            "session_id": session_id,
            "package": origin_result.get("package"),
            "field": field,
            "writer": writer,
            "error": (
                "该 writer 不属于字段声明类，自动 this.field 观测可能读取错误对象；"
                "当前只自动验证同类实例字段 writer"
            ),
            "next_action": "查看 writer 源码确认目标对象来源后，再用 trace_java paths/fields 手工指定",
        }

    state = investigation.load(session_id, refresh=True)
    safe_method = re.sub(
        r"[^A-Za-z0-9_]",
        "_",
        str(writer.get("method", "")),
    )[:24] or "writer"
    safe_field = re.sub(
        r"[^A-Za-z0-9_]",
        "_",
        field_name,
    )[:20] or "field"
    hook_id = f"rbwr_{session_id}_{writer_rank}_{safe_method}_{safe_field}"

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    investigation.add_temporary_hook(session_id, hook_id)
    try:
        result = trace_java(
            package=state["package"],
            class_name=writer_class,
            method=str(writer.get("method", "")),
            capture_args=[],
            fields=[
                {
                    "target": "this",
                    "name": field_name,
                    "render": "tostring",
                }
            ],
            this="class",
            ret=False,
            when="both",
            stack=False,
            hook_id=hook_id,
            restart=restart,
            seconds=max(0.5, float(seconds)),
            max_events=max(2, min(int(max_events), 600)),
            include_recent=True,
            since_seq=cursor,
            hot=hot,
        )
    finally:
        if cleanup:
            try:
                unhook(state["package"], hook_id)
            finally:
                investigation.remove_temporary_hook(session_id, hook_id)

    events = result.get("events", [])
    change = writer_probe.analyze_writer_events(events, field_name)

    try:
        latest = int(client.get_recent(limit=0).get("latest_seq", cursor) or cursor)
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    if events:
        investigation.record_trace_evidence(
            session_id,
            writer_class,
            str(writer.get("method", "")),
            events,
        )

    investigation.add_discovery(
        session_id,
        {
            "type": "condition_writer_verification",
            "field": field_name,
            "writer": f"{writer_class}.{writer.get('method', '')}",
            "writer_rank": writer_rank,
            "paired_calls": change.get("paired_calls", 0),
            "changed_calls": change.get("changed_calls", 0),
            "changed": change.get("changed", False),
        },
    )

    return {
        "ok": True,
        "session_id": session_id,
        "package": state["package"],
        "a": a,
        "b": b,
        "condition": origin_result.get("condition"),
        "probe": origin_result.get("probe"),
        "field": field,
        "writer": writer,
        "writer_rank": writer_rank,
        "change": change,
        "event_cursor": latest,
        "posted": result.get("posted"),
        "cleanup": cleanup,
        "next_action": (
            "该 writer 已观测到字段值变化；下一步调用 inspect_value_lineage 自动跨方法追右值来源链"
            if change.get("changed")
            else "本轮未观测到字段变化；确认已触发对应场景，或尝试下一个 writer_rank"
        ),
    }


@mcp.tool()
def inspect_value_lineage(
    session_id: str,
    a: str,
    b: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    max_depth: int = 4,
    max_nodes: int = 60,
) -> dict:
    """跨方法递归追踪已确认 A/B 分叉条件的值来源。

    字段条件从指定 writer 的赋值右值开始，按 DEX callee 与 JADX return 继续上溯；
    条件方法直接从 return 表达式开始。解析不唯一时会保留 ambiguities，不会擅自选类。
    """
    origin_result = inspect_condition_origin(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_limit=max(40, int(writer_rank)),
    )
    if not origin_result.get("ok"):
        return origin_result

    state = investigation.load(session_id, refresh=True)
    origin_kind = str(origin_result.get("origin_kind", ""))

    if origin_kind == "field":
        field_origin = origin_result.get("field_origin") or {}
        field = field_origin.get("field") or {}
        lineage = investigation.field_value_lineage(
            session_id,
            str(field.get("class", "")),
            str(field.get("name", "")),
            field_type=str(field.get("type", "")),
            writer_rank=max(1, int(writer_rank)),
            max_depth=max_depth,
            max_nodes=max_nodes,
        )
        if lineage.get("ok"):
            investigation.record_value_lineage_evidence(session_id, lineage)

        investigation.add_discovery(
            session_id,
            {
                "type": "value_lineage",
                "kind": "field",
                "field": field.get("name", ""),
                "writer_rank": writer_rank,
                "nodes": lineage.get("node_count", 0),
                "edges": lineage.get("edge_count", 0),
                "paths": len(lineage.get("origin_paths", [])),
                "ambiguities": len(lineage.get("ambiguities", [])),
            },
        )

        if lineage.get("ambiguities"):
            next_action = (
                "存在同名 callee 歧义；优先查看 ambiguities 的候选类，结合 writer 源码接收者类型后再收窄"
            )
        elif lineage.get("origin_paths"):
            next_action = (
                "优先查看 origin_paths 中最长且 runtime_confirmed 节点最多的链；"
                "下一步分别 verify_value_lineage 采集 A/B，再 compare_value_lineage_runtime 找最早真实值差异"
            )
        else:
            next_action = (
                "没有形成完整来源路径；检查 unresolved_calls，或确认值是否来自反射/native/序列化框架"
            )

        return {
            "ok": bool(lineage.get("ok")),
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "condition": origin_result.get("condition"),
            "probe": origin_result.get("probe"),
            "origin_kind": "field",
            "field": field,
            "writer_rank": max(1, int(writer_rank)),
            "lineage": lineage,
            "next_action": next_action,
        }

    if origin_kind == "condition_method":
        probe = origin_result.get("probe") or {}
        lineage = investigation.condition_method_value_lineage(
            session_id,
            str(probe.get("class", "")),
            str(probe.get("method", "")),
            max_depth=max_depth,
            max_nodes=max_nodes,
        )
        if lineage.get("ok"):
            investigation.record_value_lineage_evidence(session_id, lineage)

        investigation.add_discovery(
            session_id,
            {
                "type": "value_lineage",
                "kind": "condition_method",
                "method": f"{probe.get('class', '')}.{probe.get('method', '')}",
                "nodes": lineage.get("node_count", 0),
                "edges": lineage.get("edge_count", 0),
                "paths": len(lineage.get("origin_paths", [])),
                "ambiguities": len(lineage.get("ambiguities", [])),
            },
        )
        return {
            "ok": bool(lineage.get("ok")),
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "condition": origin_result.get("condition"),
            "probe": probe,
            "origin_kind": "condition_method",
            "lineage": lineage,
            "next_action": (
                "查看 origin_paths；若某层出现 ambiguities，先解析接收者实际类型；"
                "无歧义时分别 verify_value_lineage 采集 A/B 并比较链上返回值"
            ),
        }

    return {
        "ok": False,
        "session_id": session_id,
        "package": state["package"],
        "error": f"暂不支持 Value Lineage 的 origin_kind: {origin_kind}",
    }


def _capture_runtime_value_lineage(
    session_id: str,
    state: dict[str, Any],
    scenario_name: str,
    path: dict[str, Any],
    seconds: float = 20.0,
    quiet_ms: int = 1500,
    max_events: int = 600,
    max_hooks: int = 16,
    include_external: bool = False,
    return_render: str = "tostring",
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict[str, Any]:
    methods = runtime_lineage.path_methods(
        path,
        max_hooks=max_hooks,
        include_external=include_external,
    )
    if not methods:
        return {
            "ok": False,
            "error": "所选 Value Lineage 路径中没有可运行时验证的方法",
        }

    render = return_render if return_render in {"tostring", "class", "json", "deep"} else "tostring"
    field = runtime_lineage.terminal_field(path)
    writer = methods[-1] if methods else None
    can_capture_field = bool(
        field
        and writer
        and str(field.get("class", "")) == str(writer.get("class", ""))
        and field.get("field")
    )

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    targets: list[dict[str, Any]] = []
    hook_ids: list[str] = []
    hook_map: dict[str, dict[str, Any]] = {}

    for index, method in enumerate(methods, 1):
        safe_class = re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            method["class"].rsplit(".", 1)[-1],
        )[:18] or "class"
        safe_method = re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            method["method"],
        )[:22] or "method"
        hook_id = (
            f"rbvl_{session_id}_{index}_{safe_class}_{safe_method}"
        )
        hook_ids.append(hook_id)
        hook_map[hook_id] = method
        investigation.add_temporary_hook(session_id, hook_id)

        is_writer = bool(
            can_capture_field
            and int(method["path_index"]) == int(writer["path_index"])
        )
        capture: dict[str, Any] = {
            "this": "class",
            "when": "both" if is_writer else "after",
            "all_args": False,
            "ret": {
                "capture": True,
                "render": render,
                "max": 4096,
            },
            "stack": False,
        }
        if is_writer:
            capture["fields"] = [
                {
                    "target": "this",
                    "name": str(field.get("field", "")),
                    "render": "tostring",
                }
            ]

        targets.append(
            {
                "kind": "java",
                "id": hook_id,
                "class": method["class"],
                "method": method["method"],
                "capture": capture,
            }
        )

    config: dict[str, Any] = {
        "package": state["package"],
        "restart": bool(restart and not hot),
        "debug": False,
        "targets": targets,
    }
    if hot:
        config["restart"] = False
        config["mode"] = "append"

    posted: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    collect_error = ""

    try:
        posted = client.post_json("/hook", config)
        events = client.collect_sse(
            seconds=max(0.5, float(seconds)),
            max_events=max(1, min(int(max_events), 2500)),
            fold_stack=True,
            include_recent=True,
            since_seq=cursor,
            quiet_ms=max(0, int(quiet_ms)),
        )
    except Exception as exc:
        collect_error = str(exc)
    finally:
        if cleanup:
            for hook_id in hook_ids:
                try:
                    unhook(state["package"], hook_id)
                except Exception:
                    pass
                finally:
                    investigation.remove_temporary_hook(session_id, hook_id)

    try:
        latest = int(
            client.get_recent(limit=0).get("latest_seq", cursor)
            or cursor
        )
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    analysis = runtime_lineage.analyze_capture(
        path,
        events,
        hook_map,
    )

    for hook_id, meta in hook_map.items():
        matched = [
            event
            for event in events
            if (
                str(event.get("hook_id", "")) == hook_id
                or (
                    candidate.normalize_class_name(
                        str(event.get("class", ""))
                    ) == meta["class"]
                    and str(event.get("method", "")) == meta["method"]
                )
            )
        ]
        if matched:
            investigation.record_trace_evidence(
                session_id,
                meta["class"],
                meta["method"],
                matched,
            )

    investigation.record_runtime_lineage_evidence(
        session_id,
        path,
        analysis,
    )

    lineage_key = runtime_lineage.path_fingerprint(path)
    capture = {
        "scenario": scenario_name,
        "captured_at": int(time.time() * 1000),
        "lineage_fingerprint": lineage_key,
        "path_text": path.get("text", ""),
        "path": {
            "length": path.get("length", 0),
            "nodes": path.get("nodes", []),
            "relations": path.get("relations", []),
        },
        "hooked_methods": methods,
        "analysis": analysis,
    }
    saved = investigation.save_runtime_lineage_capture(
        session_id,
        scenario_name,
        lineage_key,
        capture,
    )
    investigation.add_discovery(
        session_id,
        {
            "type": "runtime_value_lineage",
            "scenario": scenario_name,
            "lineage_fingerprint": lineage_key,
            "methods": analysis.get("method_count", 0),
            "method_coverage": analysis.get("method_coverage", 0),
            "ordered_coverage": analysis.get("ordered_coverage", 0),
            "full_sequence": analysis.get(
                "full_method_sequence_observed",
                False,
            ),
            "writer_changed": bool(
                (analysis.get("writer_change") or {}).get("changed")
            ),
        },
    )

    return {
        "ok": not bool(collect_error),
        "scenario": scenario_name,
        "lineage_fingerprint": lineage_key,
        "analysis": analysis,
        "hooked_methods": methods,
        "saved": saved,
        "posted": posted,
        "events": events[:300],
        "event_cursor": latest,
        "cleanup": cleanup,
        "error": collect_error or None,
    }


@mcp.tool()
def verify_value_lineage(
    session_id: str,
    a: str,
    b: str,
    capture_for: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    path_index: int = 0,
    max_depth: int = 4,
    max_nodes: int = 60,
    seconds: float = 20.0,
    quiet_ms: int = 1500,
    max_events: int = 600,
    max_hooks: int = 16,
    include_external: bool = False,
    return_render: str = "tostring",
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
    include_events: bool = False,
) -> dict:
    """一次性动态验证一条 Value Lineage 的方法返回顺序与最终字段变化。

    capture_for 必须等于 a 或 b。默认对路径中的应用方法抓 after 返回值；
    若路径以同类实例字段结束，则最后 writer 同时抓 before/after 字段值。
    """
    if capture_for not in {a, b}:
        return {
            "ok": False,
            "session_id": session_id,
            "error": "capture_for 必须等于场景 a 或 b",
        }

    lineage_result = inspect_value_lineage(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_rank=writer_rank,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    if not lineage_result.get("ok"):
        return lineage_result

    lineage = lineage_result.get("lineage") or {}
    paths = lineage.get("origin_paths") or []
    if not paths:
        return {
            **lineage_result,
            "ok": False,
            "error": "当前 Value Lineage 没有形成可验证的 origin_path",
            "next_action": "先处理 ambiguities/unresolved_calls，再重新生成 Lineage",
        }

    path_index = max(0, min(int(path_index), len(paths) - 1))
    selected_path = paths[path_index]
    state = investigation.load(session_id, refresh=True)

    result = _capture_runtime_value_lineage(
        session_id,
        state,
        capture_for,
        selected_path,
        seconds=seconds,
        quiet_ms=quiet_ms,
        max_events=max_events,
        max_hooks=max_hooks,
        include_external=include_external,
        return_render=return_render,
        restart=restart,
        hot=hot,
        cleanup=cleanup,
    )
    result.update(
        {
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "capture_for": capture_for,
            "selected_path_index": path_index,
            "selected_path": selected_path,
            "condition": lineage_result.get("condition"),
            "probe": lineage_result.get("probe"),
        }
    )

    key = result.get("lineage_fingerprint", "")
    if result.get("ok") and key:
        other_name = b if capture_for == a else a
        other = investigation.load_runtime_lineage_capture(
            session_id,
            other_name,
            key,
        )
        current = investigation.load_runtime_lineage_capture(
            session_id,
            capture_for,
            key,
        )
        if other and current:
            capture_a = current if capture_for == a else other
            capture_b = current if capture_for == b else other
            result["comparison"] = runtime_lineage.compare_captures(
                capture_a,
                capture_b,
            )

    if not include_events:
        result.pop("events", None)
    return result


@mcp.tool()
def compare_value_lineage_runtime(
    session_id: str,
    a: str,
    b: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    path_index: int = 0,
    max_depth: int = 4,
    max_nodes: int = 60,
) -> dict:
    """比较已采集的 A/B Runtime Value Lineage，找最早稳定值差异。"""
    lineage_result = inspect_value_lineage(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_rank=writer_rank,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    if not lineage_result.get("ok"):
        return lineage_result

    paths = (lineage_result.get("lineage") or {}).get(
        "origin_paths",
        [],
    )
    if not paths:
        return {
            **lineage_result,
            "ok": False,
            "error": "当前 Value Lineage 没有 origin_path",
        }

    path_index = max(0, min(int(path_index), len(paths) - 1))
    selected_path = paths[path_index]
    key = runtime_lineage.path_fingerprint(selected_path)

    capture_a = investigation.load_runtime_lineage_capture(
        session_id,
        a,
        key,
    )
    capture_b = investigation.load_runtime_lineage_capture(
        session_id,
        b,
        key,
    )
    missing = [
        name
        for name, capture in ((a, capture_a), (b, capture_b))
        if capture is None
    ]
    if missing:
        return {
            "ok": False,
            "session_id": session_id,
            "package": lineage_result.get("package"),
            "a": a,
            "b": b,
            "lineage_fingerprint": key,
            "selected_path_index": path_index,
            "selected_path": selected_path,
            "missing": missing,
            "error": "尚未完成两侧同一 Runtime Value Lineage 采集",
            "next_action": (
                "分别调用 verify_value_lineage，capture_for="
                + " / ".join(missing)
            ),
        }

    comparison = runtime_lineage.compare_captures(
        capture_a,
        capture_b,
    )
    first = comparison.get("first_stable_value_difference")

    investigation.add_discovery(
        session_id,
        {
            "type": "runtime_value_lineage_comparison",
            "a": a,
            "b": b,
            "lineage_fingerprint": key,
            "first_difference": (
                first.get("label", "")
                if isinstance(first, dict)
                else ""
            ),
            "a_full_sequence": comparison.get(
                "a_full_sequence",
                False,
            ),
            "b_full_sequence": comparison.get(
                "b_full_sequence",
                False,
            ),
        },
    )

    if first:
        next_action = (
            "已找到 A/B 最早稳定返回值差异；下一步调用 rank_root_causes，"
            "把最早差异、writer 变化与静态来源证据综合排序"
        )
    elif comparison.get("a_full_sequence") and comparison.get(
        "b_full_sequence"
    ):
        next_action = (
            "两侧链路都完整命中但未找到稳定返回值差异；可将 return_render 改为 deep，"
            "或对关键对象使用 paths 抓内部字段"
        )
    else:
        next_action = (
            "至少一侧链路覆盖不完整；确认触发行为或扩大 seconds/max_events 后重新采集"
        )

    return {
        **comparison,
        "session_id": session_id,
        "package": lineage_result.get("package"),
        "selected_path_index": path_index,
        "selected_path": selected_path,
        "next_action": next_action,
    }


@mcp.tool()
def rank_root_causes(
    session_id: str,
    a: str,
    b: str,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    path_index: int = 0,
    max_depth: int = 4,
    max_nodes: int = 60,
    limit: int = 5,
    include_hypothesis: bool = True,
) -> dict:
    """综合静态来源、Runtime Lineage 与 writer 变化，对根因节点做可解释排序。

    即使 A/B Runtime Lineage 尚未采集，也会返回静态排序；若运行时结果齐全，
    会把最早稳定值差异、A/B 命中、完整链覆盖和 writer 字段变化加入评分。
    """
    lineage_result = inspect_value_lineage(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_rank=writer_rank,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )
    if not lineage_result.get("ok"):
        return lineage_result

    lineage = lineage_result.get("lineage") or {}
    paths = lineage.get("origin_paths") or []
    if not paths:
        return {
            **lineage_result,
            "ok": False,
            "error": "当前 Value Lineage 没有 origin_path，无法排序根因",
        }

    path_index = max(0, min(int(path_index), len(paths) - 1))
    selected_path = paths[path_index]
    lineage_key = runtime_lineage.path_fingerprint(selected_path)

    capture_a = None
    capture_b = None
    try:
        capture_a = investigation.load_runtime_lineage_capture(
            session_id,
            a,
            lineage_key,
        )
    except (ValueError, FileNotFoundError):
        capture_a = None
    try:
        capture_b = investigation.load_runtime_lineage_capture(
            session_id,
            b,
            lineage_key,
        )
    except (ValueError, FileNotFoundError):
        capture_b = None

    runtime_comparison = None
    if capture_a is not None and capture_b is not None:
        comparison = runtime_lineage.compare_captures(
            capture_a,
            capture_b,
        )
        if comparison.get("comparable"):
            runtime_comparison = comparison

    hypothesis_results = (
        investigation.root_cause_hypothesis_results(session_id)
        if include_hypothesis
        else {}
    )
    ranking = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=runtime_comparison,
        hypothesis_results=hypothesis_results,
        selected_path_index=path_index,
        limit=max(1, min(int(limit), 20)),
    )
    if not ranking.get("ok"):
        return {
            **ranking,
            "session_id": session_id,
            "package": lineage_result.get("package"),
            "a": a,
            "b": b,
        }

    investigation.record_root_cause_ranking(
        session_id,
        ranking,
    )

    top = ranking.get("top_candidate") or {}
    missing_runtime = [
        name
        for name, capture in ((a, capture_a), (b, capture_b))
        if capture is None
    ]
    investigation.add_discovery(
        session_id,
        {
            "type": "root_cause_ranking",
            "a": a,
            "b": b,
            "lineage_fingerprint": lineage_key,
            "top_label": top.get("label", ""),
            "top_score": top.get("score", 0),
            "top_evidence_level": top.get("evidence_level", ""),
            "runtime_available": bool(runtime_comparison),
            "missing_runtime": missing_runtime,
        },
    )

    top_hypothesis = top.get("hypothesis_verification") or {}
    if missing_runtime:
        next_action = (
            "当前排名包含静态证据；要提升到运行时根因排序，请分别调用 verify_value_lineage，"
            "capture_for=" + " / ".join(missing_runtime)
        )
    elif top_hypothesis.get("status"):
        next_action = str(top.get("next_action", "")) or (
            "该候选已完成最小假设实验；按验证结论继续追内部计算或上游输入"
        )
    elif top.get("is_first_runtime_difference"):
        next_action = (
            "排名第一节点就是 A/B 最早稳定值差异；下一步分别调用 "
            "verify_root_cause_hypothesis 采集 A/B，验证差异是在方法内部产生还是入口已不同"
        )
    elif top.get("is_writer") and top.get("writer_changed"):
        next_action = (
            "排名第一节点是已真实改字段的 writer；继续追它的赋值右值和上游 callee"
        )
    else:
        next_action = str(top.get("next_action", "")) or (
            "继续补充排名靠前节点的运行时值证据"
        )

    return {
        **ranking,
        "session_id": session_id,
        "package": lineage_result.get("package"),
        "a": a,
        "b": b,
        "condition": lineage_result.get("condition"),
        "probe": lineage_result.get("probe"),
        "lineage_fingerprint": lineage_key,
        "runtime_available": bool(runtime_comparison),
        "missing_runtime": missing_runtime,
        "runtime_comparison": runtime_comparison,
        "hypothesis_results_applied": len(hypothesis_results),
        "next_action": next_action,
    }


def _capture_root_cause_hypothesis(
    session_id: str,
    state: dict[str, Any],
    scenario_name: str,
    plan: dict[str, Any],
    seconds: float = 15.0,
    quiet_ms: int = 1200,
    max_events: int = 200,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
) -> dict[str, Any]:
    class_name = str(plan.get("class", ""))
    method_name = str(plan.get("method", ""))
    if not class_name or not method_name:
        return {"ok": False, "error": "假设实验缺少 class/method"}

    fingerprint = str(plan.get("hypothesis_fingerprint", ""))
    safe_scenario = re.sub(
        r"[^A-Za-z0-9_]",
        "_",
        scenario_name,
    )[:16] or "scenario"
    safe_method = re.sub(
        r"[^A-Za-z0-9_]",
        "_",
        method_name,
    )[:20] or "method"
    hook_id = (
        f"rbhyp_{session_id}_{fingerprint[:8]}_"
        f"{safe_scenario}_{safe_method}"
    )

    capture: dict[str, Any] = {
        "this": "class",
        "when": "both",
        "stack": False,
    }

    arg_specs = []
    for item in plan.get("capture_args") or []:
        arg_specs.append(
            {
                "index": int(item.get("index", 0)),
                "render": str(item.get("render", "tostring")),
                "max": int(item.get("max", 3000) or 3000),
            }
        )
    if arg_specs:
        capture["args"] = arg_specs
    elif not bool(
        (plan.get("input_coverage") or {}).get("descriptor_parsed")
    ):
        capture["all_args"] = True
    else:
        capture["all_args"] = False

    fields = []
    for item in plan.get("capture_fields") or []:
        fields.append(
            {
                "target": "this",
                "name": str(item.get("name", "")),
                "render": str(item.get("render", "tostring")),
                "max": int(item.get("max", 2500) or 2500),
            }
        )
    if fields:
        capture["fields"] = fields

    if plan.get("capture_return"):
        capture["ret"] = {
            "capture": True,
            "render": str(plan.get("return_render", "tostring")),
            "max": 5000,
        }

    target: dict[str, Any] = {
        "kind": "java",
        "id": hook_id,
        "class": class_name,
        "method": method_name,
        "capture": capture,
    }
    params = plan.get("params")
    if isinstance(params, list):
        target["params"] = params

    config: dict[str, Any] = {
        "package": state["package"],
        "restart": bool(restart and not hot),
        "debug": False,
        "targets": [target],
    }
    if hot:
        config["restart"] = False
        config["mode"] = "append"

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    investigation.add_temporary_hook(session_id, hook_id)
    posted: dict[str, Any] = {}
    events: list[dict[str, Any]] = []
    collect_error = ""
    try:
        posted = client.post_json("/hook", config)
        events = client.collect_sse(
            seconds=max(0.5, float(seconds)),
            max_events=max(2, min(int(max_events), 800)),
            fold_stack=True,
            include_recent=True,
            since_seq=cursor,
            quiet_ms=max(0, int(quiet_ms)),
        )
    except Exception as exc:
        collect_error = str(exc)
    finally:
        if cleanup:
            try:
                unhook(state["package"], hook_id)
            except Exception:
                pass
            finally:
                investigation.remove_temporary_hook(
                    session_id,
                    hook_id,
                )

    try:
        latest = int(
            client.get_recent(limit=0).get("latest_seq", cursor)
            or cursor
        )
        investigation.set_event_cursor(session_id, latest)
    except Exception:
        latest = cursor

    matched = [
        event
        for event in events
        if (
            str(event.get("hook_id", "")) == hook_id
            or (
                candidate.normalize_class_name(
                    str(event.get("class", ""))
                ) == class_name
                and str(event.get("method", "")) == method_name
            )
        )
    ]
    analysis = hypothesis_verify.analyze_capture(
        matched,
        plan,
    )
    if matched:
        investigation.record_trace_evidence(
            session_id,
            class_name,
            method_name,
            matched,
        )

    payload = {
        "scenario": scenario_name,
        "captured_at": int(time.time() * 1000),
        "hypothesis_fingerprint": fingerprint,
        "candidate_key": plan.get("candidate_key", ""),
        "candidate": plan.get("candidate", {}),
        "plan": {
            "class": class_name,
            "method": method_name,
            "descriptor": plan.get("descriptor", ""),
            "overload_precision": plan.get(
                "overload_precision",
                "",
            ),
            "capture_args": plan.get("capture_args", []),
            "capture_fields": plan.get("capture_fields", []),
            "capture_return": bool(plan.get("capture_return")),
            "return_render": plan.get("return_render", ""),
            "input_coverage": plan.get("input_coverage", {}),
        },
        "analysis": analysis,
    }
    saved = investigation.save_root_cause_hypothesis_capture(
        session_id,
        scenario_name,
        fingerprint,
        payload,
    )

    investigation.add_discovery(
        session_id,
        {
            "type": "root_cause_hypothesis_capture",
            "scenario": scenario_name,
            "candidate_key": plan.get("candidate_key", ""),
            "candidate": (
                f"{class_name}.{method_name}"
            ),
            "before_count": analysis.get("before_count", 0),
            "after_count": analysis.get("after_count", 0),
            "primary_tid": analysis.get("primary_tid"),
        },
    )

    return {
        "ok": not bool(collect_error),
        "scenario": scenario_name,
        "hypothesis_fingerprint": fingerprint,
        "candidate_key": plan.get("candidate_key", ""),
        "plan": plan,
        "analysis": analysis,
        "saved": saved,
        "posted": posted,
        "event_count": len(matched),
        "events": matched[:120],
        "event_cursor": latest,
        "cleanup": cleanup,
        "error": collect_error or None,
    }


def _saved_hypothesis_candidate_for_rank(
    session_id: str,
    scenario_name: str,
    candidate_rank: int,
) -> dict[str, Any] | None:
    """从另一侧场景复用已固定的候选，避免首侧命中导致排名漂移后 A/B 错配。"""
    try:
        data = investigation.load_call_scenario(
            session_id,
            scenario_name,
        )
    except (ValueError, FileNotFoundError):
        return None

    captures = data.get("root_cause_hypothesis_captures") or {}
    ordered = sorted(
        (
            item
            for item in captures.values()
            if isinstance(item, dict)
        ),
        key=lambda item: int(item.get("saved_at", 0) or 0),
        reverse=True,
    )
    for item in ordered:
        candidate_row = item.get("candidate") or {}
        if (
            int(candidate_row.get("rank", 0) or 0)
            == int(candidate_rank)
            and candidate_row.get("candidate_type") == "method"
            and candidate_row.get("candidate_key")
        ):
            return dict(candidate_row)
    return None


@mcp.tool()
def verify_root_cause_hypothesis(
    session_id: str,
    a: str,
    b: str,
    capture_for: str,
    candidate_rank: int = 1,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    path_index: int = 0,
    max_depth: int = 4,
    max_nodes: int = 60,
    max_args: int = 8,
    max_fields: int = 6,
    seconds: float = 15.0,
    quiet_ms: int = 1200,
    max_events: int = 200,
    restart: bool = True,
    hot: bool = False,
    cleanup: bool = True,
    include_events: bool = False,
) -> dict:
    """对一个方法根因候选执行最小 A/B 输入输出实验。

    实验候选始终从不含旧假设加权的基线排名中选择，避免验证后排名变化导致
    A/B 两次采集错接到不同候选。第二侧完成后会自动比较并返回验证后排名。
    """
    if capture_for not in {a, b}:
        return {
            "ok": False,
            "session_id": session_id,
            "error": "capture_for 必须等于场景 a 或 b",
        }

    candidate_rank = max(1, min(int(candidate_rank), 20))
    baseline = rank_root_causes(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_rank=writer_rank,
        path_index=path_index,
        max_depth=max_depth,
        max_nodes=max_nodes,
        limit=max(10, candidate_rank),
        include_hypothesis=False,
    )
    if not baseline.get("ok"):
        return baseline

    other_name = b if capture_for == a else a
    selected = _saved_hypothesis_candidate_for_rank(
        session_id,
        other_name,
        candidate_rank,
    )
    candidate_pinned_from_other_scenario = selected is not None
    if selected is None:
        selected = next(
            (
                item
                for item in (baseline.get("candidates") or [])
                if int(item.get("rank", 0) or 0) == candidate_rank
            ),
            None,
        )
    if selected is None:
        return {
            "ok": False,
            "session_id": session_id,
            "package": baseline.get("package"),
            "error": f"找不到 candidate_rank={candidate_rank}",
            "candidates": baseline.get("candidates", []),
        }
    if selected.get("candidate_type") != "method":
        method_candidates = [
            item
            for item in (baseline.get("candidates") or [])
            if item.get("candidate_type") == "method"
        ]
        return {
            "ok": False,
            "session_id": session_id,
            "package": baseline.get("package"),
            "candidate": selected,
            "error": "静态来源节点不能直接做方法输入输出实验",
            "method_candidates": method_candidates[:5],
            "next_action": (
                "若当前 Top 是静态来源，先完成 verify_value_lineage A/B；"
                "或选择 method_candidates 中的 candidate_rank"
            ),
        }

    context = investigation.method_context(
        session_id,
        str(selected.get("class", "")),
        str(selected.get("method", "")),
        descriptor=str(selected.get("descriptor", "")),
        relation_limit=80,
        include_source=True,
    )
    plan = hypothesis_verify.plan_experiment(
        selected,
        context,
        max_args=max_args,
        max_fields=max_fields,
    )
    if not plan.get("ok"):
        return {
            **plan,
            "session_id": session_id,
            "package": baseline.get("package"),
        }

    state = investigation.load(session_id, refresh=True)
    result = _capture_root_cause_hypothesis(
        session_id,
        state,
        capture_for,
        plan,
        seconds=seconds,
        quiet_ms=quiet_ms,
        max_events=max_events,
        restart=restart,
        hot=hot,
        cleanup=cleanup,
    )
    result.update(
        {
            "session_id": session_id,
            "package": state["package"],
            "a": a,
            "b": b,
            "capture_for": capture_for,
            "candidate_rank": candidate_rank,
            "baseline_candidate": selected,
            "candidate_pinned_from_other_scenario": (
                candidate_pinned_from_other_scenario
            ),
            "baseline_top_candidate": baseline.get(
                "top_candidate"
            ),
        }
    )

    fingerprint = str(
        result.get("hypothesis_fingerprint", "")
    )
    if result.get("ok") and fingerprint:
        other_name = b if capture_for == a else a
        other = investigation.load_root_cause_hypothesis_capture(
            session_id,
            other_name,
            fingerprint,
        )
        current = investigation.load_root_cause_hypothesis_capture(
            session_id,
            capture_for,
            fingerprint,
        )
        if other and current:
            capture_a = current if capture_for == a else other
            capture_b = current if capture_for == b else other
            comparison = hypothesis_verify.compare_captures(
                capture_a,
                capture_b,
            )
            investigation.save_root_cause_hypothesis_result(
                session_id,
                str(selected.get("candidate_key", "")),
                comparison,
            )
            investigation.record_root_cause_hypothesis_evidence(
                session_id,
                selected,
                comparison,
            )
            result["comparison"] = comparison
            result["updated_ranking"] = rank_root_causes(
                session_id,
                a,
                b,
                condition_rank=condition_rank,
                probe_index=probe_index,
                writer_rank=writer_rank,
                path_index=path_index,
                max_depth=max_depth,
                max_nodes=max_nodes,
                limit=10,
                include_hypothesis=True,
            )

    if not include_events:
        result.pop("events", None)
    return result


@mcp.tool()
def compare_root_cause_hypothesis(
    session_id: str,
    a: str,
    b: str,
    candidate_rank: int = 1,
    condition_rank: int = 1,
    probe_index: int = 0,
    writer_rank: int = 1,
    path_index: int = 0,
    max_depth: int = 4,
    max_nodes: int = 60,
    max_args: int = 8,
    max_fields: int = 6,
) -> dict:
    """重新比较已采集的根因假设实验，并返回验证前/后的根因排名变化。"""
    candidate_rank = max(1, min(int(candidate_rank), 20))
    baseline = rank_root_causes(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_rank=writer_rank,
        path_index=path_index,
        max_depth=max_depth,
        max_nodes=max_nodes,
        limit=max(10, candidate_rank),
        include_hypothesis=False,
    )
    if not baseline.get("ok"):
        return baseline

    selected = _saved_hypothesis_candidate_for_rank(
        session_id,
        a,
        candidate_rank,
    )
    if selected is None:
        selected = _saved_hypothesis_candidate_for_rank(
            session_id,
            b,
            candidate_rank,
        )
    if selected is None:
        selected = next(
            (
                item
                for item in (baseline.get("candidates") or [])
                if int(item.get("rank", 0) or 0) == candidate_rank
            ),
            None,
        )
    if selected is None or selected.get("candidate_type") != "method":
        return {
            "ok": False,
            "session_id": session_id,
            "package": baseline.get("package"),
            "candidate": selected,
            "error": "所选 candidate_rank 不是可验证的方法候选",
        }

    context = investigation.method_context(
        session_id,
        str(selected.get("class", "")),
        str(selected.get("method", "")),
        descriptor=str(selected.get("descriptor", "")),
        relation_limit=80,
        include_source=True,
    )
    plan = hypothesis_verify.plan_experiment(
        selected,
        context,
        max_args=max_args,
        max_fields=max_fields,
    )
    fingerprint = str(
        plan.get("hypothesis_fingerprint", "")
    )
    if not plan.get("ok") or not fingerprint:
        return {
            **plan,
            "session_id": session_id,
            "package": baseline.get("package"),
        }

    capture_a = investigation.load_root_cause_hypothesis_capture(
        session_id,
        a,
        fingerprint,
    )
    capture_b = investigation.load_root_cause_hypothesis_capture(
        session_id,
        b,
        fingerprint,
    )
    missing = [
        name
        for name, capture in ((a, capture_a), (b, capture_b))
        if capture is None
    ]
    if missing:
        return {
            "ok": False,
            "session_id": session_id,
            "package": baseline.get("package"),
            "candidate": selected,
            "plan": plan,
            "missing": missing,
            "error": "尚未完成两侧同一 Root Cause 假设实验采集",
            "next_action": (
                "分别调用 verify_root_cause_hypothesis，capture_for="
                + " / ".join(missing)
            ),
        }

    comparison = hypothesis_verify.compare_captures(
        capture_a,
        capture_b,
    )
    investigation.save_root_cause_hypothesis_result(
        session_id,
        str(selected.get("candidate_key", "")),
        comparison,
    )
    investigation.record_root_cause_hypothesis_evidence(
        session_id,
        selected,
        comparison,
    )
    updated = rank_root_causes(
        session_id,
        a,
        b,
        condition_rank=condition_rank,
        probe_index=probe_index,
        writer_rank=writer_rank,
        path_index=path_index,
        max_depth=max_depth,
        max_nodes=max_nodes,
        limit=10,
        include_hypothesis=True,
    )

    new_candidate = next(
        (
            item
            for item in (updated.get("candidates") or [])
            if item.get("candidate_key")
            == selected.get("candidate_key")
        ),
        None,
    )
    return {
        "ok": True,
        "session_id": session_id,
        "package": baseline.get("package"),
        "a": a,
        "b": b,
        "candidate": selected,
        "plan": plan,
        "comparison": comparison,
        "baseline_rank": selected.get("rank"),
        "baseline_score": selected.get("score"),
        "updated_candidate": new_candidate,
        "updated_ranking": updated,
        "next_action": (
            (new_candidate or {}).get("next_action")
            or comparison.get("explanation", "")
        ),
    }


@mcp.tool()
def investigate(
    session_id: str,
    goal: str,
    verify_runtime: bool = True,
    top_n: int = 5,
    seconds: float = 15.0,
    max_queries: int = 4,
    hot: bool = False,
    restart: bool = True,
    stack: bool = False,
    include_events: bool = False,
    include_source: bool = True,
    auto_prepare_source: bool = True,
    relation_limit: int = 20,
    include_call_graph: bool = True,
    call_up_depth: int = 2,
    call_down_depth: int = 2,
    call_graph_max_nodes: int = 120,
) -> dict:
    """执行一轮自动调查：目标解析 → DEX 索引 → 多词候选排序 → 可选运行时验证 → 方法上下文 → 证据汇总。

    goal 可以是自然语言，例如“找到会员状态判断方法”或“定位点击「立即开通」后走的方法”。
    默认会做运行时验证，并在主候选确定后自动展开 callers/callees、JADX 源码与递归调用链。
    如果设备/Tracer 不可用，仍保留静态候选、源码和静态调用路径。
    """
    goal = goal.strip()
    if not goal:
        return {"ok": False, "error": "goal 不能为空", "session_id": session_id}

    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    apk = state.get("primary_apk", "")
    if not apk:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "goal": goal,
            "status": "missing_apk",
            "error": "当前会话没有 APK，无法执行自动调查",
            "next_action": "确保设备可连接后重新 open_target，或先 pull_apk",
        }

    planned_queries = pipeline.plan_queries(goal, max_queries=max_queries)
    if not planned_queries:
        planned_queries = [goal]

    stages: list[dict[str, Any]] = []

    index_result = external.ensure_dex_index(apk)
    stages.append(
        {
            "stage": "index",
            "ok": bool(index_result.get("ok")),
            "reused": bool(index_result.get("reused")),
            "built": bool(index_result.get("built")),
            "error": index_result.get("error"),
        }
    )

    rankings: list[tuple[str, list[dict[str, Any]]]] = []
    ranking_errors: list[str] = []
    per_query: list[dict[str, Any]] = []
    static_limit = max(10, min(30, int(top_n) * 3))

    for query in planned_queries:
        result = _rank_target_candidates(
            state,
            query,
            limit=static_limit,
            pool_limit=max(80, static_limit * 6),
        )
        candidates = result.get("candidates", [])
        if candidates:
            rankings.append((query, candidates))
            investigation.record_search_evidence(
                session_id,
                query,
                "investigate-static",
                candidates,
            )
        ranking_errors.extend(result.get("errors", []))
        per_query.append(
            {
                "query": query,
                "candidate_count": len(candidates),
                "pool_size": result.get("pool_size", 0),
            }
        )

    merged = pipeline.merge_rankings(
        rankings,
        limit=max(10, min(30, int(top_n) * 3)),
    )
    stages.append(
        {
            "stage": "static_ranking",
            "ok": bool(merged),
            "queries": per_query,
            "candidate_count": len(merged),
            "errors": ranking_errors[:8],
        }
    )

    investigation.add_discovery(
        session_id,
        {
            "type": "investigation_pipeline",
            "goal": goal,
            "queries": planned_queries,
            "static_candidates": len(merged),
            "verify_runtime": bool(verify_runtime),
        },
    )

    if not merged:
        return {
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "goal": goal,
            "planned_queries": planned_queries,
            "status": "no_candidates",
            "stages": stages,
            "top_candidates": [],
            "next_action": "尝试更具体的 UI 文案/类名/字段名，或 prepare_target 后做源码搜索",
        }

    top_n = max(1, min(int(top_n), 8))
    static_top = merged[:top_n]
    verification: dict[str, Any] | None = None

    if verify_runtime:
        # 刷新 state，让刚写入的证据图可以参与后续记录。
        state = investigation.load(session_id, refresh=True)
        verification = _verify_ranked_candidates(
            session_id,
            state,
            planned_queries[0],
            static_top,
            seconds=seconds,
            max_events=max(100, top_n * 30),
            restart=restart,
            hot=hot,
            stack=stack,
            cleanup=True,
        )
        stages.append(
            {
                "stage": "runtime_verification",
                "ok": bool(verification.get("ok")),
                "tested": verification.get("tested", 0),
                "confirmed": verification.get("confirmed_count", 0),
                "event_count": verification.get("event_count", 0),
                "error": verification.get("error"),
            }
        )

    confirmed = (verification or {}).get("confirmed", [])
    if confirmed:
        status = "runtime_confirmed"
        primary = confirmed[0]
        next_action = "先用 verify_call_path 验证代表业务链；需要更深参数/字段时再对 primary_candidate 使用 trace_target"
    elif verify_runtime and verification and verification.get("ok"):
        status = "runtime_no_hit"
        primary = static_top[0]
        next_action = "确认已触发目标行为；可先 inspect_call_graph 查看静态链，再用 verify_call_path 单独验证代表路径"
    elif verify_runtime:
        status = "static_ranked_runtime_unavailable"
        primary = static_top[0]
        next_action = "静态候选与调用图已保留；检查设备/Tracer 后可直接 verify_call_path 验证代表路径"
    else:
        status = "static_ranked"
        primary = static_top[0]
        next_action = "需要确认真实执行路径时，调用 verify_candidates 或再次 investigate(verify_runtime=true)"

    method_ctx: dict[str, Any] | None = None
    source_prepare: dict[str, Any] | None = None
    if include_source and auto_prepare_source:
        refreshed = investigation.load(session_id, refresh=True)
        if not refreshed["artifacts"].get("jadx_dirs"):
            source_prepare = external.decompile_apk(apk)
            refreshed = investigation.load(session_id, refresh=True)
            stages.append(
                {
                    "stage": "source_prepare",
                    "ok": bool(source_prepare.get("ok")) if isinstance(source_prepare, dict) else False,
                    "reused": False,
                    "error": source_prepare.get("error") if isinstance(source_prepare, dict) else None,
                }
            )

    try:
        method_ctx = investigation.method_context(
            session_id,
            str(primary.get("class", "")),
            str(primary.get("method", "")),
            descriptor=str(primary.get("descriptor", "")),
            relation_limit=max(1, min(int(relation_limit), 100)),
            include_source=include_source,
        )
        investigation.record_method_context_evidence(
            session_id,
            candidate.normalize_class_name(str(primary.get("class", ""))),
            str(primary.get("method", "")),
            str(primary.get("descriptor", "")),
            method_ctx,
        )
        relations = method_ctx.get("relations") or {}
        source_info = method_ctx.get("source") or {}
        stages.append(
            {
                "stage": "method_context",
                "ok": bool(relations.get("ok")) or bool(source_info.get("available")),
                "callers": len(relations.get("callers", [])),
                "callees": len(relations.get("callees", [])),
                "strings": len(relations.get("strings", [])),
                "source": bool(source_info.get("available")),
                "error": relations.get("error"),
            }
        )
    except Exception as exc:
        method_ctx = {
            "relations": {"ok": False, "error": str(exc)},
            "source": {"available": False, "reason": "context_failed"},
        }
        stages.append(
            {
                "stage": "method_context",
                "ok": False,
                "error": str(exc),
            }
        )

    call_graph: dict[str, Any] | None = None
    if include_call_graph:
        try:
            call_graph = investigation.call_graph_context(
                session_id,
                str(primary.get("class", "")),
                str(primary.get("method", "")),
                descriptor=str(primary.get("descriptor", "")),
                upstream_depth=max(0, min(int(call_up_depth), 5)),
                downstream_depth=max(0, min(int(call_down_depth), 5)),
                max_nodes=max(20, min(int(call_graph_max_nodes), 300)),
                max_edges=max(60, min(int(call_graph_max_nodes) * 3, 900)),
                max_paths=20,
                expand_external=False,
            )
            stages.append(
                {
                    "stage": "call_graph",
                    "ok": bool(call_graph.get("ok")),
                    "nodes": call_graph.get("node_count", 0),
                    "edges": call_graph.get("edge_count", 0),
                    "paths": len(call_graph.get("representative_paths", [])),
                    "runtime_confirmed_nodes": call_graph.get("runtime_confirmed_nodes", 0),
                    "error": call_graph.get("error"),
                }
            )
        except Exception as exc:
            call_graph = {"ok": False, "error": str(exc)}
            stages.append(
                {
                    "stage": "call_graph",
                    "ok": False,
                    "error": str(exc),
                }
            )

    focus = (
        (primary.get("matched_queries") or [None])[0]
        or planned_queries[0]
        or goal
    )
    try:
        explanation = investigation.explain_evidence_graph(
            session_id,
            focus=str(focus),
            depth=3,
            limit=80,
        )
    except Exception as exc:
        explanation = {
            "focus": focus,
            "summary": f"证据汇总失败: {exc}",
            "runtime_confirmed": [],
        }

    compact_confirmed = [
        pipeline.compact_candidate(item)
        for item in confirmed[:top_n]
    ]
    compact_static = [
        pipeline.compact_candidate(item)
        for item in merged[: max(top_n, 8)]
    ]

    result: dict[str, Any] = {
        "ok": True,
        "session_id": session_id,
        "package": state["package"],
        "goal": goal,
        "planned_queries": planned_queries,
        "status": status,
        "runtime_verified": bool(confirmed),
        "primary_candidate": pipeline.compact_candidate(primary),
        "confirmed": compact_confirmed,
        "top_candidates": compact_static,
        "evidence_summary": explanation.get("summary", ""),
        "evidence_focus": explanation.get("focus", focus),
        "method_context": method_ctx,
        "call_graph": (
            {
                "ok": call_graph.get("ok"),
                "node_count": call_graph.get("node_count", 0),
                "edge_count": call_graph.get("edge_count", 0),
                "runtime_confirmed_nodes": call_graph.get("runtime_confirmed_nodes", 0),
                "representative_paths": (call_graph.get("representative_paths") or [])[:8],
                "upstream_paths": (call_graph.get("upstream_paths") or [])[:5],
                "downstream_paths": (call_graph.get("downstream_paths") or [])[:5],
                "limits": call_graph.get("limits", {}),
                "error": call_graph.get("error"),
            }
            if call_graph is not None
            else None
        ),
        "stages": stages,
        "next_action": next_action,
    }

    if verification:
        result["runtime"] = {
            "ok": verification.get("ok"),
            "tested": verification.get("tested", 0),
            "confirmed_count": verification.get("confirmed_count", 0),
            "event_count": verification.get("event_count", 0),
            "error": verification.get("error"),
        }
        if include_events:
            result["events"] = verification.get("events", [])[:100]

    return result


@mcp.tool()
def rank_candidates(
    session_id: str,
    query: str,
    limit: int = 10,
    pool_limit: int = 80,
) -> dict:
    """从字符串 xref、方法名、类名与 Evidence Graph 中生成可解释的候选方法排序。

    每个候选返回 score + reasons；已有运行时命中证据会显著前置，但不会删除低分候选。
    这个工具只做静态排序，不连接设备执行 Hook。
    """
    query = query.strip()
    if not query:
        return {"ok": False, "error": "query 不能为空", "session_id": session_id}

    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    result = _rank_target_candidates(
        state,
        query,
        limit=max(1, min(int(limit), 50)),
        pool_limit=pool_limit,
    )
    if result.get("candidates"):
        investigation.record_search_evidence(
            session_id,
            query,
            "candidate-ranking",
            result["candidates"],
        )
        investigation.add_discovery(
            session_id,
            {
                "type": "candidate_ranking",
                "query": query,
                "count": len(result["candidates"]),
            },
        )
    return {
        **result,
        "session_id": session_id,
        "package": state["package"],
    }


@mcp.tool()
def verify_candidates(
    session_id: str,
    query: str,
    top_n: int = 5,
    seconds: float = 15.0,
    max_events: int = 200,
    restart: bool = True,
    hot: bool = False,
    stack: bool = False,
    cleanup: bool = True,
) -> dict:
    """把排名靠前的多个 Java 候选一次性装 Hook，并在一个共享窗口里验证谁真实命中。

    调用后在 seconds 秒内触发一次目标行为即可。只会做观测，不篡改参数或返回值。
    hot=True 时尝试向已运行目标热加全部候选；默认结束后逐个清理本次临时 Hook。
    """
    query = query.strip()
    if not query:
        return {"ok": False, "error": "query 不能为空", "session_id": session_id}

    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    top_n = max(1, min(int(top_n), 8))
    ranked_result = _rank_target_candidates(
        state,
        query,
        limit=top_n,
        pool_limit=max(60, top_n * 20),
    )
    ranked = ranked_result.get("candidates", [])
    if not ranked:
        return {
            **ranked_result,
            "ok": False,
            "session_id": session_id,
            "package": state["package"],
            "error": ranked_result.get("error") or "没有可验证的候选方法",
        }

    result = _verify_ranked_candidates(
        session_id,
        state,
        query,
        ranked,
        seconds=seconds,
        max_events=max_events,
        restart=restart,
        hot=hot,
        stack=stack,
        cleanup=cleanup,
    )
    return {
        **result,
        "session_id": session_id,
        "package": state["package"],
    }


@mcp.tool()
def trace_target(session_id: str, class_name: str, method: str,
                 params: Optional[list] = None,
                 seconds: float = 12.0,
                 max_events: int = 80,
                 hot: bool = False,
                 restart: bool = True,
                 cleanup: bool = True,
                 stack: bool = False,
                 paths: Optional[list] = None) -> dict:
    """在当前会话目标上临时 trace 一个 Java 方法，命中即返回，并默认自动卸载 Hook。

    这是 trace_java 的会话化快捷入口：自动使用会话包名、维护事件游标、生成唯一 hook_id，
    默认 until_first_hit=True，避免每次手工拼 package/hook id/采集参数。
    """
    try:
        state = investigation.load(session_id, refresh=True)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    safe_method = re.sub(r"[^A-Za-z0-9_]", "_", method)[:30] or "method"
    safe_class = re.sub(r"[^A-Za-z0-9_]", "_", class_name.rsplit(".", 1)[-1])[:24] or "class"
    hook_id = f"rb_{session_id}_{safe_class}_{safe_method}"

    try:
        cursor = int(client.get_recent(limit=0).get("latest_seq", 0) or 0)
    except Exception:
        cursor = int(state.get("event_cursor", 0) or 0)

    investigation.add_temporary_hook(session_id, hook_id)
    try:
        result = trace_java(
            package=state["package"],
            class_name=class_name,
            method=method,
            params=params,
            paths=paths,
            stack=stack,
            hook_id=hook_id,
            restart=restart,
            seconds=seconds,
            max_events=max_events,
            until_first_hit=True,
            include_recent=True,
            since_seq=cursor,
            hot=hot,
        )
        try:
            latest = int(client.get_recent(limit=0).get("latest_seq", cursor) or cursor)
            investigation.set_event_cursor(session_id, latest)
        except Exception:
            latest = cursor

        investigation.add_discovery(session_id, {
            "type": "runtime_trace",
            "class": class_name,
            "method": method,
            "hits": result.get("count", 0),
        })
        investigation.record_trace_evidence(
            session_id,
            class_name,
            method,
            result.get("events", []),
        )
        result.update({
            "session_id": session_id,
            "package": state["package"],
            "hook_id": hook_id,
            "event_cursor": latest,
        })
        return result
    finally:
        if cleanup:
            try:
                unhook(state["package"], hook_id)
            finally:
                investigation.remove_temporary_hook(session_id, hook_id)


@mcp.tool()
def evidence_graph(session_id: str, focus: str = "", depth: int = 2, limit: int = 100) -> dict:
    """查看分析会话证据图。

    focus 为空时返回图摘要与一部分节点；指定字符串、类名、方法名或字段名后，
    返回该节点附近最多 depth 层的关联证据。适合继续调查前快速恢复上下文。
    """
    try:
        graph = investigation.evidence_subgraph(
            session_id,
            focus=focus,
            depth=depth,
            limit=limit,
        )
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}
    return {
        "ok": True,
        "session_id": session_id,
        **graph,
    }


@mcp.tool()
def explain_evidence(session_id: str, focus: str, depth: int = 3, limit: int = 80) -> dict:
    """解释某个关键词/类/方法/字段当前已有的证据链。

    返回关联字符串、方法、字段、运行时确认情况和对应边，不替用户做最终安全结论，
    但能直接回答“我们为什么怀疑/确认这里”。
    """
    focus = focus.strip()
    if not focus:
        return {"ok": False, "error": "focus 不能为空", "session_id": session_id}
    try:
        result = investigation.explain_evidence_graph(
            session_id,
            focus=focus,
            depth=depth,
            limit=limit,
        )
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}
    return {
        "ok": True,
        "session_id": session_id,
        **result,
    }


@mcp.tool()
def close_investigation(session_id: str, cleanup_hooks: bool = True) -> dict:
    """结束分析会话；默认同时清理该目标包由分析过程留下的 hook。"""
    try:
        state = investigation.load(session_id)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc), "session_id": session_id}

    cleanup = None
    if cleanup_hooks:
        try:
            cleanup = unhook(state["package"])
        except Exception as exc:
            cleanup = {"ok": False, "error": str(exc)}
    closed = investigation.close(session_id)
    if cleanup is not None:
        closed["hook_cleanup"] = cleanup
    return closed


# =====================================================================
# 设备原子工具（封装 M1 HTTP 接口）
# =====================================================================

@mcp.tool()
def device_status() -> dict:
    """探测手机守护进程状态与连接方式，返回 /health 及当前传输配置。用于排查连不上的问题。"""
    health = client.get_json("/health")
    return {
        "transport": settings.transport,
        "base_url": client._base,  # noqa: SLF001 便于诊断
        "health": health,
    }


@mcp.tool()
def list_packages(name_filter: str = "", only_third_party: bool = False) -> dict:
    """列出设备上已安装应用（包名 / versionCode / 安装路径 / 是否系统应用）。

    name_filter: 只保留包名包含该子串的（不区分大小写）；空则不过滤。
    only_third_party: True 时只返回非系统应用。
    """
    data = client.get_json("/packages")
    pkgs = data.get("packages", [])
    nf = name_filter.lower()
    out = []
    for p in pkgs:
        if only_third_party and p.get("system"):
            continue
        if nf and nf not in p.get("package", "").lower():
            continue
        out.append(p)
    return {"count": len(out), "total_installed": data.get("count"), "packages": out}


@mcp.tool()
def pull_apk(package_name: str) -> dict:
    """拉取某应用的**全部** apk（base.apk + 所有 split_config.*.apk）到 PC 工作目录。

    返回本地文件路径列表；等价 adb pull 但走 reconbridge，不依赖 adb 授权。
    """
    info = client.get_json("/apk", {"pkg": package_name})
    apks = info.get("apks", [])
    if not apks:
        raise ReconError(f"{package_name} 无 apk 或未安装")
    dest_dir = _pkg_dir(package_name, "apk")
    results = []
    for a in apks:
        remote = a["path"]
        dest = dest_dir / a["name"]
        n = client.download("/apk", {"pkg": package_name, "path": remote}, dest)
        ok = (a.get("size", -1) in (-1, n))
        results.append({"name": a["name"], "local_path": str(dest),
                        "bytes": n, "remote_size": a.get("size"), "size_match": ok})
    return {"package": package_name, "count": len(results),
            "dir": str(dest_dir), "files": results}


@mcp.tool()
def pull_libs(package_name: str) -> dict:
    """拉取某应用 lib 目录下已落地的 native .so 到 PC 工作目录。

    若应用 extractNativeLibs=false，可能没有落地 so（此时用 pull_apk 拉包后本地解包 lib/arm64-v8a/）。
    """
    info = client.get_json("/libs", {"pkg": package_name})
    libs = info.get("libs", [])
    dest_dir = _pkg_dir(package_name, "libs")
    results = []
    for so in libs:
        dest = dest_dir / so["name"]
        n = client.download("/libs", {"pkg": package_name, "path": so["path"]}, dest)
        results.append({"name": so["name"], "local_path": str(dest), "bytes": n})
    return {"package": package_name, "count": len(results), "dir": str(dest_dir),
            "note": info.get("note"), "files": results}


@mcp.tool()
def read_remote_file(path: str, save_as: str = "", max_inline_kb: int = 64) -> dict:
    """root 读取设备上任意文件（流式）。

    path: 设备绝对路径。
    save_as: PC 本地保存路径；为空时存到工作目录 files/ 下。
    小于 max_inline_kb 且疑似文本时，附带内联内容预览。
    """
    if save_as:
        p = Path(save_as)
        if not p.is_absolute():
            p = settings.workdir / p
        dest = p.resolve()
        try:
            dest.relative_to(settings.workdir.resolve())
        except ValueError:
            raise ReconError(f"save_as path must be within workdir ({settings.workdir})")
    else:
        safe_name = Path(path).name
        if not safe_name or safe_name in (".", ".."):
            safe_name = "remote_file"
        dest = (settings.workdir / "files" / safe_name).resolve()
        try:
            dest.relative_to(settings.workdir.resolve())
        except ValueError:
            raise ReconError(f"Target path escapes workdir: {path}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    n = client.download("/file", {"path": path}, dest)
    result: dict[str, Any] = {"remote_path": path, "local_path": str(dest), "bytes": n}
    if n <= max_inline_kb * 1024:
        raw = dest.read_bytes()
        try:
            result["text"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            result["text"] = None
            result["hint"] = "二进制文件，未内联；见 local_path"
    return result



@mcp.tool()
def proc_info(pid: int, what: str = "status") -> dict:
    """读取 /proc/<pid>/<what>，what ∈ maps|status|cmdline。"""
    text = client.get_text("/proc", {"pid": str(pid), "what": what})
    return {"pid": pid, "what": what, "content": text}


@mcp.tool()
def remote_shell(argv: Optional[list[str]] = None, cmd: str = "") -> dict:
    """在设备上以 root 执行**白名单内**命令。优先用 argv 数组（安全，无需引号）。

    白名单：id whoami getprop uname ls cat stat du df md5sum sha1sum sha256sum
            pm cmd dumpsys ps getenforce settings wc head tail ip netstat pgrep
            mount readlink basename dirname find date。白名单外返回 403。
    """
    body: dict[str, Any] = {}
    if argv:
        body["argv"] = argv
    elif cmd:
        body["cmd"] = cmd
    else:
        raise ReconError("需要 argv 或 cmd")
    return client.post_json("/shell", body)


# =====================================================================
# PC 本地反编译工具链（详见 external.py）
# =====================================================================

@mcp.tool()
def decompile_apk(apk_path: str, output_dir: str = "") -> dict:
    """用 jadx 反编译 apk 到 Java 源码目录，返回反编译输出目录。

    apk_path: 本地 apk（用 pull_apk 拉下来的 base.apk）。
    output_dir: 输出目录；为空时放到 apk 同级的 jadx-out/。
    """
    return external.decompile_apk(apk_path, output_dir)


@mcp.tool()
def dexkit_search(apk_path: str, query: dict) -> dict:
    """用 DexKit 在 apk 的 dex 里做链式查询（定位类/方法/字段）。

    query 为结构化查询描述，支持的形式见 external.py 文档；例如：
      {"find": "method", "method_name": "encrypt"}
      {"find": "method", "using_strings": ["sign", "md5"]}
      {"find": "class", "class_name": "SecurityUtil"}
    """
    return external.dexkit_search(apk_path, query)


@mcp.tool()
def ghidra_analyze(so_path: str, options: Optional[dict] = None) -> dict:
    """用 Ghidra headless 分析 .so，返回导出表 / 导入表 / 字符串 / 函数列表 / 可疑函数。

    options: {"strings_min_len": 5, "max_functions": 400, "decompile": ["symbol1", 0x1234]}
             decompile 里给符号名或偏移可返回其反编译伪代码。
    """
    return external.ghidra_analyze(so_path, options or {})


@mcp.tool()
def hermes_decompile(bundle_path: str, output_dir: str = "") -> dict:
    """反编译 React Native Hermes 字节码 .hbc（通常在 apk 的 assets/index.android.bundle）。"""
    return external.hermes_decompile(bundle_path, output_dir)


# =====================================================================
# 动态 hook / dump（M3 / M4）—— 封装守护进程动态接口
# =====================================================================

@mcp.tool()
def post_hook(config: dict | str) -> dict:
    """下发原始 hook 配置（M3 native / M5 Java）。
    M5 Java Tracer 已支持运行中完整配置 reconcile；restart:false 时可 live add/remove/replace。
    M3 native 仍按原有进程启动/restart 语义。
    """
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except Exception as e:
            return {
                "ok": False,
                "error": f"Invalid argument: 'config' is a string but failed to parse as JSON: {e}"
            }
    if not isinstance(config, dict):
        return {
            "ok": False,
            "error": f"Invalid argument: 'config' must be a JSON object (dict), got {type(config).__name__} ({repr(config)})"
        }
    return client.post_json("/hook", config)



@mcp.tool()
def list_hooks() -> dict:
    """列出当前磁盘上的期望 hook 配置。"""
    return client.get_json("/hooks")


@mcp.tool()
def runtime_hook_status(package: str = "") -> dict:
    """查看运行中 M5 Runtime 的真实状态。

    与 list_hooks 不同，这里返回目标进程当前实际 installed / pending Java/Runtime target、
    HookRegistry live reconcile / Runtime Command 能力、进程/pid、动态 ClassLoader/watcher，以及
    Runtime State、Event Bus、Context/Lifecycle Runtime 的真实状态。
    context_runtime 会报告 Application/Context/当前 Activity 可用性与 Activity 状态；
    lifecycle_runtime 会报告 attach watcher、ActivityLifecycleCallbacks 和生命周期事件计数。
    pending_hooks 会显示等待类名、重试次数和最后错误；context_runtime 会显示当前
    Application/Context/Activity 与 activity_state，lifecycle_runtime 会显示 callbacks/events；
    package 为空时列出全部连接进程。
    """
    params = None
    if package:
        _validate_package_name(package)
        params = {"package": package}
    return client.get_json("/runtime_status", params=params)


def _runtime_command(
    package: str,
    op: str,
    *,
    process: str = "",
    timeout_ms: int = 3000,
    **payload: Any,
) -> dict:
    _validate_package_name(package)
    body: dict[str, Any] = {
        "package": package,
        "timeout_ms": max(200, min(int(timeout_ms), 10000)),
        "command": {
            "op": op,
            **payload,
        },
    }
    if process:
        body["process"] = process
    return client.post_json("/runtime_command", body)


@mcp.tool()
def runtime_state_get(
    package: str,
    key: str,
    scope: str = "process",
    hook_id: str = "",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """直接读取在线 M5 Runtime State，不创建临时 Hook。

    scope 支持 process/package/hook；hook scope 需传 hook_id。
    多进程 App 未传 process 时会分别返回每个在线 Runtime 的结果。
    """
    return _runtime_command(
        package,
        "state_get",
        process=process,
        timeout_ms=timeout_ms,
        scope=scope,
        key=key,
        hook_id=hook_id,
    )


@mcp.tool()
def runtime_state_set(
    package: str,
    key: str,
    value: Any,
    scope: str = "process",
    hook_id: str = "",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """直接写入在线 M5 Runtime State；支持 JSON 标量、对象和数组。"""
    return _runtime_command(
        package,
        "state_set",
        process=process,
        timeout_ms=timeout_ms,
        scope=scope,
        key=key,
        value=value,
        hook_id=hook_id,
    )


@mcp.tool()
def runtime_state_remove(
    package: str,
    key: str,
    scope: str = "process",
    hook_id: str = "",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """删除在线 M5 Runtime State 的一个 key，并返回旧值。"""
    return _runtime_command(
        package,
        "state_remove",
        process=process,
        timeout_ms=timeout_ms,
        scope=scope,
        key=key,
        hook_id=hook_id,
    )


@mcp.tool()
def runtime_state_increment(
    package: str,
    key: str,
    delta: float = 1.0,
    scope: str = "process",
    hook_id: str = "",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """原子增加在线 Runtime State 数值；不存在时从 0 开始。"""
    return _runtime_command(
        package,
        "state_increment",
        process=process,
        timeout_ms=timeout_ms,
        scope=scope,
        key=key,
        delta=float(delta),
        hook_id=hook_id,
    )


@mcp.tool()
def runtime_state_append(
    package: str,
    key: str,
    value: Any,
    scope: str = "process",
    hook_id: str = "",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """向在线 Runtime State 列表追加一个 JSON 值。"""
    return _runtime_command(
        package,
        "state_append",
        process=process,
        timeout_ms=timeout_ms,
        scope=scope,
        key=key,
        value=value,
        hook_id=hook_id,
    )


@mcp.tool()
def runtime_state_clear(
    package: str,
    scope: str = "process",
    hook_id: str = "",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """清空在线 Runtime 的一个 State scope；hook scope 需指定 hook_id。"""
    return _runtime_command(
        package,
        "state_clear",
        process=process,
        timeout_ms=timeout_ms,
        scope=scope,
        hook_id=hook_id,
    )


@mcp.tool()
def runtime_event_emit(
    package: str,
    name: str,
    payload: Optional[dict[str, Any]] = None,
    source_hook: str = "__remote__",
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """从 PC 直接向在线 M5 Runtime EventBus 发事件。

    payload 会作为真实结构化对象进入 event.*；现有 on_event/on_lifecycle 订阅之外的
    自定义监听器可立即同步响应并修改 Runtime State。
    """
    return _runtime_command(
        package,
        "event_emit",
        process=process,
        timeout_ms=timeout_ms,
        name=name,
        payload=payload or {},
        source_hook=source_hook,
    )


@mcp.tool()
def runtime_context_status(
    package: str,
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """实时读取目标进程当前 Application/Context/Activity/Lifecycle 状态。"""
    return _runtime_command(
        package,
        "context_status",
        process=process,
        timeout_ms=timeout_ms,
    )


@mcp.tool()
def runtime_activity_action(
    package: str,
    actions: list[dict[str, Any]],
    process: str = "",
    timeout_ms: int = 3000,
) -> dict:
    """在当前 Activity 上直接执行现有 Action Pipeline，不创建 Java Hook。

    actions 示例：[{"action":"call_method","target":"activity","method":"finish"}]。
    也可读写 state、emit_event、调用其它对象；当前没有 Activity 时会明确返回错误。
    """
    if not isinstance(actions, list) or not all(
        isinstance(item, dict) for item in actions
    ):
        return {
            "ok": False,
            "error": "actions 必须是 JSON object 列表",
        }
    return _runtime_command(
        package,
        "activity_action",
        process=process,
        timeout_ms=timeout_ms,
        actions=actions,
    )


def _normalize_runtime_program_manifest(manifest: dict | str) -> dict:
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except Exception as exc:
            raise ReconError(
                f"Runtime Program manifest JSON 解析失败: {exc}"
            ) from exc
    if not isinstance(manifest, dict):
        raise ReconError("Runtime Program manifest 必须是 JSON object")
    return manifest


def _runtime_program_write(
    package: str,
    manifest: dict | str,
    *,
    mode: str,
    enable: Optional[bool],
    restart: bool,
    timeout_ms: int,
    expected_revision: int,
) -> dict:
    _validate_package_name(package)
    body: dict[str, Any] = {
        "package": package,
        "manifest": _normalize_runtime_program_manifest(manifest),
        "mode": mode,
        "restart": bool(restart),
        "timeout_ms": max(200, min(int(timeout_ms), 10000)),
    }
    if enable is not None:
        body["enable"] = bool(enable)
    if int(expected_revision) > 0:
        body["expected_revision"] = int(expected_revision)
    return client.post_json("/runtime_program/install", body)


@mcp.tool()
def runtime_program_install(
    package: str,
    manifest: dict | str,
    enable: bool = True,
    restart: bool = False,
    timeout_ms: int = 3000,
) -> dict:
    """安装一个命名 Runtime Program。

    manifest 至少包含 id；可包含 name/version/description、targets、state_init、state_cleanup。
    target id 会被命名空间化为 rp:<program>:<local_id>，避免不同 Program 冲突。
    """
    return _runtime_program_write(
        package,
        manifest,
        mode="install",
        enable=enable,
        restart=restart,
        timeout_ms=timeout_ms,
        expected_revision=0,
    )


@mcp.tool()
def runtime_program_replace(
    package: str,
    manifest: dict | str,
    enable: Optional[bool] = None,
    expected_revision: int = 0,
    restart: bool = False,
    timeout_ms: int = 3000,
) -> dict:
    """替换已安装 Runtime Program，并把旧版本压入最多 5 层 rollback 历史。

    expected_revision>0 时启用乐观并发检查，避免覆盖另一端刚更新的版本。
    enable=None 时沿用 Program 当前启用状态。
    """
    return _runtime_program_write(
        package,
        manifest,
        mode="replace",
        enable=enable,
        restart=restart,
        timeout_ms=timeout_ms,
        expected_revision=expected_revision,
    )


def _runtime_program_toggle(
    package: str,
    program_id: str,
    *,
    enabled: bool,
    restart: bool,
    timeout_ms: int,
) -> dict:
    _validate_package_name(package)
    body = {
        "package": package,
        "id": program_id,
        "restart": bool(restart),
        "timeout_ms": max(200, min(int(timeout_ms), 10000)),
    }
    endpoint = (
        "/runtime_program/enable"
        if enabled
        else "/runtime_program/disable"
    )
    return client.post_json(endpoint, body)


@mcp.tool()
def runtime_program_enable(
    package: str,
    program_id: str,
    restart: bool = False,
    timeout_ms: int = 3000,
) -> dict:
    """启用已安装 Runtime Program，并 live reconcile + 应用 state_init。"""
    return _runtime_program_toggle(
        package,
        program_id,
        enabled=True,
        restart=restart,
        timeout_ms=timeout_ms,
    )


@mcp.tool()
def runtime_program_disable(
    package: str,
    program_id: str,
    restart: bool = False,
    timeout_ms: int = 3000,
) -> dict:
    """禁用 Runtime Program；只移除该 Program 的 targets，并执行 state_cleanup。"""
    return _runtime_program_toggle(
        package,
        program_id,
        enabled=False,
        restart=restart,
        timeout_ms=timeout_ms,
    )


@mcp.tool()
def runtime_program_rollback(
    package: str,
    program_id: str,
    restart: bool = False,
    timeout_ms: int = 3000,
) -> dict:
    """回滚 Runtime Program 到上一份 manifest；revision 继续单调递增。"""
    _validate_package_name(package)
    return client.post_json(
        "/runtime_program/rollback",
        {
            "package": package,
            "id": program_id,
            "restart": bool(restart),
            "timeout_ms": max(200, min(int(timeout_ms), 10000)),
        },
    )


@mcp.tool()
def runtime_program_status(
    package: str,
    program_id: str = "",
) -> dict:
    """查看一个包已持久化的 Runtime Program、版本、启用状态和 rollback 深度。"""
    _validate_package_name(package)
    params = {"package": package}
    if program_id:
        params["id"] = program_id
    return client.get_json("/runtime_programs", params=params)


@mcp.tool()
def unhook(package: str, hook_id: str = "") -> dict:
    """移除某包 hook；运行中的 M5 Tracer 会立即 live unhook。

    不给 hook_id 则清空该包全部期望 Hook；给了则只移除该 id。
    对支持 HookRegistry reconcile 的运行进程会立即调用 LSPosed Unhook，无需 force-stop。
    """
    _validate_package_name(package)
    body = {"package": package}
    if hook_id:
        body["id"] = hook_id
    return client.post_json("/unhook", body)



@mcp.tool()
def collect_events(seconds: float = 10.0, max_events: int = 200,
                   until_first_hit: bool = False, until_n_events: int = 0,
                   fold_stack: bool = True,
                   include_recent: bool = False, since_seq: int = 0,
                   quiet_ms: int = 0) -> dict:
    """连 hook 事件流(SSE)收集命中事件（参数/返回值/调用栈/dump 通知）。

    先 post_hook 下发配置并启动/重启目标，再调用本工具采集。

    - seconds: 采集窗口上限（兜底）。
    - until_first_hit=True: **命中即返回**，不空等满窗口（消除“掐点说话”，见 P0-1）；
      until_n_events=N: 收满 N 条命中即返回。二者任一达标即刻返回（+短暂收拢同批事件）。
    - include_recent=True: **事后采集**——先从守护进程环形缓冲补捞历史命中（P0-1），命中即便
      发生在本次采集开始之前也能拿到，并可立刻满足早返回；since_seq 只取该游标之后的增量。
    - fold_stack=True: 折叠调用栈顶部的 hook 框架帧，直接看到真实 caller（raw 传 False）。
    """
    evts = client.collect_sse(seconds=seconds, max_events=max_events,
                              until_first_hit=until_first_hit, until_n_events=until_n_events,
                              fold_stack=fold_stack, include_recent=include_recent,
                              since_seq=since_seq, quiet_ms=quiet_ms)
    return {"count": len(evts), "seconds": seconds,
            "early_return": bool(until_first_hit or until_n_events), "events": evts}


# =====================================================================
# 场景捕获 + 差分（P2）—— 把"A 与 B 行为为何不同"做成一等公民
# =====================================================================

_SCEN_DIR = settings.workdir / "scenarios"


def _scenario_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)[:64] or "scenario"
    _SCEN_DIR.mkdir(parents=True, exist_ok=True)
    return _SCEN_DIR / f"{safe}.json"


def _sig(e: Any) -> Optional[str]:
    """方法签名（用于分组/比对）：优先 hook_id（稳定，一目标一 id），否则 class.method。"""
    if not isinstance(e, dict):
        return None
    return e.get("hook_id") or f"{e.get('class', '?')}.{e.get('method', '?')}"


def _display(e: Any) -> str:
    return f"{e.get('class', '?')}.{e.get('method', '?')}" if isinstance(e, dict) else "?"


def _fp(e: Any) -> str:
    """事件的"值指纹"：拼参数/返回值/路径/字段的值，用于判断两场景同一方法参数是否不同。"""
    if not isinstance(e, dict):
        return ""
    parts = []
    for a in (e.get("args") or []):
        parts.append(f"a{a.get('index')}={a.get('value')}")
    if "ret" in e:
        parts.append(f"ret={e.get('ret')}")
    for p in (e.get("paths") or []):
        parts.append(f"{p.get('path')}={p.get('value')}")
    for f in (e.get("fields") or []):
        parts.append(f"{f.get('name')}={f.get('value')}")
    return " | ".join(parts)


@mcp.tool()
def capture_scenario(name: str, seconds: float = 20.0, quiet_ms: int = 1500,
                     max_events: int = 500, fold_stack: bool = True) -> dict:
    """记录一个「场景」的命中时间线，存盘供 diff_scenarios 比对（P2）。

    前提：先用 post_hook / trace_java arm 好一组（通常较宽的）hook，目标进程已带这些 hook 运行。
    调用本工具后**在窗口内做一次目标操作**（如「查看X」）；抓完这一波（连续 quiet_ms 无新事件即停）
    后存盘到 work/scenarios/<name>.json。

    典型流程：arm 宽 trace → capture_scenario("A") 做操作A → capture_scenario("B") 做操作B
              → diff_scenarios("A","B") 直接看出两者方法/参数差异。
    - quiet_ms: 命中后静默这么久即认为本波结束返回（0=不早停，跑满 seconds）。
    """
    cursor = client.get_recent(limit=0).get("latest_seq", 0)
    evts = client.collect_sse(seconds=seconds, max_events=max_events, fold_stack=fold_stack,
                              include_recent=True, since_seq=cursor, quiet_ms=quiet_ms)
    store = {"name": name, "captured_at": int(time.time() * 1000),
             "since_seq": cursor, "count": len(evts), "events": evts}
    path = _scenario_path(name)
    path.write_text(json.dumps(store, ensure_ascii=False, indent=1), encoding="utf-8")
    methods: dict[str, int] = {}
    for e in evts:
        s = _sig(e)
        if s:
            methods[s] = methods.get(s, 0) + 1
    return {"name": name, "count": len(evts), "distinct_methods": len(methods),
            "methods": methods, "saved": str(path),
            "note": ("空命中——确认已 arm hook 且窗口内确实触发了操作" if not evts else "")}


@mcp.tool()
def list_scenarios() -> dict:
    """列出已捕获的场景（work/scenarios/ 下）及各自命中数。"""
    out = []
    if _SCEN_DIR.is_dir():
        for p in sorted(_SCEN_DIR.glob("*.json")):
            try:
                s = json.loads(p.read_text(encoding="utf-8"))
                out.append({"name": s.get("name", p.stem), "count": s.get("count"),
                            "captured_at": s.get("captured_at"), "path": str(p)})
            except Exception:
                continue
    return {"count": len(out), "scenarios": out}


@mcp.tool()
def diff_scenarios(a: str, b: str) -> dict:
    """比对两个已捕获场景，给出**方法级差异**（P2）——直接回答"A 与 B 行为为何不同"。

    返回：只在 A 命中的方法 / 只在 B 命中的方法 / 两者都命中但**参数值不同**的方法。
    命中最常见的一类逆向：如「查看X」跳转而「打开X」不跳、App 对话渲染答案卡而悬浮窗不渲染。
    """
    pa, pb = _scenario_path(a), _scenario_path(b)
    if not pa.exists():
        raise ReconError(f"场景 {a} 不存在（先 capture_scenario('{a}')）")
    if not pb.exists():
        raise ReconError(f"场景 {b} 不存在（先 capture_scenario('{b}')）")
    sa = json.loads(pa.read_text(encoding="utf-8"))
    sb = json.loads(pb.read_text(encoding="utf-8"))

    def index(scn: dict) -> dict:
        d: dict[str, dict] = {}
        for e in scn.get("events", []):
            s = _sig(e)
            if not s:
                continue
            slot = d.setdefault(s, {"display": _display(e), "count": 0, "fps": set()})
            slot["count"] += 1
            fp = _fp(e)
            if fp:
                slot["fps"].add(fp)
        return d

    ia, ib = index(sa), index(sb)
    only_a = [{"method": ia[s]["display"], "sig": s, "hits": ia[s]["count"]}
              for s in ia if s not in ib]
    only_b = [{"method": ib[s]["display"], "sig": s, "hits": ib[s]["count"]}
              for s in ib if s not in ia]
    both, differing = [], []
    for s in ia:
        if s not in ib:
            continue
        both.append({"method": ia[s]["display"], "sig": s,
                     "a_hits": ia[s]["count"], "b_hits": ib[s]["count"]})
        if ia[s]["fps"] != ib[s]["fps"]:
            av = sorted(ia[s]["fps"] - ib[s]["fps"])[:8]
            bv = sorted(ib[s]["fps"] - ia[s]["fps"])[:8]
            if av or bv:
                differing.append({"method": ia[s]["display"], "sig": s,
                                  "only_in_a_values": av, "only_in_b_values": bv})
    return {"a": a, "b": b, "a_count": sa.get("count"), "b_count": sb.get("count"),
            "only_in_a": sorted(only_a, key=lambda x: -x["hits"]),
            "only_in_b": sorted(only_b, key=lambda x: -x["hits"]),
            "in_both": both, "differing_args": differing,
            "summary": (f"{len(only_a)} 个方法只在 A 命中、{len(only_b)} 个只在 B 命中、"
                        f"{len(differing)} 个两者都命中但参数不同")}


@mcp.tool()
def recent_events(limit: int = 50, since_seq: int = 0) -> dict:
    """取守护进程环形缓冲里**最近的命中事件**（事后采集，P0-1）——无需正连着 SSE。

    典型用法：post_hook 下发后先记下游标（recent_events(limit=0) 的 latest_seq），触发目标行为，
    再 recent_events(since_seq=<游标>) 补捞这期间的所有命中；或忘了开采集时直接捞最近若干条。
    返回 {latest_seq, count, events}；latest_seq 可作下次 since_seq 只取增量。
    """
    data = client.get_recent(limit=limit, since_seq=since_seq)
    evts = [_fold_stack(e) for e in data.get("events", [])]
    return {"latest_seq": data.get("latest_seq"), "count": len(evts), "events": evts}


@mcp.tool()
def trace_java(package: str, class_name: str, method: str,
               params: Optional[list] = None,
               args_render: str = "tostring",
               capture_args: Optional[list] = None,
               fields: Optional[list] = None,
               paths: Optional[list] = None,
               this: str = "class",
               ret: bool = True,
               when: str = "after",
               stack: bool = False,
               hook_id: str = "",
               debug: bool = False,
               restart: bool = True,
               seconds: float = 12.0,
               max_events: int = 200,
               until_first_hit: bool = False,
               until_n_events: int = 0,
               fold_stack: bool = True,
               include_recent: bool = False,
               since_seq: int = 0,
               hot: bool = False) -> dict:
    """一步下发一个 Java 方法 trace 并采集命中（M5）。

    需设备已装 **ReconBridge Tracer** LSPosed 模块并在 LSPosed 里启用 + 勾选目标 App 作用域。
    在目标进程用 XposedBridge hook `class_name.method`，实时回传 this/参数/返回值/字段/调用栈，
    走与 M3 相同的 socket→SSE 链路。协议见 m5/JAVA_HOOK_PROTOCOL.md。

    - params: 精确重载的参数类型全名列表（如 ["java.lang.String","java.lang.String"]）；
      省略=hook 所有同名重载；method="<init>" 则 hook 构造函数。
    - capture_args: 逐参数抓取 [{"index":0,"render":"tostring","max":2000}]；省略=按 tostring 抓全部参数。
    - fields: 反射读取的（私有）字段 [{"target":"this","name":"Z3","render":"tostring"}]。
    - paths: **嵌套字段路径捕获**（P0-3），直接拿深埋在 payload 对象里的值，不靠 toString 撞运气：
      [{"path":"args[1].payload.load_url","render":"tostring","max":2000}]。
      路径语法 args[N]/this/ret 起头，`.name` 逐层（反射字段→getter→Map key），`[n]` 索引数组/List；
      裸字段名等价 this.<name>。解析不到的段返回 {"unresolved":true}。
    - this: this 渲染 class|tostring|none；when: before|after|both。
    - render: tostring|class|json|**deep**（deep=反射把对象图深度序列化成 JSON，带深度/环/节点预算防爆）。

    注意：模块在进程启动时读配置，故对已运行的目标需 restart=True（force-stop 触发重载），
    之后在 seconds 窗口内手动触发目标行为（如唤起小爱问一句）即可收到命中。

    - until_first_hit=True / until_n_events=N: **命中即返回**，不空等满窗口（P0-1）；
      对“重启目标→手动触发一次→拿到命中”的迭代尤其省时，无需再和窗口掐点。
    - fold_stack=True: 折叠调用栈顶部 hook 框架帧，直接看到真实 caller。
    - hot=True: **免重启热加**（P0-2）——若目标进程在跑，直接往运行中的进程增量追加这个 hook
      （restart 强制置 False + mode:append），**不 force-stop、不用重新唤醒/重说**。返回的 posted.note /
      hot_injected 会告诉你热注入了几个进程；为 0 说明目标没在跑（配置会在下次启动生效）。
      需设备装的是**支持热加的 tracer**（新版 APK）；旧版或 native 目标不响应热加，仍需 restart。
    """
    _validate_package_name(package)
    capture: dict[str, Any] = {"this": this, "when": when, "stack": stack}

    if capture_args is not None:
        capture["args"] = capture_args
    else:
        capture["all_args"] = True
    if ret:
        capture["ret"] = {"capture": True, "render": args_render}
    if fields:
        capture["fields"] = fields
    if paths:
        capture["paths"] = paths
    target: dict[str, Any] = {
        "kind": "java",
        "id": hook_id or f"{class_name.rsplit('.', 1)[-1]}_{method}",
        "class": class_name,
        "method": method,
        "capture": capture,
    }
    if params is not None:
        target["params"] = params
    config: dict[str, Any] = {"package": package, "restart": restart, "debug": debug,
                              "targets": [target]}
    if hot:
        config["restart"] = False   # 热加：不 force-stop
        config["mode"] = "append"   # 增量合并进现有配置
    posted = client.post_json("/hook", config)
    evts = client.collect_sse(seconds=seconds, max_events=max_events,
                              until_first_hit=until_first_hit, until_n_events=until_n_events,
                              fold_stack=fold_stack, include_recent=include_recent,
                              since_seq=since_seq)
    return {"posted": posted, "count": len(evts), "seconds": seconds,
            "early_return": bool(until_first_hit or until_n_events), "events": evts}


@mcp.tool()
def patch_java(package: str, class_name: str, method: str,
               params: Optional[list] = None,
               replace_args: Optional[list] = None,
               replace_return: Optional[dict] = None,
               mutate_return: Optional[list] = None,
               condition: Optional[dict] = None,
               before_actions: Optional[list] = None,
               after_actions: Optional[list] = None,
               action: Optional[dict] = None,
               skip_original: bool = False,
               trace: bool = True,
               capture_args: Optional[list] = None,
               this: str = "class",
               when: str = "after",
               hook_id: str = "",
               debug: bool = False,
               restart: bool = True,
               seconds: float = 0.0,
               max_events: int = 100,
               hot: bool = False) -> dict:
    """实时篡改与高级动作流水线（M5 v2）：改参数 / 改返回值 / 字段深层路径篡改 / 条件执行 / 副作用动作。

    需设备已装 **ReconBridge Tracer** LSPosed 模块并启用+勾选目标作用域。协议见 m5/JAVA_HOOK_PROTOCOL.md。

    - mutate_return: **返回值深层字段/Map key 篡改**，[{"path":"body.type","value":"normal"}]。
    - condition: **条件执行**，{"path":"ret.type","op":"eq","value":"revokemsg"} 或 {"script":"$ret != null"}。
    - before_actions / after_actions: **副作用动作流水线**，包含 call_method, set_field, eval_js, exec_shell, mutate 等。
    - replace_args: 进入原方法前覆盖参数，[{"index":1,"value":"新内容","type":"string"}]。
    - replace_return: 覆盖返回值，{"value":0,"type":"int"}。
    - skip_original: True 则不执行原方法，直接返回 replace_return。
    - hot=True: **免重启 live reconcile**——按 id 合并期望配置并下发到运行中的 M5；新 id 安装、同 id 改配置实时 replace（restart 强制置 False）。
    - 模板变量：value / args 字段支持 `${args[0]}`、`${ret.type}`、`${$v1}` 语法引用运行时数据。
    """
    _validate_package_name(package)
    target: dict[str, Any] = {

        "kind": "java",
        "id": hook_id or f"{class_name.rsplit('.', 1)[-1]}_{method}",
        "class": class_name,
        "method": method,
    }
    if params is not None:
        target["params"] = params
    cap: dict[str, Any] = {"this": this, "when": (when if trace else "none")}
    if capture_args is not None:
        cap["args"] = capture_args
    elif trace:
        cap["all_args"] = True
    if trace:
        cap["ret"] = {"capture": True, "render": "tostring"}
    target["capture"] = cap
    act: dict[str, Any] = action.copy() if action is not None else {}
    if replace_args is not None:
        act["replace_args"] = replace_args
    if replace_return is not None:
        act["replace_return"] = replace_return
    if mutate_return is not None:
        act["mutate_return"] = mutate_return
    if condition is not None:
        act["condition"] = condition
    if before_actions is not None:
        act["before_actions"] = before_actions
    if after_actions is not None:
        act["after_actions"] = after_actions
    if skip_original:
        act["skip_original"] = True
    if act:
        target["action"] = act
    config: dict[str, Any] = {"package": package, "restart": restart, "debug": debug, "targets": [target]}
    if hot:
        config["restart"] = False
        config["mode"] = "append"
    posted = client.post_json("/hook", config)
    result: dict[str, Any] = {"posted": posted}
    if seconds and seconds > 0:
        evts = client.collect_sse(seconds=seconds, max_events=max_events)
        result.update({"count": len(evts), "seconds": seconds, "events": evts})
    return result


@mcp.tool()
def dump_dex(package: str, symbol: str = "", offset: str = "", base_arg: int = 0,
             size_arg: int = 1, lib: str = "libart.so", restart: bool = True) -> dict:
    """通用内存 dex dump（M4）：hook dex 加载入口，把内存中已解密的 dex 回传落盘。

    symbol/offset 指定入口（用 ghidra_analyze 分析 /system/lib64/libart.so 定位）；
    base_arg/size_arg 为 dex 基址/长度所在参数下标。命中后用 list_dumps / read_remote_file 取回。
    """
    _validate_package_name(package)
    body: dict[str, Any] = {"package": package, "lib": lib, "base_arg": base_arg,
                            "size_arg": size_arg, "restart": restart}

    if symbol:
        body["symbol"] = symbol
    if offset:
        body["offset"] = offset
    return client.post_json("/dump_dex", body)


@mcp.tool()
def list_dumps() -> dict:
    """列出已落盘的内存 dump（用 read_remote_file 或 pull 取回）。"""
    return client.get_json("/dumps")


@mcp.tool()
def list_artifacts(package_name: str = "") -> dict:
    """列出 PC 工作目录里某包（或全部包）已产出的物件：已拉的 apk、已拉的 native so、
    已反编译的 jadx 目录、已反编译的 Hermes 目录。免去“到底拉过/反编译过没有”的翻找（P1-6）。

    package_name 为空则枚举工作目录下所有包。路径可直接喂给 decompile_apk / ghidra_analyze。
    """
    base = settings.workdir

    def scan(pkg_dir: Path) -> dict:
        apk_dir = pkg_dir / "apk"
        libs_dir = pkg_dir / "libs"
        apks = sorted(str(p) for p in apk_dir.glob("*.apk")) if apk_dir.is_dir() else []
        libs = sorted(str(p) for p in libs_dir.glob("*.so")) if libs_dir.is_dir() else []
        # jadx 输出默认在 apk 同级的 "<stem>-jadx/"；Hermes 在 "<stem>-hermes/"
        jadx = sorted(str(p) for p in pkg_dir.rglob("*-jadx") if p.is_dir())
        hermes = sorted(str(p) for p in pkg_dir.rglob("*-hermes") if p.is_dir())
        return {
            "package": pkg_dir.name,
            "apks": apks,
            "libs": libs,
            "jadx_dirs": jadx,
            "hermes_dirs": hermes,
            "has_apk": bool(apks),
            "has_decompiled": bool(jadx),
        }

    if package_name:
        _validate_package_name(package_name)
        pkg_dir = (base / package_name).resolve()
        try:
            pkg_dir.relative_to(base.resolve())
        except ValueError:
            raise ReconError(f"Package path escapes workdir: {package_name}")
        if not pkg_dir.is_dir():

            return {"package": package_name, "exists": False,
                    "note": "工作目录下无该包产出物；用 pull_apk / pull_libs 先拉取"}
        return {"exists": True, **scan(pkg_dir)}

    pkgs = []
    if base.is_dir():
        for d in sorted(base.iterdir()):
            if not d.is_dir() or d.name in ("files",):
                continue
            info = scan(d)
            if info["apks"] or info["libs"] or info["jadx_dirs"] or info["hermes_dirs"]:
                pkgs.append(info)
    return {"workdir": str(base), "count": len(pkgs), "packages": pkgs}


@mcp.tool()
def toolchain_status() -> dict:
    """检查 PC 本地反编译工具链（jadx / DexKit / Ghidra / Hermes）是否就绪及其路径。"""
    return external.toolchain_status()


def main() -> None:
    # 冻结成 exe 后没有 `-m reconbridge_mcp` 入口，故把这些也做进同一个可执行文件：
    #   reconbridge-mcp.exe --register   [--transport adb|wifi] [--print-only]
    #   reconbridge-mcp.exe --unregister [--print-only]
    #   reconbridge-mcp.exe --serve      [--port N] [--host H] [--no-open]   本地 Web 控制台
    # 其余情况照常起 stdio MCP server。
    import sys
    args = sys.argv[1:]
    if "--dex-worker" in args:
        from . import dex_worker
        idx = args.index("--dex-worker")
        raise SystemExit(dex_worker.main(args[idx + 1:]))
    if "--serve" in args:
        from . import webconsole
        raise SystemExit(webconsole.main(args))
    if "--register" in args or "--unregister" in args:
        from . import register
        raise SystemExit(register.main(args))
    mcp.run()


if __name__ == "__main__":
    main()
