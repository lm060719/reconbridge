"""Diagnostics and bounded, auditable event capture. No implicit target hooks."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Any

from . import external, investigation
from .client import client
from .settings import settings


def validate_package(package: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*", package):
        raise ValueError("invalid package")
    return package


def safe_error(exc: Exception) -> str:
    message = str(exc)
    for token in (settings.token, getattr(client, "_token", "")):
        if token:
            message = message.replace(token, "[redacted]")
    return message[:600]


def event_integrity(data: dict, since_seq: int = 0, stream_id: str = "") -> dict:
    supported = all(k in data for k in ("stream_id", "truncated", "earliest_seq", "cursor_reset"))
    reset = bool(data.get("cursor_reset")) or bool(stream_id and data.get("stream_id") != stream_id)
    reset |= int(data.get("latest_seq", 0)) < since_seq
    gap = bool(data.get("truncated")) or reset
    return {"supported": supported, "complete": not gap if supported else None,
            "cursor_reset": reset, "truncated": gap,
            "lost_before_cursor": data.get("lost_before_cursor"),
            "limit_truncated": data.get("limit_truncated"),
            "scope": "daemon_ingress", "upstream_loss": "unknown"}


def event_stream_status(since_seq: int = 0, stream_id: str = "") -> dict:
    """Check daemon buffer loss/restart and subscriber drops; upstream loss remains unknown.

    Pass BOTH latest_seq and stream_id from a previous snapshot to detect daemon restarts.
    Older daemons return integrity.supported=false, never a claim of complete capture.
    """
    if since_seq < 0:
        raise ValueError("since_seq must be nonnegative")
    data = client.get_recent(limit=0, since_seq=since_seq, stream_id=stream_id)
    return {**data, "integrity": event_integrity(data, since_seq, stream_id)}


def diagnose_target(package: str) -> dict:
    """Diagnose connectivity, installed versions, desired/actual Java hooks and native observer.

    Uses normal adb/wifi connection setup. Does not restart the app or install hooks.
    A missing Runtime connection does NOT prove that LSPosed scope is disabled.
    """
    validate_package(package)
    checks: list[dict[str, Any]] = []
    def add(name: str, status: str, detail: Any, hint: str = "") -> None:
        checks.append({"check": name, "status": status, "detail": detail, "hint": hint})
    tools = external.toolchain_status()
    add("local_tools", "ok" if tools.get("jadx") and tools.get("androguard") else "warning", tools,
        "本地静态工具缺失不影响已安装的动态 Hook。")
    try:
        health = client.get_json("/health")
        add("daemon", "ok" if health.get("status") == "ok" else "error", health)
    except Exception as exc:
        add("daemon", "error", safe_error(exc), "检查 adb 授权/多设备选择、root、模块启用和 wifi 地址/token。")
        return {"ok": False, "package": package, "checks": checks}
    try:
        packages = client.get_json("/packages").get("packages", [])
        target = next((p for p in packages if p.get("package") == package), None)
        tracer = next((p for p in packages if p.get("package") == "com.reconbridge.tracer"), None)
        add("target_installed", "ok" if target else "error", target)
        add("tracer_installed", "ok" if tracer else "warning", tracer,
            "安装版本不代表当前进程加载的版本；以 Runtime 回报为准。")
    except Exception as exc:
        add("packages", "unknown", safe_error(exc))
    try:
        desired = client.get_json("/hooks").get("hooks", [])
        desired = next((h.get("targets", []) for h in desired if h.get("package") == package), [])
        java_ids = {h["id"] for h in desired if h.get("kind") in {"java", "runtime"} and h.get("id")}
        add("desired_hooks", "ok", {"java_ids": sorted(java_ids), "total": len(desired)})
    except Exception as exc:
        java_ids = set()
        add("desired_hooks", "unknown", safe_error(exc))
    try:
        rows = client.get_json("/runtime_status", {"package": package}).get("processes", [])
        java_rows = [r for r in rows if r.get("live_reconcile") or r.get("runtime_command")]
        add("java_runtime", "ok" if java_rows else "warning", {"connected_processes": len(java_rows)},
            "无连接可能是进程未启动、尚无 Hook 配置、Tracer 未启用或作用域未勾选；不能仅凭无连接确定原因。")
        for row in rows:
            runtime = row.get("runtime") or {}
            if not (row.get("live_reconcile") or row.get("runtime_command")):
                failed = [h for h in runtime.get("jni_observers", []) if h.get("status") != "installed"]
                add("native_runtime", "warning" if failed else ("ok" if runtime else "unknown"), row)
                continue
            installed = {h.get("id") for h in runtime.get("hooks", [])}
            pending = runtime.get("pending_hooks", [])
            missing = sorted(java_ids - installed)
            add("java_hooks", "warning" if missing or pending else "ok",
                {"process": row.get("process"), "pid": runtime.get("pid"),
                 "tracer_version": runtime.get("tracer_version"), "installed": sorted(installed - {None}),
                 "missing": missing, "pending": pending},
                "pending_class 需等待对应 ClassLoader；missing 请核对类名、签名及 Runtime 错误。")
    except Exception as exc:
        add("runtime", "unknown", safe_error(exc))
    try:
        stream = event_stream_status()
        add("event_stream", "ok" if stream["integrity"]["supported"] else "warning", stream,
            "检查区间完整性时必须使用开始时的 stream_id 和 latest_seq。")
    except Exception as exc:
        add("event_stream", "unknown", safe_error(exc))
    return {"ok": all(c["status"] == "ok" for c in checks), "package": package, "checks": checks}


def capture_event_window(session_id: str, seconds: float = 10, max_events: int = 10000) -> dict:
    """Poll events into a session JSONL file (up to 60s). Report every gap/restart/error.

    Completeness covers only events received by the daemon, not upstream hook delivery.
    No hook is installed and no operation is replayed. Target package and subprocesses only.
    """
    if not 0 <= seconds <= 60 or not 1 <= max_events <= 100000:
        raise ValueError("seconds must be 0..60; max_events must be 1..100000")
    state = investigation.load(session_id, refresh=True)
    folder = investigation._session_path(session_id).with_suffix(".events")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (secrets.token_hex(8) + ".jsonl")
    start = client.get_recent(limit=0)
    cursor, epoch = start["latest_seq"], start.get("stream_id", "")
    report: dict[str, Any] = {"session_id": session_id, "package": state["package"],
        "path": str(path), "start_seq": cursor, "stream_id": epoch, "count": 0,
        "complete": True if epoch else None, "scope": "daemon_ingress", "upstream_loss": "unknown", "issues": []}
    deadline = time.monotonic() + seconds
    with path.open("x", encoding="utf-8") as output:
        while True:
            try:
                data = client.get_recent(limit=10000, since_seq=cursor, stream_id=epoch)
                integrity = event_integrity(data, cursor, epoch)
                if integrity["complete"] is not True:
                    report["complete"] = False if integrity["complete"] is False else None
                    report["issues"].append(integrity)
                for event in data.get("events", []):
                    if not isinstance(event, dict) or event.get("package", "").split(":", 1)[0] != state["package"]:
                        continue
                    if report["count"] >= max_events:
                        report["complete"] = False
                        report["issues"].append({"reason": "max_events"})
                        break
                    output.write(json.dumps(event, ensure_ascii=False) + "\n")
                    report["count"] += 1
                cursor = data["latest_seq"]
                output.flush()
                if report["issues"] or time.monotonic() >= deadline:
                    break
                time.sleep(min(.1, max(0, deadline - time.monotonic())))
            except Exception as exc:
                report["complete"] = False
                report["issues"].append({"reason": "transport_error", "error": safe_error(exc)})
                break
    report["end_seq"] = cursor
    report["ok"] = report["complete"] is True
    path.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def register(mcp) -> None:
    for tool in (diagnose_target, event_stream_status, capture_event_window):
        mcp.tool()(tool)
