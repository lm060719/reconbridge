"""高层分析会话：把包名、APK、JADX 目录和搜索状态持久化。

目标是让 AI/用户从“反复拼原子工具参数”切换到“围绕一个目标持续调查”：
open_target -> search_target -> trace/inspect（后续继续扩展）。
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from .settings import settings

_SESSION_RE = re.compile(r"^[a-f0-9]{12}$")
_ROOT = settings.workdir / ".investigations"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _session_path(session_id: str) -> Path:
    if not _SESSION_RE.fullmatch(session_id):
        raise ValueError("invalid investigation session id")
    return _ROOT / f"{session_id}.json"


def _scan_artifacts(package: str) -> dict[str, Any]:
    pkg_dir = (settings.workdir / package).resolve()
    workdir = settings.workdir.resolve()
    pkg_dir.relative_to(workdir)

    apk_dir = pkg_dir / "apk"
    libs_dir = pkg_dir / "libs"
    apks = sorted(str(p.resolve()) for p in apk_dir.glob("*.apk")) if apk_dir.is_dir() else []
    libs = sorted(str(p.resolve()) for p in libs_dir.glob("*.so")) if libs_dir.is_dir() else []
    jadx_dirs = sorted(
        str(p.resolve())
        for p in pkg_dir.rglob("*-jadx")
        if p.is_dir()
    )
    hermes_dirs = sorted(
        str(p.resolve())
        for p in pkg_dir.rglob("*-hermes")
        if p.is_dir()
    )
    return {
        "package_dir": str(pkg_dir),
        "apks": apks,
        "libs": libs,
        "jadx_dirs": jadx_dirs,
        "hermes_dirs": hermes_dirs,
    }


def _choose_primary_apk(apks: list[str]) -> str:
    if not apks:
        return ""
    for path in apks:
        if Path(path).name.lower() == "base.apk":
            return path
    return max(apks, key=lambda p: Path(p).stat().st_size if Path(p).exists() else 0)


def create(package: str, note: str = "") -> dict[str, Any]:
    _ROOT.mkdir(parents=True, exist_ok=True)
    artifacts = _scan_artifacts(package)
    session_id = secrets.token_hex(6)
    now = _now_ms()
    state: dict[str, Any] = {
        "session_id": session_id,
        "package": package,
        "created_at": now,
        "updated_at": now,
        "note": note,
        "artifacts": artifacts,
        "primary_apk": _choose_primary_apk(artifacts["apks"]),
        "event_cursor": 0,
        "temporary_hooks": [],
        "discoveries": [],
    }
    save(state)
    return state


def save(state: dict[str, Any]) -> None:
    _ROOT.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = _now_ms()
    path = _session_path(str(state["session_id"]))
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load(session_id: str, refresh: bool = False) -> dict[str, Any]:
    path = _session_path(session_id)
    if not path.exists():
        raise FileNotFoundError(f"investigation session not found: {session_id}")
    state = json.loads(path.read_text(encoding="utf-8"))
    if refresh:
        artifacts = _scan_artifacts(state["package"])
        state["artifacts"] = artifacts
        state["primary_apk"] = _choose_primary_apk(artifacts["apks"])
        save(state)
    return state


def status(session_id: str) -> dict[str, Any]:
    state = load(session_id, refresh=True)
    artifacts = state["artifacts"]
    return {
        "session_id": state["session_id"],
        "package": state["package"],
        "primary_apk": state.get("primary_apk", ""),
        "apk_count": len(artifacts.get("apks", [])),
        "lib_count": len(artifacts.get("libs", [])),
        "jadx_ready": bool(artifacts.get("jadx_dirs")),
        "jadx_dirs": artifacts.get("jadx_dirs", []),
        "event_cursor": state.get("event_cursor", 0),
        "temporary_hooks": state.get("temporary_hooks", []),
        "discoveries": state.get("discoveries", [])[-20:],
        "created_at": state.get("created_at"),
        "updated_at": state.get("updated_at"),
    }


def close(session_id: str) -> dict[str, Any]:
    state = load(session_id)
    path = _session_path(session_id)
    path.unlink(missing_ok=True)
    return {
        "closed": True,
        "session_id": session_id,
        "package": state.get("package"),
        "temporary_hooks": state.get("temporary_hooks", []),
    }


def set_event_cursor(session_id: str, cursor: int) -> None:
    state = load(session_id)
    state["event_cursor"] = max(0, int(cursor))
    save(state)


def add_discovery(session_id: str, discovery: dict[str, Any]) -> None:
    state = load(session_id)
    items = state.setdefault("discoveries", [])
    items.append({"at": _now_ms(), **discovery})
    if len(items) > 200:
        del items[:-200]
    save(state)


def source_search(session_id: str, query: str, limit: int = 20) -> dict[str, Any]:
    """对已有 JADX 源码做轻量流式文本搜索，不把完整源码读入内存。"""
    state = load(session_id, refresh=True)
    query_folded = query.casefold()
    limit = max(1, min(int(limit), 100))
    matches: list[dict[str, Any]] = []

    for jadx_dir in state["artifacts"].get("jadx_dirs", []):
        root = Path(jadx_dir) / "sources"
        if not root.is_dir():
            root = Path(jadx_dir)
        for path in root.rglob("*"):
            if len(matches) >= limit:
                break
            if not path.is_file() or path.suffix.lower() not in {".java", ".kt", ".xml", ".smali"}:
                continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                with path.open("r", encoding="utf-8", errors="replace") as fp:
                    for line_no, line in enumerate(fp, 1):
                        if query_folded in line.casefold():
                            matches.append({
                                "path": str(path),
                                "line": line_no,
                                "text": line.strip()[:500],
                            })
                            if len(matches) >= limit:
                                break
            except OSError:
                continue
        if len(matches) >= limit:
            break

    return {
        "strategy": "jadx-source",
        "query": query,
        "count": len(matches),
        "results": matches,
    }
