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

from .dex_index import index_status, method_call_graph, method_relations
from . import evidence
from .settings import settings

_SESSION_RE = re.compile(r"^[a-f0-9]{12}$")
_SCENARIO_RE = re.compile(r"^[A-Za-z0-9_.\-\u4e00-\u9fff]{1,64}$")
_ROOT = settings.workdir / ".investigations"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _session_path(session_id: str) -> Path:
    if not _SESSION_RE.fullmatch(session_id):
        raise ValueError("invalid investigation session id")
    return _ROOT / f"{session_id}.json"


def _call_scenario_dir(session_id: str) -> Path:
    _session_path(session_id)
    return _ROOT / f"{session_id}.call-scenarios"


def _call_scenario_path(session_id: str, name: str) -> Path:
    if not _SCENARIO_RE.fullmatch(name):
        raise ValueError("invalid call graph scenario name")
    return _call_scenario_dir(session_id) / f"{name}.json"


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
        "evidence_graph": evidence.new_graph(),
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
    primary_apk = state.get("primary_apk", "")
    dex_index = index_status(primary_apk) if primary_apk else {"ready": False, "path": "", "bytes": 0}
    return {
        "session_id": state["session_id"],
        "package": state["package"],
        "primary_apk": primary_apk,
        "dex_index": dex_index,
        "dex_index_ready": bool(dex_index.get("ready")),
        "apk_count": len(artifacts.get("apks", [])),
        "lib_count": len(artifacts.get("libs", [])),
        "jadx_ready": bool(artifacts.get("jadx_dirs")),
        "jadx_dirs": artifacts.get("jadx_dirs", []),
        "event_cursor": state.get("event_cursor", 0),
        "temporary_hooks": state.get("temporary_hooks", []),
        "discoveries": state.get("discoveries", [])[-20:],
        "evidence_graph": evidence.summary(state.get("evidence_graph") or evidence.new_graph()),
        "call_scenario_count": len(list_call_scenarios(session_id)),
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


def add_temporary_hook(session_id: str, hook_id: str) -> None:
    state = load(session_id)
    hooks = state.setdefault("temporary_hooks", [])
    if hook_id not in hooks:
        hooks.append(hook_id)
    save(state)


def remove_temporary_hook(session_id: str, hook_id: str) -> None:
    state = load(session_id)
    hooks = state.setdefault("temporary_hooks", [])
    state["temporary_hooks"] = [item for item in hooks if item != hook_id]
    save(state)


def add_discovery(session_id: str, discovery: dict[str, Any]) -> None:
    state = load(session_id)
    items = state.setdefault("discoveries", [])
    items.append({"at": _now_ms(), **discovery})
    if len(items) > 200:
        del items[:-200]
    save(state)


def record_search_evidence(
    session_id: str,
    query: str,
    strategy: str,
    results: list[dict[str, Any]],
) -> None:
    state = load(session_id)
    graph = state.setdefault("evidence_graph", evidence.new_graph())
    evidence.record_search(graph, query, strategy, results)
    save(state)


def record_trace_evidence(
    session_id: str,
    class_name: str,
    method_name: str,
    events: list[dict[str, Any]],
) -> None:
    state = load(session_id)
    graph = state.setdefault("evidence_graph", evidence.new_graph())
    evidence.record_trace(graph, class_name, method_name, events)
    save(state)


def evidence_subgraph(
    session_id: str,
    focus: str = "",
    depth: int = 2,
    limit: int = 100,
) -> dict[str, Any]:
    state = load(session_id)
    graph = state.setdefault("evidence_graph", evidence.new_graph())
    return evidence.subgraph(graph, focus=focus, depth=depth, limit=limit)


def explain_evidence_graph(
    session_id: str,
    focus: str,
    depth: int = 3,
    limit: int = 80,
) -> dict[str, Any]:
    state = load(session_id)
    graph = state.setdefault("evidence_graph", evidence.new_graph())
    return evidence.explain(graph, focus=focus, depth=depth, limit=limit)


def _normalize_class_name(class_name: str) -> str:
    value = (class_name or "").strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    return value.replace("/", ".")


def source_method_context(
    session_id: str,
    class_name: str,
    method_name: str,
    context_lines: int = 8,
    max_chars: int = 12000,
) -> dict[str, Any]:
    """从已有 JADX 产物里定位方法声明并返回方法体附近源码。"""
    state = load(session_id, refresh=True)
    jadx_dirs = state["artifacts"].get("jadx_dirs", [])
    if not jadx_dirs:
        return {
            "available": False,
            "reason": "jadx_not_ready",
            "hint": "调用 prepare_target 生成 JADX 源码",
        }

    normalized = _normalize_class_name(class_name)
    outer = normalized.split("$", 1)[0]
    parts = outer.split(".")
    simple = parts[-1] if parts else outer
    rel = Path(*parts) if parts else Path(simple)

    candidates: list[Path] = []
    for jadx_dir in jadx_dirs:
        root = Path(jadx_dir) / "sources"
        if not root.is_dir():
            root = Path(jadx_dir)

        for suffix in (".java", ".kt"):
            direct = root / rel.with_suffix(suffix)
            if direct.is_file() and direct not in candidates:
                candidates.append(direct)

        if not candidates:
            for suffix in (".java", ".kt"):
                for path in root.rglob(simple + suffix):
                    if path.is_file():
                        candidates.append(path)
                        if len(candidates) >= 8:
                            break
                if candidates:
                    break

    if not candidates:
        return {
            "available": False,
            "reason": "source_file_not_found",
            "class": normalized,
        }

    path = candidates[0]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {
            "available": False,
            "reason": "source_read_failed",
            "error": str(exc),
            "path": str(path),
        }

    target_name = simple if method_name == "<init>" else method_name
    pattern = re.compile(rf"(?<![\w$.]){re.escape(target_name)}\s*\(")
    modifier_re = re.compile(
        r"\b(public|private|protected|static|final|synchronized|native|abstract|override|fun)\b"
    )
    best_index = -1
    best_score = -1

    for index, line in enumerate(lines):
        match = pattern.search(line)
        if not match:
            continue
        stripped = line.strip()
        score = 0
        if modifier_re.search(stripped):
            score += 5
        if "{" in stripped:
            score += 3
        prefix = stripped[: match.start()]
        if "." not in prefix:
            score += 2
        if stripped.endswith("{"):
            score += 1
        if stripped.startswith("//"):
            score -= 5
        if score > best_score:
            best_score = score
            best_index = index

    if best_index < 0:
        return {
            "available": False,
            "reason": "method_declaration_not_found",
            "path": str(path),
            "class": normalized,
            "method": method_name,
        }

    # 尝试按花括号找完整方法体；遇到反编译异常时退回固定上下文窗口。
    body_end = min(len(lines) - 1, best_index + max(20, context_lines * 4))
    depth = 0
    seen_open = False
    for index in range(best_index, min(len(lines), best_index + 220)):
        line = lines[index]
        opens = line.count("{")
        closes = line.count("}")
        if opens:
            seen_open = True
        if seen_open:
            depth += opens - closes
            if depth <= 0:
                body_end = index
                break

    start = max(0, best_index - max(2, context_lines // 2))
    end = min(len(lines) - 1, body_end + max(2, context_lines // 2))
    numbered = "\n".join(
        f"{line_no + 1:>6} | {lines[line_no]}"
        for line_no in range(start, end + 1)
    )
    truncated = len(numbered) > max_chars
    if truncated:
        numbered = numbered[:max_chars] + "\n... <源码片段已截断>"

    return {
        "available": True,
        "path": str(path),
        "class": normalized,
        "method": method_name,
        "declaration_line": best_index + 1,
        "start_line": start + 1,
        "end_line": end + 1,
        "truncated": truncated,
        "text": numbered,
    }


def method_context(
    session_id: str,
    class_name: str,
    method_name: str,
    descriptor: str = "",
    relation_limit: int = 20,
    include_source: bool = True,
) -> dict[str, Any]:
    """聚合 DEX 调用关系与 JADX 源码上下文。"""
    state = load(session_id, refresh=True)
    apk = state.get("primary_apk", "")
    relations = (
        method_relations(
            apk,
            class_name,
            method_name,
            descriptor=descriptor,
            limit=relation_limit,
        )
        if apk
        else {"ok": False, "error": "当前会话没有 APK"}
    )
    source = (
        source_method_context(session_id, class_name, method_name)
        if include_source
        else {"available": False, "reason": "disabled"}
    )
    return {
        "class": _normalize_class_name(class_name),
        "method": method_name,
        "descriptor": descriptor,
        "relations": relations,
        "source": source,
    }


def record_method_context_evidence(
    session_id: str,
    class_name: str,
    method_name: str,
    descriptor: str,
    context: dict[str, Any],
) -> None:
    state = load(session_id)
    graph = state.setdefault("evidence_graph", evidence.new_graph())
    evidence.record_method_context(
        graph,
        class_name,
        method_name,
        descriptor,
        context,
    )
    save(state)


def call_graph_context(
    session_id: str,
    class_name: str,
    method_name: str,
    descriptor: str = "",
    upstream_depth: int = 2,
    downstream_depth: int = 2,
    max_nodes: int = 120,
    max_edges: int = 300,
    max_paths: int = 20,
    expand_external: bool = False,
) -> dict[str, Any]:
    """递归展开目标方法调用图，并叠加当前会话已有 runtime 证据。"""
    state = load(session_id, refresh=True)
    apk = state.get("primary_apk", "")
    if not apk:
        return {"ok": False, "error": "当前会话没有 APK"}

    graph = method_call_graph(
        apk,
        class_name,
        method_name,
        descriptor=descriptor,
        upstream_depth=upstream_depth,
        downstream_depth=downstream_depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_paths=max_paths,
        expand_external=expand_external,
    )
    if not graph.get("ok"):
        return graph

    evidence_graph = state.setdefault("evidence_graph", evidence.new_graph())
    evidence.annotate_call_graph_runtime(evidence_graph, graph)
    evidence.record_call_graph(evidence_graph, graph)
    save(state)
    return graph


def record_runtime_path_evidence(
    session_id: str,
    path: dict[str, Any],
    analysis: dict[str, Any],
) -> None:
    state = load(session_id)
    graph = state.setdefault("evidence_graph", evidence.new_graph())
    evidence.record_runtime_path(graph, path, analysis)
    save(state)


def save_call_scenario(
    session_id: str,
    name: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """保存一次会话级调用图场景；事件不会塞进主 session JSON。"""
    load(session_id)
    path = _call_scenario_path(session_id, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        **payload,
        "name": name,
        "session_id": session_id,
        "saved_at": _now_ms(),
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, path)
    return {
        "name": name,
        "path": str(path),
        "event_count": int((data.get("analysis") or {}).get("event_count", 0) or 0),
        "graph_fingerprint": data.get("graph_fingerprint", ""),
    }


def save_condition_probe(
    session_id: str,
    scenario_name: str,
    probe_key: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """把条件探针压缩结果写回对应调用图场景文件。"""
    load(session_id)
    path = _call_scenario_path(session_id, scenario_name)
    if not path.exists():
        raise FileNotFoundError(f"call graph scenario not found: {scenario_name}")

    data = json.loads(path.read_text(encoding="utf-8"))
    probes = data.setdefault("condition_probes", {})
    probes[probe_key] = {
        **payload,
        "saved_at": _now_ms(),
    }
    data["probe_updated_at"] = _now_ms()

    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, path)
    return {
        "scenario": scenario_name,
        "probe_key": probe_key,
        "path": str(path),
        "probe_count": len(probes),
    }


def load_condition_probe(
    session_id: str,
    scenario_name: str,
    probe_key: str,
) -> dict[str, Any] | None:
    data = load_call_scenario(session_id, scenario_name)
    probe = (data.get("condition_probes") or {}).get(probe_key)
    return dict(probe) if isinstance(probe, dict) else None


def load_call_scenario(session_id: str, name: str) -> dict[str, Any]:
    load(session_id)
    path = _call_scenario_path(session_id, name)
    if not path.exists():
        raise FileNotFoundError(f"call graph scenario not found: {name}")
    return json.loads(path.read_text(encoding="utf-8"))


def list_call_scenarios(session_id: str) -> list[dict[str, Any]]:
    _session_path(session_id)
    root = _call_scenario_dir(session_id)
    if not root.is_dir():
        return []

    out: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append(
            {
                "name": data.get("name", path.stem),
                "saved_at": data.get("saved_at"),
                "graph_fingerprint": data.get("graph_fingerprint", ""),
                "event_count": int((data.get("analysis") or {}).get("event_count", 0) or 0),
                "observed_nodes": int((data.get("analysis") or {}).get("observed_nodes", 0) or 0),
                "primary_tid": (data.get("analysis") or {}).get("primary_tid"),
                "condition_probe_count": len(data.get("condition_probes") or {}),
                "path": str(path),
            }
        )
    return out


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
