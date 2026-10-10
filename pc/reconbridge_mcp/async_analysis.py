"""Opt-in scheduling hooks and evidence-based asynchronous span reconstruction."""
from __future__ import annotations
import json
import re
from .client import client
from .observability import validate_package
from . import investigation, workflow_artifacts


def configure_async_trace(package: str, enqueue: dict, execute: dict, namespace: str = "tasks") -> dict:
    """Install two explicit Java hooks to observe the SAME task object across enqueue/execute.

    Requires Tracer 1.2.0+. Each descriptor: class, method, optional params, task=this|arg:N.
    No global Executor/Handler hook is guessed; wrappers, task reuse, eviction and >60s delays
    may be unmatched/ambiguous. Remove the returned hook IDs with unhook when finished.
    """
    validate_package(package)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", namespace):
        raise ValueError("invalid async namespace")
    targets = []
    for role, descriptor in (("enqueue", enqueue), ("execute", execute)):
        if not isinstance(descriptor, dict) or set(descriptor) - {"class", "method", "params", "task"}:
            raise ValueError("descriptor supports class/method/params/task")
        if any(not isinstance(descriptor.get(key), str) or not descriptor[key] or len(descriptor[key]) > 512 for key in ("class", "method")):
            raise ValueError("class and method are required")
        task = descriptor.get("task", "arg:0" if role == "enqueue" else "this")
        if task != "this" and not (isinstance(task, str) and re.fullmatch(r"arg:[0-9]{1,2}", task)):
            raise ValueError("task must be this or arg:N")
        params = descriptor.get("params")
        if params is not None and (not isinstance(params, list) or len(params) > 100 or any(not isinstance(p,str) or not p for p in params)):
            raise ValueError("params must be a list of Java type names")
        target = {"id": f"__rb_async_{namespace}_{role}", "kind": "java", "class": descriptor["class"],
            "method": descriptor["method"], "capture": {"when": "both", "this": "none", "correlation": True},
            "async_link": {"role": role, "namespace": namespace, "task": task}}
        if params is not None: target["params"] = params
        targets.append(target)
    result = client.post_json("/hook", {"package": package, "mode": "append", "restart": False, "targets": targets})
    return {**result, "hook_ids": [t["id"] for t in targets], "runtime_effect_confirmed": False,
            "requires_tracer": "1.2.0", "next_step": "check runtime_hook_status, capture both hooks, then correlate_async_events"}


def correlate(events: list[dict], package: str) -> dict:
    if not isinstance(events, list) or len(events) > 10000:
        raise ValueError("events must be a list of at most 10000 objects")
    spans: dict[tuple, dict] = {}
    ignored = 0
    for event in events:
        if not isinstance(event, dict) or str(event.get("package", "")).split(":",1)[0] != package:
            ignored += 1; continue
        corr = event.get("correlation")
        if not isinstance(corr, dict) or corr.get("version") != 1 or not event.get("process_instance") or not corr.get("span_id"):
            ignored += 1; continue
        key = (str(event["process_instance"]), str(event.get("pid", "")), str(corr["span_id"]))
        row = spans.setdefault(key, {"process_instance": key[0], "pid": event.get("pid"), "span_id": key[2],
            "class": event.get("class"), "method": event.get("method"), "events": [], "correlation": corr})
        row["events"].append({"stream_id": event.get("stream_id"), "seq": event.get("seq"), "phase": event.get("phase"), "tid": event.get("tid")})
        if event.get("phase") == "after": row["correlation"] = corr
    edges, unresolved = [], []
    for key, row in spans.items():
        corr = row["correlation"]
        parent = corr.get("parent_span_id")
        if parent:
            parent_key = (*key[:2], str(parent))
            if parent_key in spans: edges.append({"from": list(parent_key), "to": list(key), "kind": "observed_thread_nesting"})
        link = corr.get("async")
        if not isinstance(link,dict) or link.get("role") != "execute": continue
        parent_key = (*key[:2], str(link.get("enqueue_span_id", "")))
        origin = spans.get(parent_key, {}).get("correlation", {}).get("async", {})
        if not isinstance(origin, dict): origin = {}
        matched = (link.get("status") == "matched" and origin.get("role") == "enqueue"
            and origin.get("task_id") == link.get("task_id") and origin.get("namespace") == link.get("namespace")
            and origin.get("enqueue_returned_successfully") is True)
        if matched:
            edges.append({"from": list(parent_key), "to": list(key), "kind": "observed_task_identity",
                          "task_id": link["task_id"], "namespace": link["namespace"]})
        else:
            unresolved.append({"span": list(key), "status": link.get("status"), "reason": "missing/ambiguous/rejected enqueue evidence"})
    return {"package": package, "spans": list(spans.values()), "edges": edges, "unresolved": unresolved,
            "ignored_events": ignored, "complete": None, "upstream_loss": "unknown",
            "scope": "explicit instrumented task identities and thread nesting; no timestamp-only causality or automatic coroutine/Binder propagation"}


def correlate_async_events(session_id: str, events: list[dict]) -> dict:
    """Reconstruct recorded task identity links; retain unresolved evidence and save a session artifact."""
    state = investigation.load(session_id)
    result = correlate(events, state["package"])
    record, folder = workflow_artifacts.create(session_id, "async_correlation")
    (folder / "correlation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    record.update(ok=True, span_count=len(result["spans"]), edge_count=len(result["edges"]), unresolved_count=len(result["unresolved"]))
    return {**workflow_artifacts.finish(record, folder), "analysis": result}


def register(mcp) -> None:
    for tool in (configure_async_trace, correlate_async_events): mcp.tool()(tool)
