"""MCP entry points for learning, validating and packaging Android actions."""
from __future__ import annotations

import copy
import secrets
import threading
import time
from typing import Any, Optional

from . import action_learning as learning, investigation
from .client import client, ReconError
from .observability import event_integrity

# One executor per session/plan in this MCP process; the device guard additionally
# serializes callers from other clients. Runs are reserved durably before dispatch.
_locks: dict[tuple[str, str], threading.Lock] = {}
_locks_lock = threading.Lock()


def _lock(session_id: str, plan_id: str) -> threading.Lock:
    with _locks_lock:
        return _locks.setdefault((session_id, plan_id), threading.Lock())


def _command(package: str, op: str, process: str = "", timeout_ms: int = 3000, **values) -> dict:
    body = {"package": package, "timeout_ms": timeout_ms, "command": {"op": op, **values}}
    if process:
        body["process"] = process
    return client.post_json("/runtime_command", body)


def _result(response: dict) -> dict:
    rows = response.get("results")
    if not response.get("ok"):
        raise ReconError(str(response.get("error") or rows or "Runtime command failed"))
    if rows is not None:
        if len(rows) != 1 or not rows[0].get("ok"):
            raise ReconError("expected exactly one successful Runtime command result")
        return rows[0].get("result", rows[0])
    return response.get("result", response)


def _select_process(package: str, process: str = "") -> tuple[str, dict]:
    status = client.get_json("/runtime_status", {"package": package})
    rows = [p for p in status.get("processes", []) if p.get("connected") and
            p.get("runtime_command") and p.get("runtime") and (not process or p.get("process") == process)]
    if len(rows) != 1:
        raise ReconError("select one online Tracer process explicitly; zero or multiple processes matched")
    return rows[0]["process"], rows[0]


def _fingerprint(state: dict) -> dict:
    fp = learning.apk_fingerprint(state)
    packages = client.get_json("/packages").get("packages", [])
    matching = [p for p in packages if p.get("package") == state["package"]]
    if len(matching) != 1 or not str(matching[0].get("versionCode", "")).isdigit():
        raise ReconError("cannot confirm installed application versionCode")
    fp["version_code"] = str(matching[0]["versionCode"])
    installed = client.get_json("/apk", {"pkg": state["package"]}).get("apks", [])
    if not installed or not fp["apk_sha256"]:
        raise ReconError("bind all installed APKs before recording or executing actions")
    hashed = client.post_json("/shell", {"argv": ["sha256sum", *[a["path"] for a in installed]]})
    if hashed.get("rc") != 0 or hashed.get("timed_out"):
        raise ReconError("cannot hash installed APK assets")
    from pathlib import PurePosixPath
    remote = []
    for line in hashed.get("stdout", "").splitlines():
        checksum, filename = line.split(maxsplit=1)
        if len(checksum) != 64:
            raise ReconError("invalid installed APK checksum")
        remote.append({"name": PurePosixPath(filename.strip().lstrip("*")).name, "sha256": checksum})
    if sorted(remote, key=lambda a: a["name"]) != fp["apk_sha256"]:
        raise ReconError("local APK assets do not match installed APKs; pull_apk and recapture")
    return fp


def _cleanup(session_id: str, package: str, hooks: list[str]) -> list[dict]:
    errors = []
    for hook in hooks:
        try:
            response = client.post_json("/unhook", {"package": package, "id": hook})
            if response.get("ok") is False:
                raise ReconError(str(response))
            investigation.remove_temporary_hook(session_id, hook)
        except Exception as exc:
            errors.append({"hook_id": hook, "error": str(exc)})
    return errors


def begin_action_capture(session_id: str, label: str, methods: Optional[list[dict]] = None,
                         ui_note: Optional[dict] = None, process: str = "") -> dict:
    """Arm click/long-click + exact candidate methods, then return for manual demonstration.

    Traditional Android View clicks expose id/text/listener class and call stack.
    Compose/WebView/custom touch handlers require additional candidate probes.
    Recording begins only after the selected Runtime reports all hooks installed.
    """
    state = investigation.load(session_id, refresh=True)
    if any(c["status"] == "recording" for c in learning.list_records(session_id, "captures")):
        return {"ok": False, "error": "finish or cancel the active demonstration first"}
    capture_id = secrets.token_hex(8)
    targets, hook_map = learning.make_targets(capture_id, methods or [])
    record = {"id": capture_id, "label": label, "status": "arming", "package": state["package"],
              "hook_map": hook_map, "ui_note": ui_note or {}, "created_at": learning.now_ms()}
    record_path = learning.path(session_id, "captures", capture_id)
    learning.write(record_path, record)
    try:
        process, _ = _select_process(state["package"], process)
        record["process"] = process
        record["fingerprint"] = _fingerprint(state)
        record["context_before"] = _result(_command(state["package"], "context_status", process))
        for hook in hook_map:
            investigation.add_temporary_hook(session_id, hook)
        posted = client.post_json("/hook", {"package": state["package"], "mode": "append",
                                           "restart": False, "debug": False, "targets": targets})
        if posted.get("ok") is False:
            raise ReconError(str(posted))
        deadline = time.monotonic() + 3.0
        while True:
            _, row = _select_process(state["package"], process)
            installed = {h["id"] for h in row["runtime"].get("hooks", []) if h.get("status", "installed") == "installed"}
            missing = sorted(set(hook_map) - installed)
            if not missing:
                break
            if time.monotonic() >= deadline:
                raise ReconError("capture hooks not installed: " + ", ".join(missing))
            time.sleep(0.1)
        record["pid"] = row["runtime"].get("pid")
        cursor = client.get_recent(limit=0)
        record["since_seq"] = cursor["latest_seq"]
        record["stream_id"] = cursor.get("stream_id", "")
        record["status"] = "recording"
        learning.write(record_path, record)
        return {"ok": True, "capture_id": capture_id, "status": "recording", "process": process,
                "instruction": "perform one operation now, then finish_action_capture",
                "coverage": "View clicks + selected methods only; other calls are not recorded"}
    except Exception as exc:
        record.update(status="failed", error=str(exc))
        record["cleanup_errors"] = _cleanup(session_id, state["package"], list(hook_map))
        learning.write(record_path, record)
        return {"ok": False, "capture_id": capture_id, "error": str(exc), "cleanup_errors": record["cleanup_errors"]}


def finish_action_capture(session_id: str, capture_id: str, cancel: bool = False) -> dict:
    """Finish a demonstration, associate clicks with methods and clean only its hooks."""
    record = learning.read(session_id, "captures", capture_id)
    if record["status"] != "recording":
        return {"ok": False, "error": "capture is not recording", "status": record["status"]}
    try:
        if cancel:
            record.update(status="cancelled", events=[])
        else:
            data = client.get_recent(limit=1000, since_seq=record["since_seq"],
                                     stream_id=record.get("stream_id", ""))
            raw = data.get("events", [])
            record["integrity"] = event_integrity(data, record["since_seq"], record.get("stream_id", ""))
            record["truncated"] = record["integrity"]["complete"] is not True
            record["events"] = [e for e in raw if e.get("package") == record["package"]
                                and e.get("hook_id") in record["hook_map"]
                                and (record.get("pid") is None or e.get("pid") == record["pid"])]
            state = investigation.load(session_id, refresh=True)
            current = _fingerprint(state)
            if current != record["fingerprint"]:
                raise ReconError("application assets/version changed during capture")
            record["context_after"] = _result(_command(record["package"], "context_status", record["process"]))
            record["associations"] = learning.correlate(record["events"], record["hook_map"])
            record["next_capture_methods"] = learning.listener_candidates(record["events"], record["hook_map"])
            record["status"] = "truncated" if record["truncated"] else "captured"
        record["finished_at"] = learning.now_ms()
    except Exception as exc:
        record.update(status="failed", error=str(exc))
    finally:
        record["cleanup_errors"] = _cleanup(session_id, record["package"], list(record["hook_map"]))
        learning.write(learning.path(session_id, "captures", capture_id), record)
    return {"ok": record["status"] in {"captured", "cancelled"} and not record["cleanup_errors"], **record}


def list_action_captures(session_id: str) -> dict:
    """List demonstrations without returning raw argument values."""
    rows = learning.list_records(session_id, "captures")
    return {"ok": True, "captures": [{k: r.get(k) for k in ("id", "label", "status", "created_at", "process")}
                                      for r in rows]}


def _captures(session_id: str, ids: list[str]) -> list[dict]:
    if len(set(ids)) != len(ids):
        raise ValueError("demonstrations must be distinct")
    records = [learning.read(session_id, "captures", c) for c in ids]
    if any(c["status"] != "captured" or c.get("cleanup_errors") for c in records):
        raise ValueError("use complete, untruncated captures with successful hook cleanup")
    return records


def compare_action_demonstrations(session_id: str, capture_ids: list[str], method: dict) -> dict:
    """Identify observed constants, dynamic values, missing parameters and ambiguous hits."""
    try:
        return learning.compare(_captures(session_id, capture_ids), method)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}


def create_action_plan(session_id: str, plan_id: str, capture_ids: list[str], method: dict,
                       receiver: str, bindings: dict, checks: list[dict],
                       limits: Optional[dict] = None, setup_actions: Optional[list[dict]] = None) -> dict:
    """Generate a module draft. Dynamic args require input/live-path bindings.

    checks: [{source:"state", path:"value.done", op:"eq", value:true, key:"done"}]
    or source:"events" with exact method and optional correlation {"args[0]":"item_id"}.
    No guess is made about which condition proves the business operation succeeded.
    """
    try:
        record_path = learning.path(session_id, "plans", plan_id)
        if record_path.exists():
            raise ValueError("plan already exists; use a new id to preserve its execution history")
        plan = learning.build_plan(plan_id, _captures(session_id, capture_ids), method,
                                   receiver, bindings, checks, limits, setup_actions)
        learning.write(record_path, plan)
        return {"ok": True, "plan": plan, "saved": str(record_path.resolve())}
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}


def inspect_action_plan(session_id: str, plan_id: str) -> dict:
    """Read the reviewable plan and durable attempt history."""
    return {"ok": True, "plan": learning.read(session_id, "plans", plan_id),
            "runs": [r for r in learning.list_records(session_id, "runs") if r["plan_id"] == plan_id]}


def check_action_compatibility(session_id: str, plan_id: str) -> dict:
    """Check installed version and all locally bound APK hashes before execution."""
    try:
        plan = learning.read(session_id, "plans", plan_id)
        current = _fingerprint(investigation.load(session_id, refresh=True))
        result = learning.compatibility(plan["fingerprint"], current)
        return {"ok": result["compatible"], **result}
    except Exception as exc:
        return {"ok": False, "compatible": False, "error": str(exc)}


def _event_probes(plan: dict, run_id: str) -> tuple[list[dict], dict]:
    targets, members = [], {}
    for rule in plan["checks"]:
        if rule["source"] != "events":
            continue
        member = learning.normalize_method(rule.get("method", {}))
        if member["params"] is None:
            raise ValueError("event outcome probes require exact params")
        key = learning.method_key(member)
        if key in members.values():
            continue
        hook = f"rao_{run_id}_{len(targets)}"
        members[hook] = key
        targets.append({"id": hook, "kind": "java", **member,
                        "capture": {"this": "class", "when": "after", "all_args": True,
                                    "ret": {"capture": True, "render": "tostring"}}})
    return targets, members


def _observe(plan: dict, process: str, since_seq: int, probes: dict, inputs: dict, pid: Any) -> dict:
    context = _result(_command(plan["package"], "context_status", process))
    observations = {"context": context, "state": {}, "events": {}}
    for rule in plan["checks"]:
        if rule["source"] == "state":
            key = rule.get("key")
            if not isinstance(key, str) or not key:
                raise ValueError("state outcome rule requires key")
            if key in observations["state"]:
                continue
            scope = rule.get("scope", "process")
            observations["state"][key] = _result(_command(plan["package"], "state_get", process,
                                                          key=key, scope=scope, hook_id=rule.get("hook_id", "")))
    if probes:
        events = client.get_recent(limit=1000, since_seq=since_seq).get("events", [])
        for rule in plan["checks"]:
            if rule["source"] != "events":
                continue
            key = learning.method_key(rule["method"])
            eligible = []
            for event in events:
                if event.get("package") != plan["package"] or probes.get(event.get("hook_id")) != key:
                    continue
                if event.get("threw"):
                    continue
                if pid is not None and event.get("pid") != pid:
                    continue
                normalized = copy.deepcopy(event)
                args = {a["index"]: a.get("value") for a in event.get("args", [])}
                normalized["args"] = [args.get(i) for i in range(max(args, default=-1) + 1)]
                correlation = rule.get("correlation", {})
                if any(name not in inputs or learning.lookup(normalized, expression) is learning.MISSING
                       or learning.digest(learning.lookup(normalized, expression)) != learning.digest(inputs[name])
                       for expression, name in correlation.items()):
                    continue
                eligible.append(normalized)
            if eligible:
                observations["events"][key] = eligible[-1]
    return observations


def _outcome_rules(plan: dict, inputs: Optional[dict] = None) -> list[dict]:
    rules = copy.deepcopy(plan["checks"])
    for r in rules:
        if isinstance(r.get("value"), str) and (match := learning.INPUT.fullmatch(r["value"])):
            if inputs is None or match[1] not in inputs:
                raise ValueError("outcome check input is missing")
            r["value"] = inputs[match[1]]
        if r["source"] == "events":
            r["path"] = "m" + learning.method_key(r["method"]) + "." + r["path"]
        elif r["source"] == "state":
            r["path"] = r["key"] + "." + r["path"]
    return rules


def execute_action_plan(session_id: str, plan_id: str, inputs: dict, dedup_key: str,
                         dry_run: bool = True, process: str = "", use_installed: bool = False) -> dict:
    """Preview or attempt once; verify independent outcomes; halt on ambiguity/failure.

    No automatic retry. An RPC timeout cannot prove that a running Java method
    was cancelled. Such attempts remain uncertain and block further dispatch.
    """
    with _lock(session_id, plan_id):
        plan = learning.read(session_id, "plans", plan_id)
        record, probes = None, {}
        try:
            if plan["unresolved"]:
                raise ValueError("draft still has unresolved issues")
            actions = learning.bind_inputs(plan, inputs)
            compatible = check_action_compatibility(session_id, plan_id)
            if not compatible.get("compatible"):
                raise ValueError("application version/assets mismatch: " + str(compatible))
            if dry_run:
                return {"ok": True, "dry_run": True, "actions": actions, "checks": plan["checks"],
                        "limits": plan["limits"], "compatibility": compatible}
            process, row = _select_process(plan["package"], process)
            if not row["runtime"].get("guarded_actions"):
                raise ValueError("update the Tracer APK: guarded_actions capability is required")
            if use_installed:
                programs = client.get_json("/runtime_programs", {"package": plan["package"], "id": plan_id})
                active = [p for p in programs.get("programs", []) if p.get("id") == plan_id
                          and p.get("effective_enabled", p.get("enabled"))]
                if len(active) != 1 or active[0].get("manifest", {}).get("learning", {}).get("plan_digest") != learning.plan_digest(plan):
                    raise ValueError("install/enable this exact verified plan before executing its Program")
            record = learning.reserve_run(session_id, plan, inputs, dedup_key)
            record["process"] = process
            targets, probes = _event_probes(plan, record["id"])
            for hook in probes:
                investigation.add_temporary_hook(session_id, hook)
            if targets:
                posted = client.post_json("/hook", {"package": plan["package"], "mode": "append",
                                                   "restart": False, "targets": targets})
                if posted.get("ok") is False:
                    raise ReconError(str(posted))
                # Ensure probes are installed before the action, including async callbacks.
                end = time.monotonic() + 3
                while True:
                    _, current = _select_process(plan["package"], process)
                    hooks = {h["id"] for h in current["runtime"].get("hooks", [])}
                    if set(probes) <= hooks:
                        break
                    if time.monotonic() >= end:
                        raise ReconError("outcome probes were not installed")
                    time.sleep(0.1)
            cursor = client.get_recent(limit=0)["latest_seq"]
            rules = _outcome_rules(plan, inputs)
            before = _observe(plan, process, cursor, probes, inputs, row["runtime"].get("pid"))
            # A pre-existing success state is not evidence that this attempt did anything.
            if learning.check_rules(rules, before)["verified"]:
                raise ValueError("success condition already true before dispatch; use a transition or correlated callback")
            cursor = client.get_recent(limit=0)["latest_seq"]
            if use_installed:
                ack = _result(_command(plan["package"], "event_emit", process, plan["limits"]["timeout_ms"],
                    name="action.execute." + plan_id, payload={"run_id": record["id"], "inputs": inputs,
                    "dedup_key": learning.digest(dedup_key)}, source_hook="__action_plan__"))
                if ack.get("listener_count") != 1:
                    raise ReconError("expected one installed action Program listener")
                guarded = _result(_command(plan["package"], "state_get", process,
                                           scope="process", key="action_guard." + plan_id)).get("value", {})
                response = {"registers": {"$guard_result": guarded}, "event_dispatch": ack}
            else:
                response = _result(_command(plan["package"], "activity_action", process,
                                            plan["limits"]["timeout_ms"], actions=[learning.guard_action(
                                                plan, actions, record["id"], learning.digest(dedup_key))]))
            record["dispatch"] = response
            guarded = response.get("registers", {}).get("$guard_result", {})
            if guarded.get("status") != "awaiting_verification" or guarded.get("run_id") != record["id"]:
                raise ReconError("guarded execution did not finish successfully: " + str(guarded))
            deadline = time.monotonic() + plan["limits"]["verification_ms"] / 1000
            while True:
                observed = _observe(plan, process, cursor, probes, inputs, row["runtime"].get("pid"))
                observed["events"] = {"m" + k: v for k, v in observed["events"].items()}
                outcome = learning.check_rules(rules, observed)
                if outcome["verified"] or time.monotonic() >= deadline:
                    break
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            record["outcome"] = outcome
            record["status"] = "verified" if outcome["verified"] else "uncertain"
            completion = _result(_command(plan["package"], "activity_action", process, actions=[{
                "action": "complete_guarded", "task_id": plan_id, "run_id": record["id"],
                "verified": outcome["verified"]}]))
            if completion.get("registers", {}).get("$guard_result", {}).get("status") != record["status"]:
                raise ReconError("device completion did not acknowledge matching run")
            if outcome["verified"]:
                plan["verified_run"] = {"run_id": record["id"], "plan_digest": learning.plan_digest(plan)}
                plan["status"] = "verified"
        except Exception as exc:
            if record is None:
                return {"ok": False, "error": str(exc)}
            record.update(status="uncertain", error=str(exc))
        finally:
            if record:
                record["finished_at"] = learning.now_ms()
                record["cleanup_errors"] = _cleanup(session_id, plan["package"], list(probes))
                if record["cleanup_errors"]:
                    record["status"] = "uncertain"
                if record["status"] != "verified":
                    plan.pop("verified_run", None)
                    plan["status"] = "halted"
                learning.write(learning.path(session_id, "runs", record["id"]), record)
                plan["last_run"] = record["id"]
                learning.write(learning.path(session_id, "plans", plan_id), plan)
        return {"ok": record["status"] == "verified", "run": record}


def export_action_plan(session_id: str, plan_id: str) -> dict:
    """Export a reviewable plan + executable Runtime Program manifest (not a signed bundle)."""
    try:
        plan = learning.read(session_id, "plans", plan_id)
        manifest = learning.build_manifest(plan)
        output = learning.directory(session_id) / f"{plan_id}.action-plan.json"
        learning.write(output, {"plan": plan, "manifest": manifest})
        return {"ok": True, "saved": str(output.resolve()), "manifest": manifest,
                "validated": plan.get("verified_run", {}).get("plan_digest") == learning.plan_digest(plan)}
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}


def install_action_plan(session_id: str, plan_id: str, enable: bool = True) -> dict:
    """Install a successfully verified plan, retaining existing Runtime Program permission policy."""
    with _lock(session_id, plan_id):
        plan = learning.read(session_id, "plans", plan_id)
        if plan.get("verified_run", {}).get("plan_digest") != learning.plan_digest(plan):
            return {"ok": False, "error": "a successful trial of this exact plan is required"}
        proof = learning.read(session_id, "runs", plan["verified_run"]["run_id"])
        if proof["status"] != "verified" or plan.get("last_run") != proof["id"]:
            return {"ok": False, "error": "the most recent attempt must be verified before installation"}
        compatibility = check_action_compatibility(session_id, plan_id)
        if not compatibility.get("compatible"):
            return {"ok": False, "error": "application compatibility check failed", "compatibility": compatibility}
        manifest = learning.build_manifest(plan)
        return client.post_json("/runtime_program/install", {"package": plan["package"],
            "manifest": manifest, "mode": "install", "enable": enable, "restart": False, "timeout_ms": 3000})


TOOLS = (begin_action_capture, finish_action_capture, list_action_captures,
         compare_action_demonstrations, create_action_plan, inspect_action_plan,
         check_action_compatibility, execute_action_plan, export_action_plan, install_action_plan)


def register(mcp) -> None:
    for function in TOOLS:
        mcp.tool()(function)
