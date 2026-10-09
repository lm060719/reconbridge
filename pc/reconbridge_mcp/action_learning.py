"""Action demonstrations, conservative parameter inference and reviewable plans.

No application-specific logic lives here. Temporal correlation is deliberately
reported as correlation, and captured object renderings are never replayed as
live Java objects.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from . import investigation, program_package

NAME = re.compile(r"^[A-Za-z0-9_\-\u4e00-\u9fff]{1,64}$")
PROGRAM_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
INPUT = re.compile(r"^\{\{input\.([A-Za-z][A-Za-z0-9_]*)\}\}$")
MISSING = object()
PRIMITIVES = {"boolean", "byte", "short", "int", "long", "float", "double", "char",
              "java.lang.String", "java.lang.Boolean", "java.lang.Integer", "java.lang.Long",
              "java.lang.Float", "java.lang.Double", "java.lang.Short", "java.lang.Byte"}


def now_ms() -> int:
    return int(time.time() * 1000)


def directory(session_id: str) -> Path:
    investigation.load(session_id)
    return investigation._ROOT / f"{session_id}.actions"


def path(session_id: str, kind: str, name: str) -> Path:
    if kind not in {"captures", "plans", "runs"} or not NAME.fullmatch(name):
        raise ValueError("invalid action record name")
    return directory(session_id) / kind / f"{name}.json"


def write(record_path: Path, record: dict) -> None:
    record_path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp names also keep independent captures from clobbering a writer.
    tmp = record_path.with_name(record_path.name + "." + secrets.token_hex(4) + ".tmp")
    try:
        tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
        os.replace(tmp, record_path)
    finally:
        tmp.unlink(missing_ok=True)


def read(session_id: str, kind: str, name: str) -> dict:
    return json.loads(path(session_id, kind, name).read_text(encoding="utf-8"))


def list_records(session_id: str, kind: str) -> list[dict]:
    root = directory(session_id) / kind
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(root.glob("*.json"))]


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def apk_fingerprint(state: dict) -> dict:
    assets = []
    for filename in sorted(state.get("artifacts", {}).get("apks", [])):
        p = Path(filename)
        h = hashlib.sha256()
        with p.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
        assets.append({"name": p.name, "sha256": h.hexdigest()})
    return {"package": state["package"], "apk_sha256": assets}


def normalize_method(method: dict) -> dict:
    name = str(method.get("class", "")).replace("/", ".")
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    member = method.get("method", "")
    params = method.get("params")
    if not name or not isinstance(member, str) or not member:
        raise ValueError("method requires class and method")
    if params is not None and (not isinstance(params, list) or not all(isinstance(p, str) for p in params)):
        raise ValueError("params must be a list of exact Java parameter types")
    return {"class": name, "method": member, "params": params}


def method_key(method: dict) -> str:
    return digest(normalize_method(method))[:16]


def make_targets(capture_id: str, methods: list[dict]) -> tuple[list[dict], dict]:
    if len(methods) > 24:
        raise ValueError("at most 24 candidate methods per capture")
    targets, hook_map = [], {}
    for i, member in enumerate([{"class": "android.view.View", "method": "performClick", "params": []},
                                {"class": "android.view.View", "method": "performLongClick", "params": []}] + methods):
        member = normalize_method(member)
        hook_id = f"rba_{capture_id}_{i}"
        ui = i < 2
        capture = {"this": "class", "when": "before" if ui else "both", "all_args": True,
                   "ret": {"capture": True, "render": "tostring"}, "stack": True}
        if ui:
            capture["paths"] = [{"path": p, "render": "tostring", "max": 256}
                                for p in ("this.id", "this.contentDescription", "this.text")]
            capture["paths"].append({"path": "this.mListenerInfo.mOnClickListener", "render": "class"})
            capture["paths"].append({"path": "this.mListenerInfo.mOnLongClickListener", "render": "class"})
        target = {"id": hook_id, "kind": "java", "class": member["class"],
                  "method": member["method"], "capture": capture}
        if member["params"] is not None:
            target["params"] = member["params"]
        targets.append(target)
        hook_map[hook_id] = {**member, "ui": ui}
    return targets, hook_map


def correlate(events: list[dict], hook_map: dict, window_ms: int = 1500) -> list[dict]:
    """Same process/thread + order is stronger than nearby wall-clock time."""
    ordered = sorted(events, key=lambda e: (e.get("ts", 0), e.get("seq", 0)))
    clicks = [e for e in ordered if hook_map.get(e.get("hook_id"), {}).get("ui")]
    associations = []
    for event in ordered:
        member = hook_map.get(event.get("hook_id"), {})
        if not member or member.get("ui"):
            continue
        nearby = [c for c in clicks if c.get("pid") == event.get("pid")
                  and 0 <= event.get("ts", 0) - c.get("ts", 0) <= window_ms]
        same_thread = [c for c in nearby if c.get("tid") is not None and c.get("tid") == event.get("tid")]
        click = (same_thread or nearby or [None])[-1]
        associations.append({"event_seq": event.get("seq"), "method": member,
                             "click_seq": click.get("seq") if click else None,
                             "delta_ms": event.get("ts", 0) - click.get("ts", 0) if click else None,
                             "association": "same_thread_temporal" if same_thread else
                             "temporal_only" if click else "unassociated",
                             "causality_confirmed": False})
    return associations


def listener_candidates(events: list[dict], hook_map: dict) -> list[dict]:
    candidates = {}
    for event in events:
        if not hook_map.get(event.get("hook_id"), {}).get("ui"):
            continue
        long_click = event.get("method") == "performLongClick"
        listener_path = "this.mListenerInfo." + ("mOnLongClickListener" if long_click else "mOnClickListener")
        for item in event.get("paths", []):
            if item.get("path") == listener_path and not item.get("unresolved") and item.get("value"):
                member = {"class": item["value"], "method": "onLongClick" if long_click else "onClick", "params": ["android.view.View"]}
                candidates[method_key(member)] = {**member, "evidence": "live View listener class", "runtime_confirmed": False}
    return list(candidates.values())


def compare(captures: list[dict], method: dict) -> dict:
    if not 2 <= len(captures) <= 20:
        raise ValueError("compare needs 2–20 demonstrations")
    method = normalize_method(method)
    signatures = {digest(c.get("fingerprint", {})) for c in captures}
    if len(signatures) != 1:
        raise ValueError("demonstrations came from different application versions/assets")
    observations, problems = [], []
    for record in captures:
        hooks = record.get("hook_map", {})
        hits = [e for e in record.get("events", [])
                if not hooks.get(e.get("hook_id"), {}).get("ui")
                and hooks.get(e.get("hook_id"), {}).get("class") == method["class"]
                and hooks.get(e.get("hook_id"), {}).get("method") == method["method"]
                and hooks.get(e.get("hook_id"), {}).get("params") == method["params"]
                and e.get("phase") == "before"]
        if len(hits) != 1:
            problems.append({"capture_id": record["id"], "hits": len(hits),
                             "reason": "expected exactly one before hit; narrow the capture or method"})
            continue
        observations.append({"capture_id": record["id"], "event": hits[0]})
    params = method["params"]
    rows = []
    count = len(params) if params is not None else max(
        [len(o["event"].get("args", [])) for o in observations] or [0])
    for index in range(count):
        values, missing = [], []
        for obs in observations:
            args = {a["index"]: a for a in obs["event"].get("args", []) if isinstance(a, dict) and "index" in a}
            arg = args.get(index)
            if arg is None or arg.get("unresolved") or arg.get("truncated") or "value" not in arg:
                missing.append(obs["capture_id"])
            else:
                values.append(arg["value"])
        stable = bool(values) and not missing and len({digest(v) for v in values}) == 1
        rows.append({"index": index, "type": params[index] if params is not None else None,
                     "classification": "missing" if missing or not values else "observed_constant" if stable else "dynamic",
                     "values": values, "missing_in": missing,
                     "replayable_literal": params is not None and params[index] in PRIMITIVES
                     and all(v is None or isinstance(v, (str, int, float, bool)) for v in values)})
    return {"ok": not problems and params is not None, "method": method,
            "demonstration_count": len(captures), "observed_count": len(observations),
            "parameters": rows, "problems": problems,
            "exact_overload": params is not None,
            "note": "observed_constant means stable in these samples, not a proven global constant"}


def lookup(value: Any, expression: str) -> Any:
    # Restricted paths: dictionaries and lists only; no eval, getters or code.
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*", expression):
        return MISSING
    for match in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]", expression):
        name, index = match.groups()
        if name and isinstance(value, dict) and name in value:
            value = value[name]
        elif index is not None and isinstance(value, list) and int(index) < len(value):
            value = value[int(index)]
        else:
            return MISSING
    return value


def check_rules(rules: list[dict], observations: dict) -> dict:
    results = []
    for rule in rules:
        actual = lookup(observations.get(rule["source"], {}), rule["path"])
        expected, op = rule.get("value"), rule.get("op", "eq")
        matched = actual is not MISSING
        if matched:
            if op == "eq":
                matched = type(actual) is type(expected) and actual == expected
            elif op == "neq":
                matched = type(actual) is not type(expected) or actual != expected
            elif op == "not_null":
                matched = actual is not None
            elif op == "contains":
                matched = ((isinstance(actual, str) and isinstance(expected, str) and expected in actual)
                           or (isinstance(actual, list) and any(type(v) is type(expected) and v == expected for v in actual))
                           or (isinstance(actual, dict) and isinstance(expected, str) and expected in actual))
            elif op in {"gt", "gte", "lt", "lte"}:
                matched = type(actual) in (int, float) and type(expected) in (int, float)
                if matched:
                    matched = {"gt": actual > expected, "gte": actual >= expected,
                               "lt": actual < expected, "lte": actual <= expected}[op]
            else:
                raise ValueError("unsupported verification operator")
        results.append({"rule": rule, "matched": bool(matched), "missing": actual is MISSING,
                        "actual": None if actual is MISSING else actual})
    return {"verified": bool(rules) and all(r["matched"] for r in results), "checks": results}


def validate_rules(rules: list[dict]) -> None:
    if not isinstance(rules, list) or not 1 <= len(rules) <= 16:
        raise ValueError("provide 1–16 independent outcome checks")
    state_addresses = {}
    for r in rules:
        if not isinstance(r, dict) or r.get("source") not in {"state", "context", "events"}:
            raise ValueError("outcome source must be state, context or events")
        if not isinstance(r.get("path"), str):
            raise ValueError("outcome checks require an observation path")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*", r["path"]):
            raise ValueError("invalid verification path")
        if r.get("op", "eq") not in {"eq", "neq", "not_null", "contains", "gt", "gte", "lt", "lte"}:
            raise ValueError("unsupported verification operator")
        if r["source"] == "state" and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(r.get("key", ""))):
            raise ValueError("state outcome checks need an identifier key")
        if r["source"] == "state":
            address = (r.get("scope", "process"), r.get("hook_id", ""))
            if address[0] not in {"process", "package", "hook"} or (address[0] == "hook" and not address[1]):
                raise ValueError("invalid outcome state scope or missing hook_id")
            if r["key"] in state_addresses and state_addresses[r["key"]] != address:
                raise ValueError("the same state key cannot refer to different scopes in one plan")
            state_addresses[r["key"]] = address
        if r["source"] == "events":
            if normalize_method(r.get("method", {}))["params"] is None:
                raise ValueError("event outcome checks require exact method params")
            correlation = r.get("correlation", {})
            if not isinstance(correlation, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in correlation.items()):
                raise ValueError("event correlation must map observation paths to input names")


def plan_digest(plan: dict) -> str:
    return digest({k: v for k, v in plan.items() if k not in {"last_run", "verified_run", "status", "created_at"}})


def build_plan(plan_id: str, captures: list[dict], method: dict, receiver: str,
               bindings: dict, checks: list[dict], limits: dict | None = None,
               setup_actions: list[dict] | None = None) -> dict:
    if not PROGRAM_ID.fullmatch(plan_id) or "." in plan_id:
        raise ValueError("invalid plan id")
    analysis = compare(captures, method)
    method = analysis["method"]
    validate_rules(checks)
    if not receiver or receiver == "this" or receiver.startswith("args[") or receiver.startswith("ret"):
        raise ValueError("receiver must be reacquired from activity/context/class or setup registers")
    if not (receiver in {"activity", "context", "application"} or receiver.startswith(("class:", "activity.", "context.", "$"))):
        raise ValueError("unsupported receiver")
    limits = {"max_runs": 10, "min_interval_ms": 1000, "timeout_ms": 5000,
              "verification_ms": 3000, **(limits or {})}
    ranges = {"max_runs": (1, 1000), "min_interval_ms": (0, 3600000),
              "timeout_ms": (200, 10000), "verification_ms": (0, 30000)}
    for key, (low, high) in ranges.items():
        if type(limits[key]) is not int or not low <= limits[key] <= high:
            raise ValueError(f"invalid limit: {key}")
    if set(limits) - set(ranges):
        raise ValueError("unknown execution limit")
    unresolved = copy.deepcopy(analysis["problems"])
    if not analysis["exact_overload"]:
        unresolved.append({"reason": "exact params required; overloaded methods cannot be guessed"})
    arguments, inputs = [], {}
    for p in analysis["parameters"]:
        binding = bindings.get(str(p["index"]))
        if binding:
            if not isinstance(binding, dict) or set(binding) - {"input", "path", "value"} or len(binding) != 1:
                raise ValueError("each binding must contain exactly input, path or value")
            if "input" in binding:
                name = binding["input"]
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
                    raise ValueError("invalid input name")
                if not p["replayable_literal"]:
                    unresolved.append({"index": p["index"], "reason": "object argument needs a live runtime path"})
                if name in inputs and inputs[name]["type"] != p["type"]:
                    raise ValueError("one input cannot have conflicting Java types")
                inputs[name] = {"type": p["type"], "required": True}
                arguments.append({"value": "{{input." + name + "}}"})
            elif "path" in binding:
                expression = binding["path"]
                if not isinstance(expression, str) or not expression.startswith(("activity.", "context.", "application.", "state.", "$")):
                    raise ValueError("argument paths must reacquire a current runtime value")
                arguments.append({"from": "path", "path": expression})
            else:
                if not p["replayable_literal"]:
                    unresolved.append({"index": p["index"], "reason": "rendered Java objects are not literal arguments"})
                else:
                    validate_input(str(p["index"]), binding["value"], p["type"])
                arguments.append({"literal": binding["value"]})
        elif p["classification"] == "observed_constant" and p["replayable_literal"]:
            validate_input(str(p["index"]), p["values"][0], p["type"])
            arguments.append({"literal": p["values"][0]})
        else:
            unresolved.append({"index": p["index"], "reason": "dynamic, missing or object parameter requires a binding"})
            arguments.append({"value": None})
    if set(bindings) - {str(p["index"]) for p in analysis["parameters"]}:
        raise ValueError("binding index is outside the method signature")
    fingerprint = captures[0]["fingerprint"]
    if not fingerprint.get("version_code"):
        unresolved.append({"reason": "live version_code missing; recapture after connecting the device"})
    if not fingerprint.get("apk_sha256"):
        unresolved.append({"reason": "bind the current APK assets before recording demonstrations"})
    for rule in checks:
        if rule["source"] == "events" and inputs and not rule.get("correlation"):
            unresolved.append({"reason": "event success check needs correlation to the current business input"})
        if set(rule.get("correlation", {}).values()) - set(inputs):
            raise ValueError("event correlation references an unknown input")
        if isinstance(rule.get("value"), str) and (match := INPUT.fullmatch(rule["value"])):
            if match[1] not in inputs:
                raise ValueError("outcome check references an unknown input")
    for source in {r["source"] for r in checks} & {"state", "context"}:
        if inputs and not any(r["source"] == source and isinstance(r.get("value"), str)
                              and INPUT.fullmatch(r["value"]) for r in checks):
            unresolved.append({"reason": f"{source} success checks need a current-input identity check"})
    actions = copy.deepcopy(setup_actions or [])
    if len(actions) > 16 or not all(isinstance(a, dict) and a.get("action") in {"call_method", "get_state"} for a in actions):
        raise ValueError("setup_actions supports at most 16 call_method/get_state steps")
    actions.append({"action": "call_method", "target": receiver, "method": method["method"],
                    "expected_class": method["class"],
                    "params": method.get("params") or [], "args": arguments, "save_to": "$action_return"})
    return {"schema": 1, "id": plan_id, "package": fingerprint["package"], "status": "draft",
            "created_at": now_ms(), "method": normalize_method(method), "actions": actions,
            "inputs": inputs, "checks": checks, "limits": limits,
            "fingerprint": fingerprint, "demonstrations": [c["id"] for c in captures],
            "analysis": analysis, "unresolved": unresolved,
            "execution_contract": "one attempt; ambiguous/failed outcome halts; no automatic resubmission"}


def validate_input(name: str, value: Any, java_type: str) -> None:
    if value is None and java_type.startswith("java.lang."):
        return
    if java_type in {"boolean", "java.lang.Boolean"}:
        valid = type(value) is bool
    elif java_type in {"byte", "short", "int", "long", "java.lang.Byte", "java.lang.Short", "java.lang.Integer", "java.lang.Long"}:
        bits = {"byte": 8, "short": 16, "int": 32, "long": 64,
                "java.lang.Byte": 8, "java.lang.Short": 16, "java.lang.Integer": 32, "java.lang.Long": 64}[java_type]
        valid = type(value) is int and -(2 ** (bits - 1)) <= value < 2 ** (bits - 1)
    elif java_type in {"float", "double", "java.lang.Float", "java.lang.Double"}:
        valid = type(value) in (float, int)
        if valid and java_type in {"float", "java.lang.Float"}:
            valid = abs(value) <= 3.4028235e38
    elif java_type == "char":
        valid = isinstance(value, str) and len(value) == 1
    else:
        valid = java_type == "java.lang.String" and isinstance(value, str)
    if not valid:
        raise ValueError(f"invalid value/type for input {name}: {java_type}")
    digest(value)  # also rejects NaN / infinity


def bind_inputs(plan: dict, inputs: dict, *, runtime: bool = False) -> list[dict]:
    if set(inputs) != set(plan["inputs"]):
        raise ValueError("inputs must exactly match the plan's required inputs")
    for name, spec in plan["inputs"].items():
        validate_input(name, inputs[name], spec["type"])
    def walk(node: Any) -> Any:
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, dict):
            if "literal" in node:
                return copy.deepcopy(node)
            if set(node) == {"value"} and isinstance(node["value"], str):
                match = INPUT.fullmatch(node["value"])
                if match:
                    return {"path": "event.inputs." + match[1]} if runtime else {"literal": inputs[match[1]]}
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, str):
            match = INPUT.fullmatch(node)
            if match:
                if runtime:
                    return "${event.inputs." + match[1] + "}"
                # Literal descriptors avoid interpreting ${...} in user input.
                return inputs[match[1]]
        return node
    return walk(plan["actions"])


def compatibility(expected: dict, current: dict) -> dict:
    mismatches = [key for key in ("package", "version_code", "apk_sha256")
                  if not expected.get(key) or expected.get(key) != current.get(key)]
    return {"compatible": not mismatches, "mismatches": mismatches,
            "expected": expected, "current": current}


def reserve_run(session_id: str, plan: dict, inputs: dict, dedup_key: str) -> dict:
    if not isinstance(dedup_key, str) or not 1 <= len(dedup_key) <= 256:
        raise ValueError("dedup_key is required and must identify the business item")
    history = [r for r in list_records(session_id, "runs") if r["plan_id"] == plan["id"]]
    if any(r["status"] != "verified" for r in history):
        raise ValueError("plan halted: a previous run is failed, pending or uncertain; review it before creating a new plan")
    if len(history) >= plan["limits"]["max_runs"]:
        raise ValueError("run limit reached")
    key = digest(dedup_key)
    if any(r["dedup_hash"] == key for r in history):
        raise ValueError("duplicate business item")
    if history and now_ms() - max(r["started_at"] for r in history) < plan["limits"]["min_interval_ms"]:
        raise ValueError("minimum interval not reached")
    record = {"id": secrets.token_hex(8), "plan_id": plan["id"], "plan_digest": plan_digest(plan),
              "inputs_digest": digest(inputs), "dedup_hash": key, "started_at": now_ms(), "status": "pending"}
    write(path(session_id, "runs", record["id"]), record)
    return record


def guard_action(plan: dict, actions: list[dict], run_id: str, dedup_key: str) -> dict:
    return {"action": "run_guarded", "task_id": plan["id"], "run_id": run_id,
            "dedup_key": dedup_key, "expected_version_code": plan["fingerprint"]["version_code"],
            **{k: plan["limits"][k] for k in ("max_runs", "min_interval_ms", "timeout_ms")},
            "actions": actions}


def build_manifest(plan: dict) -> dict:
    if plan["unresolved"]:
        raise ValueError("resolve all draft issues before generating an executable manifest")
    # Build runtime templates without inventing parameter values.
    def convert(node: Any) -> Any:
        if isinstance(node, list):
            return [convert(v) for v in node]
        if isinstance(node, dict):
            if "literal" in node:
                return copy.deepcopy(node)
            return {k: convert(v) for k, v in node.items()}
        if isinstance(node, str) and (m := INPUT.fullmatch(node)):
            return {"from": "path", "path": "event.inputs." + m[1]}
        return node
    actions = convert(plan["actions"])
    # Flatten nested descriptors resulting from value placeholders.
    def flatten(node: Any) -> Any:
        if isinstance(node, list):
            return [flatten(v) for v in node]
        if isinstance(node, dict):
            if set(node) == {"value"} and isinstance(node["value"], dict) and "from" in node["value"]:
                return node["value"]
            return {k: flatten(v) for k, v in node.items()}
        return node
    guarded = guard_action(plan, flatten(actions), "${event.run_id}", "${event.dedup_key}")
    guarded["input_schema"] = plan["inputs"]
    guarded["dispatch_main_thread"] = True
    manifest = {"id": plan["id"], "name": plan["id"], "version": "1.0.0",
                "description": "Learned action with external outcome verification; see learning metadata",
                "targets": [{"id": "execute", "kind": "runtime", "on_event": {
                    "name": "action.execute." + plan["id"], "actions": [guarded]}}],
                "learning": {"plan_digest": plan_digest(plan), "fingerprint": plan["fingerprint"],
                             "checks": plan["checks"], "inputs": plan["inputs"],
                             "limits": plan["limits"], "demonstrations": plan["demonstrations"],
                             "completion_required": "complete_guarded with matching run_id after outcome verification"}}
    manifest["permissions"] = program_package.required_permissions(manifest)
    return manifest
