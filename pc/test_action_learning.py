"""Learning tests concentrate on ambiguity, dynamic data and side-effect boundaries."""
from __future__ import annotations

import copy
import hashlib

import pytest

from reconbridge_mcp import action_learning as learning, action_tools, investigation, server
from reconbridge_mcp.settings import settings

METHOD = {"class": "com.example.Controller", "method": "submit", "params": ["long", "boolean"]}
CHECKS = [{"source": "state", "key": "result", "path": "value.done", "value": True},
          {"source": "state", "key": "result", "path": "value.item_id", "value": "{{input.item_id}}"}]


def sample(name, item):
    return {"id": name, "status": "captured", "fingerprint": {
        "package": "com.example.app", "version_code": "7",
        "apk_sha256": [{"name": "base.apk", "sha256": hashlib.sha256(b"sample").hexdigest()}]},
        "hook_map": {"business": {**METHOD, "ui": False}}, "events": [
            {"hook_id": "business", "phase": "before", "args": [
                {"index": 0, "value": item}, {"index": 1, "value": True}]}]}


def plan():
    return learning.build_plan("submit", [sample("a", 1), sample("b", 2)], METHOD,
                               "activity", {"0": {"input": "item_id"}}, CHECKS,
                               {"min_interval_ms": 0, "verification_ms": 0})


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")
    apk = tmp_path / "com.example.app" / "apk" / "base.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"sample")
    return investigation.create("com.example.app")["session_id"]


def test_inference_distinguishes_dynamic_from_observed_constants():
    result = learning.compare([sample("a", 1), sample("b", 2)], METHOD)
    assert result["ok"]
    assert [p["classification"] for p in result["parameters"]] == ["dynamic", "observed_constant"]


def test_ambiguous_and_missing_hits_are_not_treated_as_valid_training():
    a, b = sample("a", 1), sample("b", 2)
    b["events"] *= 2
    result = learning.compare([a, b], METHOD)
    assert not result["ok"]
    assert result["problems"][0]["hits"] == 2


def test_missing_argument_is_not_inferred_as_constant_null():
    a, b = sample("a", 1), sample("b", 2)
    b["events"][0]["args"] = []
    result = learning.compare([a, b], METHOD)
    assert result["parameters"][1]["classification"] == "missing"


def test_truncated_values_are_never_replayed_as_constants():
    a, b = sample("a", 1), sample("b", 2)
    for record in (a, b):
        record["events"][0]["args"][1]["truncated"] = True
    assert learning.compare([a, b], METHOD)["parameters"][1]["classification"] == "missing"


def test_version_mixture_rejected():
    b = sample("b", 2)
    b["fingerprint"]["version_code"] = "8"
    with pytest.raises(ValueError, match="different application"):
        learning.compare([sample("a", 1), b], METHOD)


def test_correlations_do_not_claim_causality_or_link_other_processes():
    hooks = {"click": {"ui": True}, "method": {**METHOD, "ui": False}}
    events = [{"hook_id": "click", "seq": 1, "ts": 100, "pid": 1, "tid": 1},
              {"hook_id": "method", "seq": 2, "ts": 105, "pid": 1, "tid": 1},
              {"hook_id": "method", "seq": 3, "ts": 110, "pid": 1, "tid": 2},
              {"hook_id": "method", "seq": 4, "ts": 111, "pid": 2, "tid": 1}]
    associations = learning.correlate(events, hooks)
    assert [a["association"] for a in associations] == ["same_thread_temporal", "temporal_only", "unassociated"]
    assert all(not a["causality_confirmed"] for a in associations)


def test_click_listener_gives_an_unconfirmed_precise_next_probe():
    events = [{"hook_id": "click", "method": "performClick", "paths": [{
        "path": "this.mListenerInfo.mOnClickListener", "value": "com.example.Screen$Listener"}]}]
    assert learning.listener_candidates(events, {"click": {"ui": True}}) == [{
        "class": "com.example.Screen$Listener", "method": "onClick", "params": ["android.view.View"],
        "evidence": "live View listener class", "runtime_confirmed": False}]


def test_dynamic_parameters_require_explicit_bindings():
    p = learning.build_plan("submit", [sample("a", 1), sample("b", 2)], METHOD, "activity", {}, [CHECKS[0]])
    assert p["unresolved"][0]["index"] == 0


def test_binding_preserves_types_and_literal_template_text():
    assert learning.bind_inputs(plan(), {"item_id": 42})[-1]["args"] == [{"literal": 42}, {"literal": True}]
    p = plan()
    p["inputs"] = {"text": {"type": "java.lang.String"}}
    p["actions"][0]["args"] = [{"value": "{{input.text}}"}]
    assert learning.bind_inputs(p, {"text": "${state.process.secret}"})[0]["args"] == [{"literal": "${state.process.secret}"}]
    with pytest.raises(ValueError, match="invalid value/type"):
        learning.bind_inputs(plan(), {"item_id": True})
    with pytest.raises(ValueError):
        learning.bind_inputs(plan(), {"item_id": 2**64})


def test_manifest_parameterizes_dynamic_input_and_enforces_limits():
    manifest = learning.build_manifest(plan())
    guarded = manifest["targets"][0]["on_event"]["actions"][0]
    assert guarded["action"] == "run_guarded"
    assert guarded["max_runs"] == 10
    assert guarded["expected_version_code"] == "7"
    assert guarded["actions"][0]["args"][0] == {"from": "path", "path": "event.inputs.item_id"}
    assert {"state.write", "java.call", "runtime.event", "activity.access"} <= set(manifest["permissions"])


@pytest.mark.parametrize("rule", [
    {"source": "state", "key": "result", "path": "value.__bad()", "value": True},
    {"source": "state", "key": "result", "path": "value", "op": "execute"},
    {"source": "events", "path": "ret", "method": {"class": "Foo", "method": "bar"}},
])
def test_invalid_outcome_contract_rejected(rule):
    with pytest.raises(ValueError):
        learning.validate_rules([rule])


def test_missing_null_and_false_are_distinct_outcomes():
    rules = [{"source": "state", "path": "done", "value": None}]
    assert not learning.check_rules(rules, {"state": {}})["verified"]
    assert learning.check_rules(rules, {"state": {"done": None}})["verified"]
    assert not learning.check_rules([{**rules[0], "value": True}], {"state": {"done": 1}})["verified"]


def test_conflicting_state_sources_cannot_be_silently_substituted():
    rules = copy.deepcopy(CHECKS)
    rules[1].update(scope="hook", hook_id="business")
    with pytest.raises(ValueError, match="different scopes"):
        learning.validate_rules(rules)


def test_durable_reservation_stops_duplicates_pending_and_excess_runs(session):
    p = plan()
    first = learning.reserve_run(session, p, {"item_id": 1}, "item:1")
    with pytest.raises(ValueError, match="halted"):
        learning.reserve_run(session, p, {"item_id": 2}, "item:2")
    first["status"] = "verified"
    learning.write(learning.path(session, "runs", first["id"]), first)
    with pytest.raises(ValueError, match="duplicate"):
        learning.reserve_run(session, p, {"item_id": 1}, "item:1")
    p["limits"]["max_runs"] = 1
    with pytest.raises(ValueError, match="limit"):
        learning.reserve_run(session, p, {"item_id": 2}, "item:2")


class FakeDevice:
    def __init__(self):
        self.hooks = {}
        self.events = []
        self.seq = 0
        self.done = False
        self.dispatches = 0
        self.installed = []
        self.guard = {}
        self.success = True
        self.timeout = False
        self.version = "7"
        self.item_id = None

    def get(self, endpoint, params=None):
        if endpoint == "/packages":
            return {"packages": [{"package": "com.example.app", "versionCode": self.version}]}
        if endpoint == "/apk":
            return {"apks": [{"path": "/data/app/base.apk", "name": "base.apk"}]}
        if endpoint == "/runtime_status":
            return {"processes": [{"connected": True, "runtime_command": True, "process": "com.example.app",
                "runtime": {"pid": 1, "guarded_actions": True, "hooks": [{"id": h} for h in self.hooks]}}]}
        if endpoint == "/runtime_programs":
            return {"programs": self.installed}
        raise AssertionError(endpoint)

    def recent(self, limit=200, since_seq=0, stream_id=""):
        events = [e for e in self.events if e["seq"] > since_seq]
        return {"latest_seq": self.seq, "events": events[-limit:] if limit else [],
                "stream_id": "test-stream", "earliest_seq": 1, "cursor_reset": False,
                "truncated": bool(limit and len(events) > limit)}

    def post(self, endpoint, body):
        if endpoint == "/shell":
            return {"rc": 0, "stdout": hashlib.sha256(b"sample").hexdigest() + "  /data/app/base.apk\n"}
        if endpoint == "/hook":
            self.hooks.update({t["id"]: t for t in body["targets"]})
            return {"ok": True}
        if endpoint == "/unhook":
            self.hooks.pop(body["id"], None)
            return {"ok": True}
        if endpoint == "/runtime_program/install":
            self.installed.append({"id": body["manifest"]["id"], "manifest": body["manifest"], "enabled": body["enable"]})
            return {"ok": True}
        assert endpoint == "/runtime_command"
        command = body["command"]
        op = command["op"]
        if op == "context_status":
            result = {"lifecycle": {"activity_class": METHOD["class"]}}
        elif op == "state_get":
            result = {"value": self.guard if command["key"].startswith("action_guard.") else {"done": self.done, "item_id": self.item_id}}
        elif op == "event_emit":
            self.dispatches += 1
            self.done = self.success
            self.item_id = command["payload"]["inputs"]["item_id"]
            self.guard = {"status": "awaiting_verification", "run_id": command["payload"]["run_id"]}
            result = {"listener_count": 1}
        elif op == "activity_action":
            guard = command["actions"][0]
            if guard["action"] == "run_guarded":
                self.dispatches += 1
                if self.timeout:
                    raise TimeoutError("RPC timed out after dispatch")
                self.done = self.success
                self.item_id = guard["actions"][-1]["args"][0]["literal"]
                result = {"registers": {"$guard_result": {"status": "awaiting_verification", "run_id": guard["run_id"]}}}
            else:
                status = "verified" if guard["verified"] else "uncertain"
                result = {"registers": {"$guard_result": {"status": status, "run_id": guard["run_id"]}}}
        else:
            raise AssertionError(op)
        return {"ok": True, "results": [{"ok": True, "result": result}]}

    def demonstrate(self, item):
        for hook, target in list(self.hooks.items()):
            self.seq += 1
            self.events.append({"package": "com.example.app", "pid": 1, "tid": 1, "seq": self.seq,
                "ts": self.seq * 10, "hook_id": hook, "phase": "before", "class": target["class"],
                "method": target["method"], "args": [] if target["class"] == "android.view.View" else
                [{"index": 0, "value": item}, {"index": 1, "value": True}]})


@pytest.fixture
def device(monkeypatch):
    fake = FakeDevice()
    monkeypatch.setattr(action_tools.client, "get_json", fake.get)
    monkeypatch.setattr(action_tools.client, "post_json", fake.post)
    monkeypatch.setattr(action_tools.client, "get_recent", fake.recent)
    return fake


def save_plan(session):
    p = plan()
    learning.write(learning.path(session, "plans", p["id"]), p)
    return p


@pytest.mark.parametrize("mode", ["legacy", "restart", "overflow"])
def test_incomplete_capture_cannot_become_a_demonstration(session, device, monkeypatch, mode):
    begin = action_tools.begin_action_capture(session, "submit", [METHOD])
    assert begin["ok"]
    device.demonstrate(1)
    def recent(**kwargs):
        data = device.recent(**kwargs)
        if mode == "legacy":
            data = {"latest_seq": data["latest_seq"], "events": data["events"]}
        elif mode == "restart":
            data["stream_id"] = "restarted-daemon"
        else:
            data.update(truncated=True, lost_before_cursor=5)
        return data
    monkeypatch.setattr(action_tools.client, "get_recent", recent)
    result = action_tools.finish_action_capture(session, begin["capture_id"])
    assert not result["ok"] and result["status"] == "truncated"
    assert not device.hooks


def test_capture_to_plan_trial_export_install_and_program_execution(session, device):
    ids = []
    for i in (1, 2):
        begin = action_tools.begin_action_capture(session, "submit", [METHOD])
        assert begin["ok"]
        device.demonstrate(i)
        finish = action_tools.finish_action_capture(session, begin["capture_id"])
        assert finish["ok"]
        ids.append(begin["capture_id"])
        assert not device.hooks
    created = action_tools.create_action_plan(session, "submit", ids, METHOD, "activity",
        {"0": {"input": "item_id"}}, CHECKS, {"min_interval_ms": 0, "verification_ms": 0})
    assert created["ok"] and not created["plan"]["unresolved"]
    assert action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3")["dry_run"]
    assert device.dispatches == 0
    run = action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3", dry_run=False)
    assert run["ok"], run
    assert action_tools.export_action_plan(session, "submit")["validated"]
    assert action_tools.install_action_plan(session, "submit")["ok"]
    device.done = False
    installed_run = action_tools.execute_action_plan(session, "submit", {"item_id": 4}, "item:4",
                                                     dry_run=False, use_installed=True)
    assert installed_run["ok"], installed_run


@pytest.mark.parametrize("timeout", [False, True])
def test_failed_or_uncertain_outcome_never_retries(session, device, timeout):
    save_plan(session)
    device.success = False
    device.timeout = timeout
    first = action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3", dry_run=False)
    assert not first["ok"] and first["run"]["status"] == "uncertain"
    second = action_tools.execute_action_plan(session, "submit", {"item_id": 4}, "item:4", dry_run=False)
    assert not second["ok"] and "halted" in second["error"]
    assert device.dispatches == 1
    assert not action_tools.install_action_plan(session, "submit")["ok"]


def test_version_change_blocks_dispatch_and_install(session, device):
    save_plan(session)
    device.version = "8"
    result = action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3", dry_run=False)
    assert not result["ok"] and device.dispatches == 0


def test_preexisting_success_is_not_verified_as_new_work(session, device):
    save_plan(session)
    device.done = True
    device.item_id = 3
    result = action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3", dry_run=False)
    assert not result["ok"] and device.dispatches == 0


def test_a_later_failure_invalidates_earlier_installation_proof(session, device):
    save_plan(session)
    assert action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3", dry_run=False)["ok"]
    device.done = False
    device.success = False
    assert not action_tools.execute_action_plan(session, "submit", {"item_id": 4}, "item:4", dry_run=False)["ok"]
    assert not action_tools.install_action_plan(session, "submit")["ok"]


def test_capture_cancellation_cleans_owned_hooks_and_rejects_overlap(session, device):
    begin = action_tools.begin_action_capture(session, "click", [METHOD])
    assert begin["ok"]
    assert not action_tools.begin_action_capture(session, "other", [METHOD])["ok"]
    assert action_tools.finish_action_capture(session, begin["capture_id"], cancel=True)["ok"]
    assert not device.hooks


def test_same_version_replaced_apk_is_rejected(session, device, monkeypatch):
    save_plan(session)
    old_post = device.post
    def post(endpoint, body):
        if endpoint == "/shell":
            return {"rc": 0, "stdout": hashlib.sha256(b"replaced").hexdigest() + "  /data/app/base.apk\n"}
        return old_post(endpoint, body)
    monkeypatch.setattr(action_tools.client, "post_json", post)
    assert not action_tools.execute_action_plan(session, "submit", {"item_id": 3}, "item:3", dry_run=False)["ok"]
    assert device.dispatches == 0


def test_new_tools_are_registered_with_mcp():
    tools = server.mcp._tool_manager.list_tools()
    assert {t.name for t in tools} >= {f.__name__ for f in action_tools.TOOLS}


def test_install_rejects_plan_changed_after_verification(session, device):
    p = save_plan(session)
    p["verified_run"] = {"plan_digest": learning.plan_digest(p)}
    p["limits"]["max_runs"] += 1
    learning.write(learning.path(session, "plans", p["id"]), p)
    assert not action_tools.install_action_plan(session, "submit")["ok"]


def test_event_verification_filters_other_items_and_other_processes(session, device):
    p = plan()
    callback = {"class": "com.example.Callback", "method": "completed", "params": ["long"]}
    p["checks"] = [{"source": "events", "method": callback, "path": "ret", "value": True,
                    "correlation": {"args[0]": "item_id"}}]
    key = learning.method_key(callback)
    for item, pid in ((9, 1), (3, 2), (3, 1)):
        device.seq += 1
        device.events.append({"seq": device.seq, "package": p["package"], "pid": pid,
                              "hook_id": "outcome", "args": [{"index": 0, "value": item}], "ret": True})
    observed = action_tools._observe(p, p["package"], 0, {"outcome": key}, {"item_id": 3}, 1)
    assert observed["events"][key]["seq"] == 3
    observed["events"] = {"m" + k: v for k, v in observed["events"].items()}
    assert learning.check_rules(action_tools._outcome_rules(p), observed)["verified"]


def test_other_business_item_cannot_satisfy_state_success_checks():
    p = plan()
    observations = {"state": {"result": {"value": {"done": True, "item_id": 99}}}}
    assert not learning.check_rules(action_tools._outcome_rules(p, {"item_id": 42}), observations)["verified"]


def test_dynamic_state_verification_without_identity_remains_a_draft():
    p = learning.build_plan("submit", [sample("a", 1), sample("b", 2)], METHOD,
                            "activity", {"0": {"input": "item_id"}}, [CHECKS[0]])
    assert any("identity" in issue["reason"] for issue in p["unresolved"])
