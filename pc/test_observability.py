import json
import pytest

from reconbridge_mcp import observability as obs, jni, investigation, server


def snapshot(seq=0, events=None, **overrides):
    return {"latest_seq": seq, "stream_id": "epoch", "earliest_seq": 1,
            "cursor_reset": False, "truncated": False, "events": events or [], **overrides}


def test_registration():
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert {"diagnose_target", "event_stream_status", "capture_event_window",
            "configure_jni_capture", "inspect_jni_bindings"} <= names


@pytest.mark.parametrize("data,epoch,complete", [
    ({"latest_seq": 9}, "", None),
    (snapshot(9), "epoch", True),
    (snapshot(9, truncated=True, lost_before_cursor=2), "epoch", False),
    (snapshot(20, stream_id="new"), "epoch", False),
    (snapshot(1), "epoch", False),
])
def test_integrity_never_calls_unknown_or_restarted_data_complete(data, epoch, complete):
    assert obs.event_integrity(data, 3, epoch)["complete"] is complete


def test_recent_tool_preserves_metadata(monkeypatch):
    monkeypatch.setattr(server.client, "get_recent", lambda **kw: snapshot(20, truncated=True))
    assert server.recent_events()["truncated"] is True


def test_diagnostic_preserves_partial_results_and_redacts_token(monkeypatch):
    monkeypatch.setattr(obs.external, "toolchain_status", lambda: {"jadx": "jadx", "androguard": "4"})
    monkeypatch.setattr(obs.client, "_token", "SECRET-TOKEN")
    monkeypatch.setattr(obs.client, "get_json", lambda *args: (_ for _ in ()).throw(RuntimeError("SECRET-TOKEN offline")))
    result = obs.diagnose_target("com.example.app")
    assert not result["ok"]
    assert result["checks"][0]["status"] == "ok"
    assert "SECRET-TOKEN" not in json.dumps(result)


def test_diagnostic_does_not_infer_disabled_scope(monkeypatch):
    monkeypatch.setattr(obs.external, "toolchain_status", lambda: {"jadx": "jadx", "androguard": "4"})
    responses = {"/health": {"status": "ok"}, "/packages": {"packages": [{"package": "com.example.app"}]},
                 "/hooks": {"hooks": []}, "/runtime_status": {"processes": []}}
    monkeypatch.setattr(obs.client, "get_json", lambda path, params=None: responses[path])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: snapshot())
    result = obs.diagnose_target("com.example.app")
    check = next(c for c in result["checks"] if c["check"] == "java_runtime")
    assert check["status"] == "warning"
    assert "不能仅凭无连接" in check["hint"]


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setattr(investigation, "_ROOT", tmp_path)
    monkeypatch.setattr(obs.settings, "workdir", tmp_path)
    return investigation.create("com.example.app")["session_id"]


def test_archive_filters_after_advancing_global_cursor(session, monkeypatch):
    calls = iter([snapshot(7), snapshot(9, [{"package": "other", "seq": 8},
        {"package": "com.example.app:worker", "seq": 9}])])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: next(calls))
    result = obs.capture_event_window(session, seconds=0)
    assert result["ok"] and result["count"] == 1 and result["end_seq"] == 9
    from pathlib import Path
    assert json.loads(Path(result["path"]).read_text(encoding="utf-8"))["seq"] == 9


def test_archive_marks_gap_even_when_no_target_event_survives(session, monkeypatch):
    calls = iter([snapshot(1), snapshot(500, truncated=True, lost_before_cursor=99)])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: next(calls))
    result = obs.capture_event_window(session, seconds=0)
    assert not result["ok"] and result["complete"] is False and result["issues"]


def test_archive_keeps_partial_file_on_transport_failure(session, monkeypatch):
    calls = iter([snapshot(), RuntimeError("disconnected")])
    def recent(**kw):
        value = next(calls)
        if isinstance(value, Exception): raise value
        return value
    monkeypatch.setattr(obs.client, "get_recent", recent)
    result = obs.capture_event_window(session, seconds=0)
    assert not result["ok"] and result["issues"][0]["reason"] == "transport_error"


def test_archive_limit_is_reported_and_never_silent(session, monkeypatch):
    calls = iter([snapshot(), snapshot(2, [{"package": "com.example.app", "seq": 1},
                                        {"package": "com.example.app", "seq": 2}])])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: next(calls))
    result = obs.capture_event_window(session, seconds=0, max_events=1)
    assert not result["ok"] and result["count"] == 1
    assert result["issues"] == [{"reason": "max_events"}]


def test_jni_capture_is_opt_in_append_and_not_claimed_live(monkeypatch):
    calls = []
    monkeypatch.setattr(jni.client, "get_json", lambda *args: {"capabilities": {"jni_observer": 1}})
    monkeypatch.setattr(jni.client, "post_json", lambda path, body: (calls.append((path, body)) or {"ok": True}))
    result = jni.configure_jni_capture("com.example.app")
    assert calls[0][1] == {"package": "com.example.app", "mode": "append", "restart": False,
                          "targets": [{"id": "__rb_jni", "kind": "jni"}]}
    assert result["runtime_effect_confirmed"] is False
    jni.configure_jni_capture("com.example.app", enable=False)
    assert calls[1] == ("/unhook", {"package": "com.example.app", "id": "__rb_jni"})


def test_jni_unsupported_daemon_does_not_write_config(monkeypatch):
    monkeypatch.setattr(jni.client, "get_json", lambda *args: {})
    monkeypatch.setattr(jni.client, "post_json", lambda *args: pytest.fail("must not mutate"))
    assert not jni.configure_jni_capture("com.example.app")["ok"]


def test_jni_inspection_is_read_only(monkeypatch):
    monkeypatch.setattr(jni.client, "post_json", lambda *args: pytest.fail("must not mutate"))
    monkeypatch.setattr(jni.client, "get_json", lambda path, params: {"path": path, "params": params})
    assert jni.inspect_jni_bindings("com.example.app")["path"] == "/jni/bindings"
    with pytest.raises(ValueError): jni.inspect_jni_bindings("../app")


def test_client_sends_epoch(monkeypatch):
    monkeypatch.setattr(obs.client, "get_json", lambda path, params: params)
    assert obs.client.get_recent(0, 5, "old")["stream_id"] == "old"


@pytest.mark.parametrize("runtime,expected", [
    ({"native_status_version": 1, "hooks": [{"id": "n1", "status": "installed"}]}, "ok"),
    ({"native_status_version": 1, "hooks": [{"id": "n1", "status": "pending"}]}, "warning"),
    ({"native_status_version": 1, "hooks": [{"id": "n1", "status": "installing"}]}, "warning"),
    ({"native_status_version": 1, "hooks": [{"id": "n1", "status": "failed", "detail": {"code": -7}}]}, "warning"),
    ({"native_status_version": 1, "hooks": [{"id": "n1", "status": "timeout"}]}, "warning"),
    ({"native_status_version": 1, "hooks": [{"id": "n1", "status": "rejected"}]}, "warning"),
    ({"native_status_version": 1, "hooks": [{"id": "old", "status": "installed"}]}, "warning"),
    ({"engine": {"status": "failed", "error": "missing library"}}, "error"),
    ({"configuration": {"status": "failed", "error": "bad offset"}}, "error"),
    ({"jni_observers": []}, "warning"),
])
def test_native_diagnostic_matches_desired_to_actual(monkeypatch, runtime, expected):
    monkeypatch.setattr(obs.external, "toolchain_status", lambda: {})
    responses = {"/health": {"status": "ok"}, "/packages": {"packages": []},
        "/hooks": {"hooks": [{"package": "com.example.app", "targets": [{"id": "n1", "lib": "libx.so"}]}]},
        "/runtime_status": {"processes": [{"connected": True, "process": "com.example.app", "runtime": runtime}]}}
    monkeypatch.setattr(obs.client, "get_json", lambda path, params=None: responses[path])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: snapshot())
    check = next(c for c in obs.diagnose_target("com.example.app")["checks"] if c["check"] == "native_runtime")
    assert check["status"] == expected
    assert check["detail"]["runtime"] == runtime
    assert check["detail"]["missing_ids"] == ([] if expected == "ok" else ["n1"])


@pytest.mark.parametrize("rows,desired,expected", [
    ([{"connected": True, "runtime": {"kind": "native", "jni_observers": []}}], [], "unknown"),
    ([], [{"id": "n1", "kind": "native"}], "warning"),
    ([{"connected": False, "runtime": {"native_status_version": 1}}], [], "warning"),
])
def test_native_diagnostic_does_not_call_legacy_or_absent_runtime_healthy(monkeypatch, rows, desired, expected):
    monkeypatch.setattr(obs.external, "toolchain_status", lambda: {})
    responses = {"/health": {"status": "ok"}, "/packages": {"packages": []},
        "/hooks": {"hooks": [{"package": "com.example.app", "targets": desired}]},
        "/runtime_status": {"processes": rows}}
    monkeypatch.setattr(obs.client, "get_json", lambda path, params=None: responses[path])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: snapshot())
    check = next(c for c in obs.diagnose_target("com.example.app")["checks"] if c["check"] == "native_runtime")
    assert check["status"] == expected


@pytest.mark.parametrize("row", [
    {"kind": "native", "live_reconcile": True, "runtime": None},
    {"live_reconcile": True, "runtime": {"kind": "native", "native_status_version": 2}},
    {"kind": "native", "live_reconcile": True, "runtime_command": False},
])
def test_live_native_connection_is_not_misclassified_as_java(row):
    assert obs.is_native_runtime(row)
    assert not obs.is_native_runtime({"live_reconcile": True, "runtime": {"hooks": []}})


def test_v2_diagnostic_ignores_retained_disabled_hooks(monkeypatch):
    monkeypatch.setattr(obs.external, "toolchain_status", lambda: {})
    responses = {"/health": {"status": "ok"}, "/packages": {"packages": []}, "/hooks": {"hooks": []},
        "/runtime_status": {"processes": [{"kind": "native", "connected": True, "live_reconcile": True,
            "runtime": {"kind": "native", "native_status_version": 2, "hooks": [],
                        "retained_hooks": [{"id": "removed", "status": "disabled"}]}}]}}
    monkeypatch.setattr(obs.client, "get_json", lambda path, params=None: responses[path])
    monkeypatch.setattr(obs.client, "get_recent", lambda **kw: snapshot())
    checks = obs.diagnose_target("com.example.app")["checks"]
    native = next(c for c in checks if c["check"] == "native_runtime")
    assert native["status"] == "ok" and native["detail"]["installed_ids"] == []
    assert not any(c["check"] == "java_hooks" for c in checks)
    responses["/runtime_status"]["processes"][0]["runtime"]["configuration"] = {"jni_restart_required": True}
    native = next(c for c in obs.diagnose_target("com.example.app")["checks"] if c["check"] == "native_runtime")
    assert native["status"] == "warning"
