"""Phase 5 Runtime Command MCP 包装层测试。"""
from __future__ import annotations

from reconbridge_mcp import server


def test_runtime_state_set_builds_expected_command(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return {"ok": True, "results": []}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    result = server.runtime_state_set(
        "com.example.app",
        key="profile",
        value={"vip": True, "roles": ["user", "tester"]},
        scope="hook",
        hook_id="vip_hook",
        process="com.example.app:core",
        timeout_ms=4200,
    )

    assert result["ok"] is True
    assert captured["path"] == "/runtime_command"
    assert captured["body"] == {
        "package": "com.example.app",
        "process": "com.example.app:core",
        "timeout_ms": 4200,
        "command": {
            "op": "state_set",
            "scope": "hook",
            "key": "profile",
            "value": {
                "vip": True,
                "roles": ["user", "tester"],
            },
            "hook_id": "vip_hook",
        },
    }


def test_runtime_event_emit_preserves_structured_payload(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    server.runtime_event_emit(
        "com.example.app",
        name="debug.toggle",
        payload={
            "enabled": True,
            "meta": {"value": "raw"},
        },
        source_hook="pc-test",
    )

    assert captured["path"] == "/runtime_command"
    assert captured["body"]["command"] == {
        "op": "event_emit",
        "name": "debug.toggle",
        "payload": {
            "enabled": True,
            "meta": {"value": "raw"},
        },
        "source_hook": "pc-test",
    }


def test_runtime_activity_action_rejects_non_object_items(monkeypatch):
    called = False

    def fake_post(path, body):
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    result = server.runtime_activity_action(
        "com.example.app",
        actions=[{"action": "set_state"}, "bad"],
    )

    assert result["ok"] is False
    assert "actions" in result["error"]
    assert called is False


def test_runtime_command_timeout_is_clamped(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    server.runtime_context_status(
        "com.example.app",
        timeout_ms=999999,
    )

    assert captured["body"]["timeout_ms"] == 10000


def test_runtime_state_remove_increment_append_build_expected_commands(monkeypatch):
    calls = []

    def fake_post(path, body):
        calls.append((path, body))
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    server.runtime_state_remove(
        "com.example.app",
        key="token",
        scope="hook",
        hook_id="vip_hook",
        process="com.example.app:core",
        timeout_ms=4200,
    )
    server.runtime_state_increment(
        "com.example.app",
        key="hits",
        delta=2.5,
    )
    server.runtime_state_append(
        "com.example.app",
        key="items",
        value={"id": 7},
    )

    assert calls[0] == (
        "/runtime_command",
        {
            "package": "com.example.app",
            "timeout_ms": 4200,
            "process": "com.example.app:core",
            "command": {
                "op": "state_remove",
                "scope": "hook",
                "key": "token",
                "hook_id": "vip_hook",
            },
        },
    )
    assert calls[1][1]["command"] == {
        "op": "state_increment",
        "scope": "process",
        "key": "hits",
        "delta": 2.5,
        "hook_id": "",
    }
    assert calls[2][1]["command"] == {
        "op": "state_append",
        "scope": "process",
        "key": "items",
        "value": {"id": 7},
        "hook_id": "",
    }


def test_runtime_command_minimum_timeout_is_clamped(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    server.runtime_state_get(
        "com.example.app",
        key="x",
        timeout_ms=1,
    )

    assert captured["body"]["timeout_ms"] == 200


def test_runtime_program_policy_tools_build_expected_requests(monkeypatch):
    calls = []

    def fake_get(path, params=None):
        calls.append(("GET", path, params))
        return {"ok": True}

    def fake_post(path, body):
        calls.append(("POST", path, body))
        return {"ok": True}

    monkeypatch.setattr(server.client, "get_json", fake_get)
    monkeypatch.setattr(server.client, "post_json", fake_post)

    server.runtime_program_policy_status("com.example.app")
    server.runtime_program_policy_set(
        "com.example.app",
        default_action="ask",
        permissions={
            "shell.root": "deny",
            "code.eval_dex": "ask",
        },
        clear_approvals=True,
        timeout_ms=4200,
    )
    server.runtime_program_approve(
        "com.example.app",
        "vip_debug",
        ["code.eval_dex"],
    )
    server.runtime_program_revoke_approval(
        "com.example.app",
        "vip_debug",
        ["code.eval_dex"],
    )

    assert calls[0] == (
        "GET",
        "/runtime_program/policy",
        {"package": "com.example.app"},
    )
    assert calls[1] == (
        "POST",
        "/runtime_program/policy",
        {
            "package": "com.example.app",
            "permissions": {
                "shell.root": "deny",
                "code.eval_dex": "ask",
            },
            "clear_approvals": True,
            "timeout_ms": 4200,
            "default": "ask",
        },
    )
    assert calls[2][1] == "/runtime_program/approval"
    assert calls[2][2]["revoke"] is False
    assert calls[2][2]["permissions"] == ["code.eval_dex"]
    assert calls[3][2]["revoke"] is True


def test_runtime_program_lifecycle_forwards_approve_once(monkeypatch):
    calls = []

    def fake_post(path, body):
        calls.append((path, body))
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    manifest = {
        "id": "vip_debug",
        "targets": [],
    }
    server.runtime_program_install(
        "com.example.app",
        manifest,
        approve_once=["code.eval_dex"],
    )
    server.runtime_program_replace(
        "com.example.app",
        manifest,
        approve_once=["code.eval_js"],
    )
    server.runtime_program_enable(
        "com.example.app",
        "vip_debug",
        approve_once=["shell.exec"],
    )
    server.runtime_program_rollback(
        "com.example.app",
        "vip_debug",
        approve_once=["java.field_write"],
    )

    assert calls[0][1]["approve_once"] == ["code.eval_dex"]
    assert calls[1][1]["approve_once"] == ["code.eval_js"]
    assert calls[2][1]["approve_once"] == ["shell.exec"]
    assert calls[3][1]["approve_once"] == ["java.field_write"]
