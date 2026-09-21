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
