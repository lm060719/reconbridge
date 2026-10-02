"""Runtime Program MCP 包装层测试。"""
from __future__ import annotations

from reconbridge_mcp import server


def test_runtime_program_install_builds_manifest_request(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    manifest = {
        "id": "vip_debug",
        "version": "1.0.0",
        "targets": [
            {
                "id": "check",
                "kind": "java",
                "class": "com.example.PayManager",
                "method": "checkVip",
            }
        ],
        "state_init": [
            {
                "scope": "process",
                "key": "enabled",
                "value": True,
            }
        ],
    }

    server.runtime_program_install(
        "com.example.app",
        manifest,
        enable=True,
        restart=False,
        timeout_ms=4200,
    )

    assert captured["path"] == "/runtime_program/install"
    assert captured["body"] == {
        "package": "com.example.app",
        "manifest": manifest,
        "mode": "install",
        "restart": False,
        "timeout_ms": 4200,
        "enable": True,
    }


def test_runtime_program_replace_supports_revision_guard(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["path"] = path
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    manifest = {
        "id": "vip_debug",
        "version": "1.1.0",
        "targets": [],
    }

    server.runtime_program_replace(
        "com.example.app",
        manifest,
        enable=None,
        expected_revision=7,
        timeout_ms=999999,
    )

    assert captured["path"] == "/runtime_program/install"
    assert captured["body"]["mode"] == "replace"
    assert captured["body"]["expected_revision"] == 7
    assert captured["body"]["timeout_ms"] == 10000
    assert "enable" not in captured["body"]


def test_runtime_program_toggle_rollback_and_status_routes(monkeypatch):
    posts = []
    gets = []

    def fake_post(path, body):
        posts.append((path, body))
        return {"ok": True}

    def fake_get(path, params=None):
        gets.append((path, params))
        return {"count": 1}

    monkeypatch.setattr(server.client, "post_json", fake_post)
    monkeypatch.setattr(server.client, "get_json", fake_get)

    server.runtime_program_enable(
        "com.example.app",
        "vip_debug",
    )
    server.runtime_program_disable(
        "com.example.app",
        "vip_debug",
        restart=True,
    )
    server.runtime_program_rollback(
        "com.example.app",
        "vip_debug",
        timeout_ms=1,
    )
    server.runtime_program_status(
        "com.example.app",
        "vip_debug",
    )

    assert posts[0][0] == "/runtime_program/enable"
    assert posts[1][0] == "/runtime_program/disable"
    assert posts[1][1]["restart"] is True
    assert posts[2][0] == "/runtime_program/rollback"
    assert posts[2][1]["timeout_ms"] == 200
    assert gets == [
        (
            "/runtime_programs",
            {
                "package": "com.example.app",
                "id": "vip_debug",
            },
        )
    ]


def test_runtime_program_manifest_can_be_json_string(monkeypatch):
    captured = {}

    def fake_post(path, body):
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(server.client, "post_json", fake_post)

    server.runtime_program_install(
        "com.example.app",
        '{"id":"demo","targets":[]}',
    )

    assert captured["body"]["manifest"]["id"] == "demo"
