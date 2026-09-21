"""分析会话与轻量源码搜索测试。"""
from __future__ import annotations

from pathlib import Path

from reconbridge_mcp import investigation
from reconbridge_mcp.settings import settings


def test_investigation_persists_target_and_searches_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")

    pkg = "com.example.target"
    apk_dir = tmp_path / pkg / "apk"
    apk_dir.mkdir(parents=True)
    (apk_dir / "base.apk").write_bytes(b"fake-apk")

    source_dir = apk_dir / "base-jadx" / "sources" / "com" / "example"
    source_dir.mkdir(parents=True)
    source_file = source_dir / "PayManager.java"
    source_file.write_text(
        "class PayManager { boolean checkVip() { return premiumStatus; } }\n",
        encoding="utf-8",
    )

    state = investigation.create(pkg, note="unit-test")
    assert state["package"] == pkg
    assert Path(state["primary_apk"]).name == "base.apk"

    status = investigation.status(state["session_id"])
    assert status["jadx_ready"]
    assert status["apk_count"] == 1

    result = investigation.source_search(state["session_id"], "premiumStatus", limit=5)
    assert result["count"] == 1
    assert result["results"][0]["path"].endswith("PayManager.java")

    investigation.add_discovery(
        state["session_id"],
        {"type": "search", "query": "premiumStatus", "count": 1},
    )
    status = investigation.status(state["session_id"])
    assert status["discoveries"][-1]["query"] == "premiumStatus"

    closed = investigation.close(state["session_id"])
    assert closed["closed"] is True


def test_source_method_context_finds_java_method_body(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")

    pkg = "com.example.target"
    apk_dir = tmp_path / pkg / "apk"
    apk_dir.mkdir(parents=True)
    (apk_dir / "base.apk").write_bytes(b"fake-apk")

    source_dir = apk_dir / "base-jadx" / "sources" / "com" / "example"
    source_dir.mkdir(parents=True)
    source_file = source_dir / "PayManager.java"
    source_file.write_text(
        """package com.example;

public class PayManager {
    private boolean premiumStatus;

    public boolean checkVip() {
        if (premiumStatus) {
            return true;
        }
        return false;
    }

    public void caller() {
        checkVip();
    }
}
""",
        encoding="utf-8",
    )

    state = investigation.create(pkg)
    result = investigation.source_method_context(
        state["session_id"],
        "Lcom/example/PayManager;",
        "checkVip",
    )

    assert result["available"]
    assert result["path"].endswith("PayManager.java")
    assert result["declaration_line"] > 0
    assert "public boolean checkVip()" in result["text"]
    assert "return true;" in result["text"]


def test_call_graph_scenario_storage_is_session_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")

    pkg = "com.example.target"
    apk_dir = tmp_path / pkg / "apk"
    apk_dir.mkdir(parents=True)
    (apk_dir / "base.apk").write_bytes(b"fake-apk")

    state = investigation.create(pkg)
    session_id = state["session_id"]

    saved = investigation.save_call_scenario(
        session_id,
        "非会员",
        {
            "graph_fingerprint": "graph-1",
            "hook_fingerprint": "hooks-1",
            "analysis": {
                "event_count": 3,
                "observed_nodes": 3,
                "primary_tid": 7,
            },
        },
    )

    assert saved["name"] == "非会员"
    loaded = investigation.load_call_scenario(session_id, "非会员")
    assert loaded["graph_fingerprint"] == "graph-1"

    listed = investigation.list_call_scenarios(session_id)
    assert len(listed) == 1
    assert listed[0]["observed_nodes"] == 3

    status = investigation.status(session_id)
    assert status["call_scenario_count"] == 1


def test_call_graph_scenario_rejects_unsafe_name(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")

    pkg = "com.example.target"
    (tmp_path / pkg / "apk").mkdir(parents=True)
    state = investigation.create(pkg)

    try:
        investigation.save_call_scenario(
            state["session_id"],
            "../escape",
            {"analysis": {}},
        )
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe scenario name should be rejected")


def test_investigation_rejects_invalid_session_id(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")

    try:
        investigation.load("../escape")
        assert False, "invalid session id should fail"
    except ValueError:
        pass
