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


def test_investigation_rejects_invalid_session_id(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    monkeypatch.setattr(investigation, "_ROOT", tmp_path / ".investigations")

    try:
        investigation.load("../escape")
        assert False, "invalid session id should fail"
    except ValueError:
        pass
