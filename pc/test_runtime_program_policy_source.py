"""Phase 8 daemon permission-policy structural regression tests."""
from __future__ import annotations

from pathlib import Path


DYNAMIC = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "dynamic.cpp"
)


def _source() -> str:
    return DYNAMIC.read_text(encoding="utf-8")


def test_daemon_registers_program_policy_routes():
    src = _source()
    assert '"/runtime_program/policy"' in src
    assert '"/runtime_program/approval"' in src
    assert "handle_runtime_program_policy_set" in src
    assert "handle_runtime_program_approval" in src


def test_program_materialization_checks_policy_every_time():
    src = _source()
    start = src.index("static json compose_hook_config_with_runtime_programs")
    end = src.index("static json runtime_program_materialize_locked", start)
    block = src[start:end]

    assert "runtime_program_policy_evaluate" in block
    assert '"decision"' in block
    assert '!= "allow"' in block


def test_install_enable_and_rollback_all_use_policy_gate():
    src = _source()
    install = src[
        src.index("static void handle_runtime_program_install"):
        src.index("static void handle_runtime_program_toggle")
    ]
    toggle = src[
        src.index("static void handle_runtime_program_toggle"):
        src.index("static void handle_runtime_program_enable")
    ]
    rollback = src[
        src.index("static void handle_runtime_program_rollback"):
        src.index("static void handle_runtime_program_policy_get")
    ]

    assert "runtime_program_policy_gate" in install
    assert "approve_once" in install
    assert "runtime_program_policy_gate" in toggle
    assert "revision_approvals" in toggle
    assert "runtime_program_policy_gate" in rollback
    assert "approve_once" in rollback


def test_policy_tightening_disables_and_cleans_running_programs():
    src = _source()
    start = src.index("static void handle_runtime_program_policy_set")
    end = src.index("static void handle_runtime_program_approval", start)
    block = src[start:end]

    assert 'record["enabled"] = false' in block
    assert 'record["revision_approvals"]' in block
    assert "json::array()" in block
    assert "runtime_program_materialize_locked" in block
    assert "runtime_program_state_apply" in block
