"""Runtime Program Package Phase 7 tests."""
from __future__ import annotations

import copy
import json

from reconbridge_mcp import program_package, server
from reconbridge_mcp.settings import settings


def _program() -> dict:
    return {
        "id": "vip_debug",
        "revision": 3,
        "enabled": True,
        "manifest": {
            "id": "vip_debug",
            "name": "VIP Debug",
            "version": "1.0.0",
            "targets": [
                {
                    "id": "vip_hook",
                    "kind": "java",
                    "class": "com.example.UserRepo",
                    "method": "refresh",
                    "skip_original": True,
                    "before_actions": [
                        {
                            "action": "set_field",
                            "target": "this",
                            "field": "vip",
                            "value": True,
                        },
                        {
                            "action": "exec_shell",
                            "cmd": "id",
                            "as_root": True,
                        },
                    ],
                },
                {
                    "id": "listener",
                    "kind": "runtime",
                    "on_event": {
                        "name": "vip.changed",
                        "actions": [
                            {
                                "action": "set_state",
                                "scope": "process",
                                "key": "vip",
                                "value": True,
                            }
                        ],
                    },
                },
            ],
            "state_init": [
                {
                    "scope": "process",
                    "key": "enabled",
                    "value": True,
                }
            ],
            "state_cleanup": [
                {
                    "scope": "process",
                    "key": "enabled",
                }
            ],
        },
    }


def test_permission_scanner_detects_high_risk_actions():
    required = program_package.required_permissions(
        _program()["manifest"]
    )

    assert "hook.java" in required
    assert "hook.tamper" in required
    assert "java.field_write" in required
    assert "shell.exec" in required
    assert "shell.root" in required
    assert "runtime.event" in required
    assert "state.write" in required


def test_signed_bundle_detects_tamper_and_package_scope(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)

    bundle = program_package.create_bundle(
        _program(),
        source_package="com.example.app",
        allowed_packages=["com.example.app"],
    )

    verified = program_package.verify_bundle(
        bundle,
        target_package="com.example.app",
        require_trusted=True,
    )
    assert verified["ok"] is True
    assert verified["trusted"] is True

    wrong_scope = program_package.verify_bundle(
        bundle,
        target_package="com.other.app",
        require_trusted=True,
    )
    assert wrong_scope["ok"] is False
    assert "不允许安装" in wrong_scope["error"]

    tampered = copy.deepcopy(bundle)
    tampered["program"]["manifest"]["name"] = "tampered"
    invalid = program_package.verify_bundle(
        tampered,
        target_package="com.example.app",
        require_trusted=True,
    )
    assert invalid["ok"] is False
    assert "SHA-256" in invalid["error"]


def test_valid_but_untrusted_signer_is_rejected_by_default(tmp_path, monkeypatch):
    signer_root = tmp_path / "signer"
    verifier_root = tmp_path / "verifier"

    monkeypatch.setattr(settings, "workdir", signer_root)
    bundle = program_package.create_bundle(
        _program(),
        source_package="com.example.app",
    )

    monkeypatch.setattr(settings, "workdir", verifier_root)
    untrusted = program_package.verify_bundle(
        bundle,
        target_package="com.example.app",
        require_trusted=False,
    )
    assert untrusted["ok"] is True
    assert untrusted["trusted"] is False

    rejected = program_package.verify_bundle(
        bundle,
        target_package="com.example.app",
        require_trusted=True,
    )
    assert rejected["ok"] is False
    assert "尚未加入本机信任列表" in rejected["error"]

    public_key = bundle["signature"]["public_key_b64"]
    program_package.trust_signer(public_key, label="shared-test")
    trusted = program_package.verify_bundle(
        bundle,
        target_package="com.example.app",
        require_trusted=True,
    )
    assert trusted["ok"] is True
    assert trusted["trusted"] is True


def test_explicit_permissions_cannot_omit_required_capability():
    manifest = copy.deepcopy(_program()["manifest"])
    manifest["permissions"] = ["hook.java"]

    try:
        program_package.normalize_permissions(
            manifest,
            infer_missing=False,
        )
    except ValueError as exc:
        assert "少声明实际能力" in str(exc)
    else:
        raise AssertionError("missing permissions should be rejected")


def test_server_export_verify_and_import_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    program = _program()

    monkeypatch.setattr(
        server,
        "runtime_program_status",
        lambda package, program_id="": {
            "count": 1,
            "package": package,
            "programs": [program],
        },
    )

    exported = server.runtime_program_export(
        "com.example.app",
        "vip_debug",
    )
    assert exported["ok"] is True
    assert exported["trusted"] is True

    output_path = exported["output_path"]
    verified = server.runtime_program_verify_package(
        output_path,
        target_package="com.example.app",
        require_trusted=True,
    )
    assert verified["ok"] is True
    assert verified["program_id"] == "vip_debug"

    captured = {}

    def fake_write(
        package,
        manifest,
        *,
        mode,
        enable,
        restart,
        timeout_ms,
        expected_revision,
        approve_once=None,
    ):
        captured.update(
            {
                "package": package,
                "manifest": manifest,
                "mode": mode,
                "enable": enable,
                "restart": restart,
                "timeout_ms": timeout_ms,
                "expected_revision": expected_revision,
            }
        )
        return {"ok": True, "program": {"id": manifest["id"]}}

    monkeypatch.setattr(server, "_runtime_program_write", fake_write)
    imported = server.runtime_program_import(
        "com.example.app",
        output_path,
        mode="install",
    )

    assert imported["ok"] is True
    assert captured["package"] == "com.example.app"
    assert captured["mode"] == "install"
    assert captured["manifest"]["permissions"]
    assert captured["manifest"]["permissions_inferred"] is False
    assert imported["package_verification"]["trusted"] is True
