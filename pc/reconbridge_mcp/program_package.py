"""Runtime Program 可移植签名包、权限扫描与 signer 信任管理。"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .settings import settings

FORMAT = "reconbridge.runtime-program-package"
SCHEMA = 1
_MAX_BUNDLE_BYTES = 4 << 20
_SIGNER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

KNOWN_PERMISSIONS = {
    "hook.java",
    "hook.tamper",
    "runtime.event",
    "runtime.lifecycle",
    "state.write",
    "java.call",
    "java.field_write",
    "java.construct",
    "code.eval_js",
    "code.eval_dex",
    "shell.exec",
    "shell.root",
    "activity.access",
}

_ACTION_PERMISSIONS = {
    "set_state": {"state.write"},
    "remove_state": {"state.write"},
    "clear_state": {"state.write"},
    "increment_state": {"state.write"},
    "append_state": {"state.write"},
    "call_method": {"java.call"},
    "invoke": {"java.call"},
    "set_field": {"java.field_write"},
    "mutate": {"java.field_write"},
    "set_path": {"java.field_write"},
    "mutate_path": {"java.field_write"},
    "construct": {"java.construct"},
    "new_instance": {"java.construct"},
    "eval_js": {"code.eval_js"},
    "js": {"code.eval_js"},
    "eval_dex": {"code.eval_dex"},
    "dex": {"code.eval_dex"},
    "exec_shell": {"shell.exec"},
    "shell": {"shell.exec"},
    "set_arg": {"hook.tamper"},
    "set_result": {"hook.tamper"},
    "replace_return": {"hook.tamper"},
    "emit_event": {"runtime.event"},
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(
            value.encode("ascii"),
            validate=True,
        )
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("无效 Base64 编码") from exc


def _security_root() -> Path:
    root = settings.workdir / ".runtime_program_security"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _signer_dir() -> Path:
    path = _security_root() / "signers"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _trust_path() -> Path:
    return _security_root() / "trusted_signers.json"


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def _write_json(path: Path, value: Any, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, path)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _key_id(public_bytes: bytes) -> str:
    return _sha256(public_bytes)[:24]


def _walk_permissions(node: Any, out: set[str]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_permissions(item, out)
        return
    if not isinstance(node, dict):
        return

    kind = node.get("kind")
    if kind == "java":
        out.add("hook.java")
    if kind == "runtime":
        if "on_event" in node or "event_handlers" in node:
            out.add("runtime.event")
        if "on_lifecycle" in node:
            out.add("runtime.lifecycle")

    if node.get("on_event") is not None or node.get("event_handlers") is not None:
        out.add("runtime.event")
    if node.get("on_lifecycle") is not None:
        out.add("runtime.lifecycle")
    if node.get("state_init") or node.get("state_cleanup"):
        out.add("state.write")

    action = node.get("action")
    if isinstance(action, str):
        out.update(_ACTION_PERMISSIONS.get(action, set()))
        if action in {"exec_shell", "shell"} and bool(node.get("as_root")):
            out.add("shell.root")

    if node.get("target") == "activity":
        out.add("activity.access")

    if (
        node.get("replace_args")
        or node.get("replace_return") is not None
        or node.get("mutate_return")
        or bool(node.get("skip_original"))
    ):
        out.add("hook.tamper")

    for key, value in node.items():
        if key == "permissions":
            continue
        _walk_permissions(value, out)


def required_permissions(manifest: dict[str, Any]) -> list[str]:
    out: set[str] = set()
    _walk_permissions(manifest, out)
    return sorted(out)


def normalize_permissions(
    manifest: dict[str, Any],
    *,
    infer_missing: bool,
) -> dict[str, Any]:
    result = json.loads(json.dumps(manifest, ensure_ascii=False))
    required = required_permissions(result)
    declared_raw = result.get("permissions")

    if declared_raw is None:
        if not infer_missing:
            raise ValueError(
                "manifest.permissions 缺失；签名包必须显式声明实际需要的权限"
            )
        declared = required
        inferred = True
    else:
        if not isinstance(declared_raw, list) or not all(
            isinstance(item, str) for item in declared_raw
        ):
            raise ValueError("manifest.permissions 必须是字符串数组")
        unknown = sorted(set(declared_raw) - KNOWN_PERMISSIONS)
        if unknown:
            raise ValueError("未知 Runtime Program 权限: " + ", ".join(unknown))
        declared = sorted(set(declared_raw))
        inferred = False

    missing = sorted(set(required) - set(declared))
    if missing:
        raise ValueError(
            "manifest.permissions 少声明实际能力: " + ", ".join(missing)
        )

    result["permissions"] = declared
    result["permissions_inferred"] = inferred
    return result


def _trust_store() -> dict[str, Any]:
    data = _read_json(_trust_path(), {"signers": {}})
    if not isinstance(data, dict):
        return {"signers": {}}
    if not isinstance(data.get("signers"), dict):
        data["signers"] = {}
    return data


def trust_signer(public_key_b64: str, label: str = "") -> dict[str, Any]:
    public_bytes = _unb64(public_key_b64)
    if len(public_bytes) != 32:
        raise ValueError("Ed25519 public key 必须是 32 bytes")
    Ed25519PublicKey.from_public_bytes(public_bytes)
    key_id = _key_id(public_bytes)
    store = _trust_store()
    store["signers"][key_id] = {
        "key_id": key_id,
        "label": label or key_id,
        "public_key_b64": public_key_b64,
        "trusted_at": int(time.time() * 1000),
    }
    _write_json(_trust_path(), store)
    return dict(store["signers"][key_id])


def ensure_signer(name: str = "default") -> dict[str, Any]:
    if not _SIGNER_RE.fullmatch(name or ""):
        raise ValueError("signer name 仅允许 1-64 位字母数字 . _ -")
    path = _signer_dir() / f"{name}.json"
    data = _read_json(path, {})
    if isinstance(data, dict) and data.get("private_key_b64"):
        private_bytes = _unb64(str(data["private_key_b64"]))
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    else:
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = _key_id(public_bytes)
    record = {
        "name": name,
        "algorithm": "ed25519",
        "key_id": key_id,
        "private_key_b64": _b64(private_bytes),
        "public_key_b64": _b64(public_bytes),
    }
    _write_json(path, record, private=True)

    store = _trust_store()
    if key_id not in store["signers"]:
        trust_signer(record["public_key_b64"], label=f"local:{name}")

    return record


def signer_status() -> dict[str, Any]:
    local = []
    for path in sorted(_signer_dir().glob("*.json")):
        data = _read_json(path, {})
        if not isinstance(data, dict) or not data.get("public_key_b64"):
            continue
        local.append(
            {
                "name": data.get("name", path.stem),
                "key_id": data.get("key_id", ""),
                "public_key_b64": data.get("public_key_b64", ""),
            }
        )
    trusted = list(_trust_store()["signers"].values())
    trusted.sort(key=lambda item: str(item.get("key_id", "")))
    return {
        "local_signers": local,
        "trusted_signers": trusted,
    }


def _signed_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": bundle.get("format"),
        "schema": bundle.get("schema"),
        "exported_at": bundle.get("exported_at"),
        "program": bundle.get("program"),
        "allowed_packages": bundle.get("allowed_packages"),
        "permissions": bundle.get("permissions"),
        "payload_sha256": bundle.get("payload_sha256"),
    }


def create_bundle(
    program: dict[str, Any],
    *,
    source_package: str,
    allowed_packages: list[str] | None = None,
    signer: str = "default",
) -> dict[str, Any]:
    manifest_raw = program.get("manifest")
    if not isinstance(manifest_raw, dict):
        raise ValueError("program.manifest 缺失")
    manifest = normalize_permissions(manifest_raw, infer_missing=True)
    permissions = list(manifest["permissions"])

    allowed = allowed_packages or [source_package]
    if not isinstance(allowed, list) or not allowed:
        raise ValueError("allowed_packages 至少包含一个包名或 *")
    normalized_allowed = sorted(set(str(item).strip() for item in allowed))
    if any(not item for item in normalized_allowed):
        raise ValueError("allowed_packages 不能包含空字符串")

    payload = {
        "format": FORMAT,
        "schema": SCHEMA,
        "exported_at": int(time.time() * 1000),
        "program": {
            "id": str(program.get("id") or manifest.get("id") or ""),
            "source_package": source_package,
            "source_revision": int(program.get("revision", 0) or 0),
            "enabled": bool(program.get("enabled", True)),
            "manifest": manifest,
        },
        "allowed_packages": normalized_allowed,
        "permissions": permissions,
    }
    payload_hash = _sha256(_canonical(payload))
    bundle = {
        **payload,
        "payload_sha256": payload_hash,
    }

    signer_record = ensure_signer(signer)
    private_key = Ed25519PrivateKey.from_private_bytes(
        _unb64(signer_record["private_key_b64"])
    )
    signature = private_key.sign(_canonical(_signed_payload(bundle)))
    bundle["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer_record["key_id"],
        "public_key_b64": signer_record["public_key_b64"],
        "signature_b64": _b64(signature),
    }
    return bundle


def load_bundle(value: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(value, dict):
        return json.loads(json.dumps(value, ensure_ascii=False))
    if not isinstance(value, str):
        raise ValueError("bundle 必须是 dict、JSON 字符串或本地文件路径")

    text = value.strip()
    if text.startswith("{"):
        if len(text.encode("utf-8")) > _MAX_BUNDLE_BYTES:
            raise ValueError("Runtime Program Package 超过 4 MiB")
        data = json.loads(text)
    else:
        path = Path(text).expanduser().resolve()
        raw = path.read_bytes()
        if len(raw) > _MAX_BUNDLE_BYTES:
            raise ValueError("Runtime Program Package 超过 4 MiB")
        data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Runtime Program Package 顶层必须是 object")
    return data


def verify_bundle(
    value: dict[str, Any] | str,
    *,
    target_package: str = "",
    require_trusted: bool = True,
) -> dict[str, Any]:
    try:
        bundle = load_bundle(value)
        if bundle.get("format") != FORMAT or int(bundle.get("schema", 0)) != SCHEMA:
            raise ValueError("不支持的 Runtime Program Package 格式或 schema")

        program = bundle.get("program")
        if not isinstance(program, dict) or not isinstance(program.get("manifest"), dict):
            raise ValueError("package.program.manifest 缺失")

        manifest = normalize_permissions(
            program["manifest"],
            infer_missing=False,
        )
        required = required_permissions(manifest)
        declared = bundle.get("permissions")
        if not isinstance(declared, list) or not all(
            isinstance(item, str) for item in declared
        ):
            raise ValueError("package.permissions 必须是字符串数组")
        if sorted(set(declared)) != sorted(set(manifest["permissions"])):
            raise ValueError("package.permissions 与 manifest.permissions 不一致")
        missing = sorted(set(required) - set(declared))
        if missing:
            raise ValueError("package.permissions 少声明实际能力: " + ", ".join(missing))

        allowed = bundle.get("allowed_packages")
        if not isinstance(allowed, list) or not all(
            isinstance(item, str) and item for item in allowed
        ):
            raise ValueError("package.allowed_packages 无效")
        if target_package and "*" not in allowed and target_package not in allowed:
            raise ValueError(
                f"签名包不允许安装到目标包 {target_package}"
            )

        payload = {
            "format": bundle.get("format"),
            "schema": bundle.get("schema"),
            "exported_at": bundle.get("exported_at"),
            "program": bundle.get("program"),
            "allowed_packages": bundle.get("allowed_packages"),
            "permissions": bundle.get("permissions"),
        }
        actual_hash = _sha256(_canonical(payload))
        if actual_hash != str(bundle.get("payload_sha256", "")):
            raise ValueError("payload SHA-256 不匹配，包内容已被修改")

        signature = bundle.get("signature")
        if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
            raise ValueError("缺少受支持的 Ed25519 signature")
        public_bytes = _unb64(str(signature.get("public_key_b64", "")))
        if len(public_bytes) != 32:
            raise ValueError("signature public key 长度无效")
        key_id = _key_id(public_bytes)
        if key_id != str(signature.get("key_id", "")):
            raise ValueError("signature key_id 与 public key 不匹配")

        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        try:
            public_key.verify(
                _unb64(str(signature.get("signature_b64", ""))),
                _canonical(_signed_payload(bundle)),
            )
        except InvalidSignature as exc:
            raise ValueError("Ed25519 签名无效") from exc

        trusted = key_id in _trust_store()["signers"]
        if require_trusted and not trusted:
            raise ValueError(
                f"签名有效但 signer {key_id} 尚未加入本机信任列表"
            )

        return {
            "ok": True,
            "trusted": trusted,
            "key_id": key_id,
            "permissions": sorted(set(declared)),
            "allowed_packages": list(allowed),
            "program_id": manifest.get("id", program.get("id", "")),
            "source_package": program.get("source_package", ""),
            "source_revision": int(program.get("source_revision", 0) or 0),
            "manifest": manifest,
            "bundle": bundle,
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "error": str(exc),
        }


def save_bundle(
    bundle: dict[str, Any],
    *,
    output_path: str = "",
) -> Path:
    program = bundle.get("program") or {}
    program_id = str(program.get("id", "program"))
    revision = int(program.get("source_revision", 0) or 0)
    if output_path:
        path = Path(output_path).expanduser().resolve()
    else:
        root = settings.workdir / "runtime_program_packages"
        root.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", program_id)[:64] or "program"
        path = root / f"{safe_id}-r{revision}.rbprog.json"
    _write_json(path, bundle)
    return path
