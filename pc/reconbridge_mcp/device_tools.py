"""Bounded adb/UI Automator/Perfetto and SDK apkanalyzer entrypoints."""
from __future__ import annotations
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from .client import client, ReconError
from .settings import settings
from . import external, workflow_artifacts
from .resource import run_limited, java_memory_env


def run_bytes(argv: list[str], timeout: float = 30, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    """Bound disk output while running; binary stdout never passes through a text shell."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdout=out, stderr=err,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        deadline = time.monotonic() + timeout
        failure = ""
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline:
                    failure = "device command timed out"; break
                if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > max_bytes:
                    failure = "device command output limit exceeded"; break
                time.sleep(.02)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        if failure or os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > max_bytes:
            raise ReconError(failure or "device command output limit exceeded")
        err.seek(0)
        if proc.returncode:
            raise ReconError(err.read(2000).decode("utf-8", "replace") or f"device command exit {proc.returncode}")
        out.seek(0)
        return out.read(max_bytes)


def adb_bytes(*args: str, timeout: float = 30, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    client._resolve_serial()
    return run_bytes([settings.adb, "-s", client._serial, *args], timeout, max_bytes)


def shell(*args: str, timeout: float = 30, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    # adb shell reparses arguments on the device; quote that shell explicitly.
    return adb_bytes("shell", shlex.join(args), timeout=timeout, max_bytes=max_bytes)


def find_apkanalyzer() -> Path | None:
    configured = os.environ.get("RECONBRIDGE_APKANALYZER", "")
    if configured:
        return Path(configured) if Path(configured).is_file() else None
    found = shutil.which("apkanalyzer")
    if found:
        return Path(found)
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    root = Path(sdk) if sdk else Path(settings.adb).parent.parent
    name = "apkanalyzer.bat" if os.name == "nt" else "apkanalyzer"
    candidates = [root / "cmdline-tools/latest/bin" / name, *sorted(root.glob(f"cmdline-tools/*/bin/{name}"), reverse=True)]
    return next((p for p in candidates if p.is_file()), None)


def android_tool_status(probe_device: bool = False) -> dict:
    """Locate SDK apkanalyzer and optionally probe device UI Automator/Perfetto via adb."""
    executable = find_apkanalyzer()
    result = {"apkanalyzer": str(executable) if executable else None,
              "adb": str(settings.adb), "device_probed": probe_device,
              "uiautomator": "unknown", "perfetto": "unknown"}
    if probe_device:
        for name in ("uiautomator", "perfetto"):
            try:
                result[name] = shell("which", name, timeout=10).decode().strip() or None
            except Exception as exc:
                result[name] = {"available": False, "error": str(exc)[:500]}
    return result


def analyze_apk_metadata(apk_path: str, section: str = "summary") -> dict:
    """Run SDK apkanalyzer summary/manifest/permissions/files on a local APK with limits."""
    commands = {"summary": ["apk", "summary"], "manifest": ["manifest", "print"],
                "permissions": ["manifest", "permissions"], "files": ["files", "list"]}
    if section not in commands:
        raise ValueError("section must be summary/manifest/permissions/files")
    apk = Path(apk_path).resolve()
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise ValueError("apk_path must be a local APK file")
    executable = find_apkanalyzer()
    if not executable:
        return {"ok": False, "error": "apkanalyzer missing", "hint": "Install Android SDK command-line tools or set RECONBRIDGE_APKANALYZER"}
    result = run_limited(external._tool_command(executable, *commands[section], str(apk)),
        timeout=60, memory_mb=settings.max_memory_mb, env=java_memory_env(os.environ, 768))
    return {"ok": result.returncode == 0 and not result.timed_out, "section": section,
            "output_tail": result.log_tail, "output_scope": "bounded log tail, may be truncated",
            "exit_code": result.returncode, "timed_out": result.timed_out,
            "memory_limit_enforced": result.memory_limit_enforced}


def capture_perfetto(session_id: str, seconds: int = 10, buffer_mb: int = 8) -> dict:
    """Capture a bounded device Perfetto trace via adb and save it in the session. No upload."""
    if not 1 <= seconds <= 60 or not 1 <= buffer_mb <= 32:
        raise ValueError("seconds must be 1..60; buffer_mb 1..32")
    record, folder = workflow_artifacts.create(session_id, "perfetto")
    remote = f"/data/misc/perfetto-traces/rb-{record['artifact_id']}.perfetto-trace"
    try:
        shell("perfetto", "-o", remote, "-t", f"{seconds}s", "-b", f"{buffer_mb}mb",
              "sched", "freq", "view", "input", timeout=seconds + 20)
        trace = adb_bytes("exec-out", "cat", remote, timeout=30, max_bytes=(buffer_mb + 8) * 1024 * 1024)
        if not trace:
            raise ReconError("Perfetto returned an empty trace")
        (folder / "trace.perfetto-trace").write_bytes(trace)
        record.update(ok=True, duration_seconds=seconds, buffer_mb=buffer_mb,
                      scope="system trace; not restricted to the target package", decoded=False)
    except Exception as exc:
        record.update(ok=False, error=str(exc)[:1000])
    finally:
        try: shell("rm", "-f", remote, timeout=10)
        except Exception: pass
    return workflow_artifacts.finish(record, folder)


def register(mcp) -> None:
    for tool in (android_tool_status, analyze_apk_metadata, capture_perfetto):
        mcp.tool()(tool)
