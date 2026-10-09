"""Run real launcher scripts on each CI OS, including paths with spaces/metacharacters."""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from reconbridge_mcp import external
from reconbridge_mcp.resource import run_limited


@pytest.fixture(autouse=True)
def launcher_python(monkeypatch):
    monkeypatch.setenv("RB_TEST_PYTHON", sys.executable)


def fake_launcher(folder: Path, name: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    helper = folder / "helper.py"
    helper.write_text('''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
if "-d" in args:
    out=Path(args[args.index("-d")+1])/"sources"; out.mkdir(parents=True,exist_ok=True)
    (out/"Sample.java").write_text("class Sample {}")
if os.environ.get("RECON_OUT"):
    Path(os.environ["RECON_OUT"]).write_text(json.dumps({"args":args}))
print(json.dumps(args,ensure_ascii=True))
''', encoding="utf-8")
    if os.name == "nt":
        path = folder / (name + ".bat")
        path.write_text('@echo off\n"%RB_TEST_PYTHON%" "%~dp0helper.py" %*\n', encoding="ascii")
    else:
        path = folder / name
        import shlex
        path.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(helper))} "$@"\n', encoding="utf-8")
        path.chmod(0o755)
    return path


def test_real_launcher_preserves_spaces_and_shell_metacharacters(tmp_path):
    launcher = fake_launcher(tmp_path / "tools with spaces & symbols", "launcher")
    args = ["a b", "x&y", "semi;colon", "中文", "bang!", "(value)"]
    result = run_limited(external._tool_command(launcher, *args), timeout=10, memory_mb=512)
    assert result.returncode == 0, result.log_tail
    assert json.loads(result.log_tail.strip()) == args


def test_jadx_executes_platform_launcher(tmp_path, monkeypatch):
    launcher = fake_launcher(tmp_path / "jadx tools", "jadx")
    monkeypatch.setattr(external, "_find_jadx", lambda: launcher)
    apk = tmp_path / "input & sample.apk"
    apk.write_bytes(b"fixture")
    result = external.decompile_apk(str(apk), str(tmp_path / "output with spaces"))
    assert result["ok"], result
    assert result["java_file_count"] == 1


def test_ghidra_executes_platform_launcher(tmp_path, monkeypatch):
    launcher = fake_launcher(tmp_path / "ghidra tools", "analyzeHeadless")
    monkeypatch.setattr(external, "_find_ghidra_headless", lambda: launcher)
    monkeypatch.setattr(external, "_find_jdk21", lambda: None)
    monkeypatch.setattr(external, "_ensure_ghidra_script", lambda: tmp_path)
    monkeypatch.setattr(external.settings, "native_tools_dir", tmp_path / "native tools")
    so = tmp_path / "lib sample.so"
    so.write_bytes(b"fixture")
    result = external.ghidra_analyze(str(so), {})
    assert result["ok"], result
    assert "-postScript" in result["analysis"]["args"]


def test_posix_command_never_uses_cmd_or_shell(monkeypatch):
    monkeypatch.setattr(external, "os", SimpleNamespace(name="posix"))
    launcher = Path("/tmp/tool with spaces")
    assert external._tool_command(launcher, "a&b", "%arg%") == [str(launcher), "a&b", "%arg%"]


def test_batch_rejects_expansion_before_start(monkeypatch):
    monkeypatch.setattr(external, "os", SimpleNamespace(name="nt"))
    with pytest.raises(ValueError):
        external._tool_command(Path("tool.bat"), "%PATH%")


def test_macos_jdk_layout(tmp_path, monkeypatch):
    home = tmp_path / "jdk-21.jdk/Contents/Home"
    (home / "bin").mkdir(parents=True)
    monkeypatch.setattr(external.settings, "native_tools_dir", tmp_path)
    monkeypatch.setattr(external.settings, "tools_dir", tmp_path)
    assert external._find_jdk21() == home


def test_posix_native_tools_default_is_in_user_home(monkeypatch):
    import importlib
    settings_module = importlib.import_module("reconbridge_mcp.settings")
    monkeypatch.setattr(settings_module, "os", SimpleNamespace(name="posix"))
    assert settings_module._default_native_tools_dir().is_relative_to(Path.home())


def test_sdk_adb_fallback_uses_host_executable(tmp_path, monkeypatch):
    import importlib
    settings_module = importlib.import_module("reconbridge_mcp.settings")
    monkeypatch.setenv("ANDROID_HOME", str(tmp_path))
    monkeypatch.setattr(settings_module.shutil, "which", lambda name: None)
    assert settings_module._default_adb() == str(tmp_path / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb"))
