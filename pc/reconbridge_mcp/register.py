"""把 reconbridge MCP server 注册进 AI 客户端的用户级配置。

支持两种客户端（`--target`）：
  - claude —— Claude Code，写 JSON：~/.claude.json 的 mcpServers.reconbridge，
              skill 铺到 ~/.claude/skills/reconbridge/
  - codex  —— ChatGPT Codex，写 TOML：~/.codex/config.toml 的 [mcp_servers.reconbridge]，
              skill 铺到 ~/.codex/skills/reconbridge/
  - both   —— 两个都装（默认）

与 scripts/install_mcp.py 的区别：这里是**包内**版本，能在 PyInstaller 冻结后的 exe 里运行，
自动把 entry 的 command 指向 **exe 自身**（`sys.executable`），无需 venv / PYTHONPATH。
源码运行时退回“venv python + -m reconbridge_mcp”的经典 entry。

由 `reconbridge-mcp.exe --register [--target ...] [--transport adb|wifi] [--print-only]` 调用
（server.main 分派），也可 `python -m reconbridge_mcp --register` 直接跑。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

from .settings import FROZEN, PC_DIR

TARGETS = ("claude", "codex", "both")


def default_target() -> str:
    t = os.environ.get("RECONBRIDGE_TARGET", "").strip().lower()
    return t if t in TARGETS else "both"


# ---------------------------------------------------------------- 路径
def claude_config_path() -> Path:
    return Path.home() / ".claude.json"


def claude_skill_dir() -> Path:
    return Path.home() / ".claude" / "skills" / "reconbridge"


def codex_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def codex_skill_dir() -> Path:
    return Path.home() / ".codex" / "skills" / "reconbridge"


# ---------------------------------------------------------------- skill
def _skill_source_dir() -> Path | None:
    """skill 源目录。冻结（exe）时在 PyInstaller 解包根 _MEIPASS/skills/reconbridge
    （见 spec 的 datas）；源码时在仓库 skills/reconbridge。找不到返回 None。"""
    if FROZEN:
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        cand = base / "skills" / "reconbridge"
    else:
        cand = PC_DIR.parent / "skills" / "reconbridge"
    return cand if cand.is_dir() else None


def install_skill(dst: Path) -> None:
    """把 skill 铺到用户级 skills 目录，与 MCP 注册对齐，
    让新会话在逆向类任务上自动加载工作流。找不到源就安静跳过。"""
    src = _skill_source_dir()
    if src is None:
        print("[i] 未找到 skill 源，跳过 skill 安装。")
        return
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.iterdir():
        if f.is_file():
            shutil.copy2(f, dst / f.name)
    print(f"[OK] 已安装 skill 到 {dst}（新会话自动可用）")


def uninstall_skill(dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst, ignore_errors=True)
        print(f"[OK] 已移除 skill {dst}")


# ---------------------------------------------------------------- entry（两端共用）
def build_entry(transport: str) -> dict:
    """构造 reconbridge MCP server 配置项（command/args/env）。

    冻结（exe）：command = exe 自身，args = []，无需 PYTHONPATH。
    源码：command = 当前 python 解释器，args = ["-m", "reconbridge_mcp"]，带 PYTHONPATH=pc。
    这份 dict 对 Claude（JSON）与 Codex（TOML）通用。
    """
    env = {
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "RECONBRIDGE_TRANSPORT": transport,
    }
    if FROZEN:
        return {
            "command": str(Path(sys.executable).resolve()),
            "args": [],
            "env": env,
        }
    env["PYTHONPATH"] = str(PC_DIR)
    return {
        "command": str(Path(sys.executable).resolve()),
        "args": ["-m", "reconbridge_mcp"],
        "env": env,
    }


# ---------------------------------------------------------------- Claude（JSON）
def register_claude(entry: dict, print_only: bool) -> int:
    if print_only:
        print("# Claude Code (~/.claude.json) mcpServers.reconbridge:")
        print(json.dumps({"reconbridge": entry}, ensure_ascii=False, indent=2))
        return 0

    cfg_path = claude_config_path()
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[x] 无法解析 {cfg_path}: {e}", file=sys.stderr)
            print("    请手动检查该文件，或删除后重试。", file=sys.stderr)
            return 1
        shutil.copy2(cfg_path, cfg_path.with_suffix(".json.bak"))
        print(f"[i] 已备份原配置到 {cfg_path.with_suffix('.json.bak')}")
    else:
        data = {}

    if not isinstance(data.get("mcpServers"), dict):
        data["mcpServers"] = {}
    data["mcpServers"]["reconbridge"] = entry

    cfg_path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"[OK] 已把 reconbridge 写入 {cfg_path}（Claude Code，用户级）")
    install_skill(claude_skill_dir())
    print("[i] 重启 Claude Code，然后 `claude mcp list` 或 /mcp 里应能看到 reconbridge。")
    return 0


def unregister_claude(print_only: bool) -> int:
    """从 ~/.claude.json 的 mcpServers 里移除 reconbridge。找不到则安静跳过。"""
    cfg_path = claude_config_path()
    if not cfg_path.exists():
        print(f"[i] {cfg_path} 不存在，无需注销。")
        return 0
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[x] 无法解析 {cfg_path}: {e}", file=sys.stderr)
        return 1

    servers = data.get("mcpServers")
    if not (isinstance(servers, dict) and "reconbridge" in servers):
        print(f"[i] {cfg_path} 里没有 reconbridge，跳过。")
        if not print_only:
            uninstall_skill(claude_skill_dir())
        return 0

    if print_only:
        print("[i] 将从 Claude mcpServers 移除 reconbridge（--print-only，未改动）。")
        return 0

    shutil.copy2(cfg_path, cfg_path.with_suffix(".json.bak"))
    print(f"[i] 已备份原配置到 {cfg_path.with_suffix('.json.bak')}")
    del servers["reconbridge"]
    cfg_path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"[OK] 已从 {cfg_path} 移除 reconbridge。重启 Claude Code 生效。")
    uninstall_skill(claude_skill_dir())
    return 0


# ---------------------------------------------------------------- Codex（TOML）
def _toml_string(s: str) -> str:
    """把字符串序列化为 TOML 值。优先用字面量单引号串（不转义，天然适配 Windows 反斜杠路径）；
    含单引号或换行时退回基本串并转义。"""
    if "'" not in s and "\n" not in s and "\r" not in s:
        return "'" + s + "'"
    esc = (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    return '"' + esc + '"'


def _entry_to_toml(name: str, entry: dict) -> str:
    """把一个 server entry 渲染成 Codex config.toml 的表块。"""
    lines = [f"[mcp_servers.{name}]"]
    lines.append(f"command = {_toml_string(str(entry['command']))}")
    args = entry.get("args", []) or []
    lines.append("args = [" + ", ".join(_toml_string(str(a)) for a in args) + "]")
    env = entry.get("env") or {}
    if env:
        lines.append("")
        lines.append(f"[mcp_servers.{name}.env]")
        for k, v in env.items():
            lines.append(f"{k} = {_toml_string(str(v))}")
    return "\n".join(lines) + "\n"


_RB_HEADER = re.compile(r"^\s*\[\s*mcp_servers\.reconbridge(\.[^\]]*)?\s*\]\s*$")
_ANY_HEADER = re.compile(r"^\s*\[")


def _strip_reconbridge_tables(text: str) -> str:
    """删除已存在的 [mcp_servers.reconbridge] / [mcp_servers.reconbridge.env] 表块，
    其余内容（含用户其它配置与注释）原样保留。表块从其表头行起，到下一个表头或 EOF。"""
    out: list[str] = []
    skipping = False
    for line in text.splitlines():
        if _RB_HEADER.match(line):
            skipping = True
            continue
        if skipping:
            if _ANY_HEADER.match(line):
                skipping = False  # 新表开始，停止跳过并保留此行
            else:
                continue
        out.append(line)
    result = "\n".join(out)
    result = re.sub(r"\n{3,}", "\n\n", result)  # 收敛多余空行
    return result.rstrip("\n")


def register_codex(entry: dict, print_only: bool) -> int:
    block = _entry_to_toml("reconbridge", entry)
    if print_only:
        print("# ChatGPT Codex (~/.codex/config.toml):")
        print(block, end="")
        return 0

    cfg = codex_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        try:
            old = cfg.read_text(encoding="utf-8")
        except Exception as e:
            print(f"[x] 无法读取 {cfg}: {e}", file=sys.stderr)
            return 1
        shutil.copy2(cfg, cfg.with_suffix(".toml.bak"))
        print(f"[i] 已备份原配置到 {cfg.with_suffix('.toml.bak')}")
        base = _strip_reconbridge_tables(old)
    else:
        base = ""

    if base.strip():
        new = base.rstrip("\n") + "\n\n" + block
    else:
        new = block
    cfg.write_text(new, encoding="utf-8")
    print(f"[OK] 已把 reconbridge 写入 {cfg}（ChatGPT Codex，用户级）")
    install_skill(codex_skill_dir())
    print("[i] 重启 Codex，`[mcp_servers.reconbridge]` 生效后即可用 reconbridge 工具。")
    return 0


def unregister_codex(print_only: bool) -> int:
    """从 ~/.codex/config.toml 移除 reconbridge 表块。找不到则安静跳过。"""
    cfg = codex_config_path()
    if not cfg.exists():
        print(f"[i] {cfg} 不存在，无需注销。")
        return 0
    try:
        old = cfg.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[x] 无法读取 {cfg}: {e}", file=sys.stderr)
        return 1

    if "mcp_servers.reconbridge" not in old:
        print(f"[i] {cfg} 里没有 reconbridge，跳过。")
        if not print_only:
            uninstall_skill(codex_skill_dir())
        return 0

    if print_only:
        print("[i] 将从 Codex config.toml 移除 [mcp_servers.reconbridge]（--print-only，未改动）。")
        return 0

    shutil.copy2(cfg, cfg.with_suffix(".toml.bak"))
    print(f"[i] 已备份原配置到 {cfg.with_suffix('.toml.bak')}")
    stripped = _strip_reconbridge_tables(old)
    cfg.write_text(stripped + "\n" if stripped else "", encoding="utf-8")
    print(f"[OK] 已从 {cfg} 移除 reconbridge。重启 Codex 生效。")
    uninstall_skill(codex_skill_dir())
    return 0


# ---------------------------------------------------------------- 分派
def register(transport: str = "adb", print_only: bool = False,
             target: str = "both") -> int:
    entry = build_entry(transport)
    rc = 0
    if target in ("claude", "both"):
        rc = register_claude(entry, print_only) or rc
    if target in ("codex", "both"):
        rc = register_codex(entry, print_only) or rc
    if not print_only:
        print(f"    command: {entry['command']}")
        print(f"    transport: {transport}  |  target: {target}")
    return rc


def unregister(print_only: bool = False, target: str = "both") -> int:
    rc = 0
    if target in ("claude", "both"):
        rc = unregister_claude(print_only) or rc
    if target in ("codex", "both"):
        rc = unregister_codex(print_only) or rc
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="reconbridge-mcp",
        description="注册/注销 reconbridge 到 Claude Code(~/.claude.json) / "
                    "ChatGPT Codex(~/.codex/config.toml) 的用户级配置",
    )
    ap.add_argument("--register", action="store_true",
                    help="注册（默认动作，可省略）")
    ap.add_argument("--unregister", action="store_true",
                    help="从客户端配置移除 reconbridge")
    ap.add_argument("--target", default=default_target(), choices=list(TARGETS),
                    help="目标客户端：claude / codex / both（默认 both，可用 "
                         "RECONBRIDGE_TARGET 环境变量覆盖）")
    ap.add_argument("--transport", default="adb", choices=["adb", "wifi"],
                    help="设备传输方式，默认 adb（USB，经 adb forward）")
    ap.add_argument("--print-only", action="store_true",
                    help="只打印将要做的改动，不落盘")
    args = ap.parse_args(argv)
    if args.unregister:
        return unregister(args.print_only, args.target)
    return register(args.transport, args.print_only, args.target)
