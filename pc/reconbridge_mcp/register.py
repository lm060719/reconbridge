"""把 reconbridge MCP server 注册进 Claude Code 的用户级配置（~/.claude.json）。

与 scripts/install_mcp.py 的区别：这里是**包内**版本，能在 PyInstaller 冻结后的 exe 里运行，
自动把 entry 的 command 指向 **exe 自身**（`sys.executable`），无需 venv / PYTHONPATH。
源码运行时退回“venv python + -m reconbridge_mcp”的经典 entry。

由 `reconbridge-mcp.exe --register [--transport adb|wifi] [--print-only]` 调用
（server.main 分派），也可 `python -m reconbridge_mcp --register` 直接跑。
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .settings import FROZEN, PC_DIR


def claude_config_path() -> Path:
    return Path.home() / ".claude.json"


def build_entry(transport: str) -> dict:
    """构造 mcpServers.reconbridge 配置项。

    冻结（exe）：command = exe 自身，args = []，无需 PYTHONPATH。
    源码：command = 当前 python 解释器，args = ["-m", "reconbridge_mcp"]，带 PYTHONPATH=pc。
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


def register(transport: str = "adb", print_only: bool = False) -> int:
    entry = build_entry(transport)

    if print_only:
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
    print(f"[OK] 已把 reconbridge 写入 {cfg_path}（用户级，任意目录可用）")
    print(f"    command: {entry['command']}")
    print(f"    transport: {transport}")
    print("[i] 重启 Claude Code，然后 `claude mcp list` 或 /mcp 里应能看到 reconbridge。")
    return 0


def unregister(print_only: bool = False) -> int:
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
        return 0

    if print_only:
        print("[i] 将从 mcpServers 移除 reconbridge（--print-only，未改动）。")
        return 0

    shutil.copy2(cfg_path, cfg_path.with_suffix(".json.bak"))
    print(f"[i] 已备份原配置到 {cfg_path.with_suffix('.json.bak')}")
    del servers["reconbridge"]
    cfg_path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"[OK] 已从 {cfg_path} 移除 reconbridge。重启 Claude Code 生效。")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="reconbridge-mcp",
        description="注册/注销 reconbridge 到 Claude Code 用户级配置（~/.claude.json）",
    )
    ap.add_argument("--register", action="store_true",
                    help="注册（默认动作，可省略）")
    ap.add_argument("--unregister", action="store_true",
                    help="从 Claude Code 配置移除 reconbridge")
    ap.add_argument("--transport", default="adb", choices=["adb", "wifi"],
                    help="设备传输方式，默认 adb（USB，经 adb forward）")
    ap.add_argument("--print-only", action="store_true",
                    help="只打印将要做的改动，不落盘")
    args = ap.parse_args(argv)
    if args.unregister:
        return unregister(args.print_only)
    return register(args.transport, args.print_only)
