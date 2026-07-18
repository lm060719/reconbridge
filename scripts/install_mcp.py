#!/usr/bin/env python3
"""把 reconbridge MCP server 注册进 Claude Code 的用户级配置（~/.claude.json）。

直接改配置文件而不用 `claude mcp add`，是因为后者在 Windows / 非 ASCII 路径下
对 JSON 引号与编码处理有坑（会写出畸形嵌套结构）。这里用 Python 稳妥地：
  1. 计算出本机绝对路径（venv 里的 python、pc 目录）；
  2. 读入 ~/.claude.json（不存在则新建），确保顶层有 mcpServers；
  3. 写入/更新 mcpServers.reconbridge；
  4. 写回前先备份为 ~/.claude.json.bak。

用法（一般由 install.ps1 / install.sh 调用，也可单独跑）：
    python scripts/install_mcp.py
    python scripts/install_mcp.py --transport wifi   # 可选，默认 adb
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PC_DIR = REPO_ROOT / "pc"


def venv_python() -> Path:
    """返回 pc/.venv 里的 python 解释器路径（跨平台）。"""
    win = PC_DIR / ".venv" / "Scripts" / "python.exe"
    nix = PC_DIR / ".venv" / "bin" / "python"
    if win.exists():
        return win
    if nix.exists():
        return nix
    # venv 还没建：退回当前解释器，让用户先跑 install 脚本
    print("[!] 未找到 pc/.venv，请先运行 install.ps1 / install.sh 创建虚拟环境。",
          file=sys.stderr)
    return Path(sys.executable)


def claude_config_path() -> Path:
    return Path.home() / ".claude.json"


def build_entry(transport: str) -> dict:
    return {
        "command": str(venv_python()),
        "args": ["-m", "reconbridge_mcp"],
        "env": {
            "PYTHONPATH": str(PC_DIR),
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "RECONBRIDGE_TRANSPORT": transport,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--transport", default="adb", choices=["adb", "wifi"],
                    help="设备传输方式，默认 adb（USB，经 adb forward）")
    ap.add_argument("--print-only", action="store_true",
                    help="只打印将要写入的 JSON，不改配置")
    args = ap.parse_args()

    entry = build_entry(args.transport)

    if args.print_only:
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
    print(f"[✓] 已把 reconbridge 写入 {cfg_path}（用户级，任意目录可用）")
    print(f"    command: {entry['command']}")
    print(f"    transport: {args.transport}")
    print("[i] 重启 Claude Code，然后 `claude mcp list` 或 /mcp 里应能看到 reconbridge。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
