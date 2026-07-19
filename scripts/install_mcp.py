#!/usr/bin/env python3
"""把 reconbridge MCP server 注册进 AI 客户端的用户级配置（源码安装用）。

支持两个客户端（`--target`）：
  - claude —— Claude Code：写 ~/.claude.json 的 mcpServers.reconbridge，
              skill 铺到 ~/.claude/skills/reconbridge/
  - codex  —— ChatGPT Codex：写 ~/.codex/config.toml 的 [mcp_servers.reconbridge]，
              skill 铺到 ~/.codex/skills/reconbridge/
  - both   —— 两个都装（默认）

直接改配置文件而不用客户端自带的 `add` 命令，是因为后者在 Windows / 非 ASCII 路径下
对引号与编码处理有坑。这里用 Python 稳妥地：算出本机绝对路径 → 读入配置（不存在则新建）
→ 写入/更新 reconbridge → 写回前先备份 → 把 skills/reconbridge/ 铺到用户级 skills 目录。

用法（一般由 install.ps1 / install.sh 调用，也可单独跑）：
    python scripts/install_mcp.py                     # 默认 both
    python scripts/install_mcp.py --target codex      # 只装 Codex
    python scripts/install_mcp.py --transport wifi
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PC_DIR = REPO_ROOT / "pc"
SKILL_SRC = REPO_ROOT / "skills" / "reconbridge"

TARGETS = ("claude", "codex", "both")


def venv_python() -> Path:
    """返回 pc/.venv 里的 python 解释器路径（跨平台）。"""
    win = PC_DIR / ".venv" / "Scripts" / "python.exe"
    nix = PC_DIR / ".venv" / "bin" / "python"
    if win.exists():
        return win
    if nix.exists():
        return nix
    print("[!] 未找到 pc/.venv，请先运行 install.ps1 / install.sh 创建虚拟环境。",
          file=sys.stderr)
    return Path(sys.executable)


# ---------------------------------------------------------------- 路径
def claude_config_path() -> Path:
    return Path.home() / ".claude.json"


def codex_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def claude_skill_dir() -> Path:
    return Path.home() / ".claude" / "skills" / "reconbridge"


def codex_skill_dir() -> Path:
    return Path.home() / ".codex" / "skills" / "reconbridge"


# ---------------------------------------------------------------- 客户端探测
def claude_present() -> bool:
    return claude_config_path().exists() or (Path.home() / ".claude").is_dir()


def codex_present() -> bool:
    return (Path.home() / ".codex").is_dir()


_ABSENT_HINT = {
    "claude": "未检测到 Claude Code（~/.claude.json 与 ~/.claude/ 均不存在）",
    "codex": "未检测到 ChatGPT Codex（~/.codex/ 不存在）",
}


def resolve_targets(target: str) -> tuple[list[str], list[str]]:
    """both：只装已检测到的客户端（未装的跳过、不建目录）；两者都没检测到则谁都不写
    （chosen 为空，不凭空造配置）。显式 claude/codex：强制装该项。返回 (要装的, 跳过的)。"""
    if target in ("claude", "codex"):
        return [target], []
    chosen: list[str] = []
    skipped: list[str] = []
    (chosen if claude_present() else skipped).append("claude")
    (chosen if codex_present() else skipped).append("codex")
    return chosen, skipped


# ---------------------------------------------------------------- skill
def install_skill(dst: Path) -> None:
    """把 skills/reconbridge/ 铺到用户级 skills 目录，让新会话在逆向类任务上自动加载工作流。"""
    if not SKILL_SRC.is_dir():
        print("[!] 未找到 skills/reconbridge/，跳过 skill 安装。", file=sys.stderr)
        return
    dst.mkdir(parents=True, exist_ok=True)
    for f in SKILL_SRC.iterdir():
        if f.is_file():
            shutil.copy2(f, dst / f.name)
    print(f"[✓] 已安装 skill 到 {dst}（用户级，新会话自动可用）")


# ---------------------------------------------------------------- entry（两端共用）
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


# ---------------------------------------------------------------- Claude（JSON）
def register_claude(entry: dict) -> int:
    cfg_path = claude_config_path()
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
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
    print(f"[✓] 已把 reconbridge 写入 {cfg_path}（Claude Code，用户级）")
    install_skill(claude_skill_dir())
    print("[i] 重启 Claude Code，然后 `claude mcp list` 或 /mcp 里应能看到 reconbridge。")
    return 0


# ---------------------------------------------------------------- Codex（TOML）
def _toml_string(s: str) -> str:
    """TOML 值序列化：优先字面量单引号串（不转义，适配 Windows 反斜杠路径）；
    含单引号或换行时退回基本串并转义。"""
    if "'" not in s and "\n" not in s and "\r" not in s:
        return "'" + s + "'"
    esc = (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    return '"' + esc + '"'


def _entry_to_toml(name: str, entry: dict) -> str:
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
    out: list[str] = []
    skipping = False
    for line in text.splitlines():
        if _RB_HEADER.match(line):
            skipping = True
            continue
        if skipping:
            if _ANY_HEADER.match(line):
                skipping = False
            else:
                continue
        out.append(line)
    result = "\n".join(out)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.rstrip("\n")


def register_codex(entry: dict) -> int:
    block = _entry_to_toml("reconbridge", entry)
    cfg = codex_config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists():
        try:
            old = cfg.read_text(encoding="utf-8-sig")
        except Exception as e:
            print(f"[x] 无法读取 {cfg}: {e}", file=sys.stderr)
            return 1
        shutil.copy2(cfg, cfg.with_suffix(".toml.bak"))
        print(f"[i] 已备份原配置到 {cfg.with_suffix('.toml.bak')}")
        base = _strip_reconbridge_tables(old)
    else:
        base = ""

    new = (base.rstrip("\n") + "\n\n" + block) if base.strip() else block
    cfg.write_text(new, encoding="utf-8")
    print(f"[✓] 已把 reconbridge 写入 {cfg}（ChatGPT Codex，用户级）")
    install_skill(codex_skill_dir())
    print("[i] 重启 Codex，`[mcp_servers.reconbridge]` 生效后即可用 reconbridge 工具。")
    return 0


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.environ.get("RECONBRIDGE_TARGET", "both"),
                    choices=list(TARGETS),
                    help="目标客户端：claude / codex / both（默认 both）")
    ap.add_argument("--transport", default="adb", choices=["adb", "wifi"],
                    help="设备传输方式，默认 adb（USB，经 adb forward）")
    ap.add_argument("--print-only", action="store_true",
                    help="只打印将要写入的配置，不改文件")
    args = ap.parse_args()
    if args.target not in TARGETS:
        args.target = "both"

    entry = build_entry(args.transport)

    if args.print_only:
        if args.target in ("claude", "both"):
            print("# Claude Code (~/.claude.json):")
            print(json.dumps({"reconbridge": entry}, ensure_ascii=False, indent=2))
        if args.target in ("codex", "both"):
            print("# ChatGPT Codex (~/.codex/config.toml):")
            print(_entry_to_toml("reconbridge", entry), end="")
        return 0

    chosen, skipped = resolve_targets(args.target)
    if not chosen:
        print("[i] 未检测到 Claude Code（~/.claude.json / ~/.claude/）与 "
              "ChatGPT Codex（~/.codex/）——工具已就位，但未写入任何客户端配置。")
        print("    装好客户端后重跑注册，或用 --target claude|codex 强制写入。")
        return 0
    for s in skipped:
        print(f"[i] {_ABSENT_HINT[s]}，跳过（如需强制安装：--target {s}）。")
    rc = 0
    if "claude" in chosen:
        rc = register_claude(entry) or rc
    if "codex" in chosen:
        rc = register_codex(entry) or rc
    print(f"    command: {entry['command']}")
    print(f"    transport: {args.transport}  |  target: {args.target} -> {'+'.join(chosen)}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
