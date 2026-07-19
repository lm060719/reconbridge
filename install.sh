#!/usr/bin/env bash
# ReconBridge —— 一键安装 MCP 工具（Linux / macOS）
#
#   1. 在 pc/.venv 建虚拟环境
#   2. 安装 Python 依赖（requirements.txt）
#   3. 把 reconbridge 注册进 AI 客户端用户级配置：
#      Claude Code（~/.claude.json）与/或 ChatGPT Codex（~/.codex/config.toml）
#
# 用法：
#   ./install.sh                 # 默认 adb 传输，both（Claude + Codex）
#   ./install.sh wifi            # 传输
#   ./install.sh adb codex       # 只装 Codex
set -euo pipefail

TRANSPORT="${1:-adb}"
TARGET="${2:-both}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PC="$ROOT/pc"
VENV="$PC/.venv"

echo "== ReconBridge MCP 安装 =="
echo "仓库根: $ROOT"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "未找到 python3，请先安装 Python 3.10+。" >&2
  exit 1
fi

if [ ! -d "$VENV" ]; then
  echo "[1/3] 创建虚拟环境 $VENV ..."
  "$PY" -m venv "$VENV"
else
  echo "[1/3] 虚拟环境已存在，跳过。"
fi
VENV_PY="$VENV/bin/python"

echo "[2/3] 安装依赖 ..."
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -r "$PC/requirements.txt"

echo "[3/3] 注册 MCP（target=$TARGET）..."
"$VENV_PY" "$ROOT/scripts/install_mcp.py" --transport "$TRANSPORT" --target "$TARGET"

echo ""
echo "✓ 完成。重启对应客户端后验证："
echo "  · Claude Code: 'claude mcp list' 或 /mcp（找 reconbridge）"
echo "  · ChatGPT Codex: ~/.codex/config.toml 里 [mcp_servers.reconbridge] 已就绪"
echo "  设备端还需刷入 KernelSU 模块（见 README 的「设备端」章节）。"
