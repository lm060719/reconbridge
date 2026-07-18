# ReconBridge —— 一键安装 MCP 工具（Windows / PowerShell）
#
#   1. 在 pc/.venv 建虚拟环境
#   2. 安装 Python 依赖（requirements.txt）
#   3. 把 reconbridge 注册进 Claude Code 用户级配置（~/.claude.json）
#
# 用法：
#   ./install.ps1                # 默认 adb 传输
#   ./install.ps1 -Transport wifi
#
# 装完重启 Claude Code，任意目录下都能用 reconbridge（无需 cd 到本仓库）。

param(
    [ValidateSet("adb", "wifi")]
    [string]$Transport = "adb"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Pc   = Join-Path $Root "pc"
$Venv = Join-Path $Pc ".venv"

Write-Host "== ReconBridge MCP 安装 ==" -ForegroundColor Cyan
Write-Host "仓库根: $Root"

# 1) 找一个可用的 python
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue) }
if (-not $py) {
    Write-Error "未找到 python，请先安装 Python 3.10+ 并加入 PATH。"
    exit 1
}
$pyExe = $py.Source

# 2) 建虚拟环境
if (-not (Test-Path $Venv)) {
    Write-Host "[1/3] 创建虚拟环境 $Venv ..." -ForegroundColor Yellow
    & $pyExe -m venv $Venv
} else {
    Write-Host "[1/3] 虚拟环境已存在，跳过。" -ForegroundColor Yellow
}
$venvPy = Join-Path $Venv "Scripts\python.exe"

# 3) 装依赖
Write-Host "[2/3] 安装依赖 ..." -ForegroundColor Yellow
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -r (Join-Path $Pc "requirements.txt")

# 4) 注册 MCP
Write-Host "[3/3] 注册 MCP 到 Claude Code ..." -ForegroundColor Yellow
& $venvPy (Join-Path $Root "scripts\install_mcp.py") --transport $Transport

Write-Host ""
Write-Host "✓ 完成。重启 Claude Code 后用 ``claude mcp list`` 或 /mcp 验证。" -ForegroundColor Green
Write-Host "  设备端还需刷入 KernelSU 模块（见 README 的「设备端」章节）。" -ForegroundColor Green
