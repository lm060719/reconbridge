# ReconBridge —— 卸载 PC 侧 MCP 工具（Windows / PowerShell）。
#
# 可直接 `irm <url> | iex` 执行，也可本地 `./uninstall.ps1 [-Purge]`：
#   irm https://github.com/lm060719/reconbridge/releases/latest/download/uninstall.ps1 | iex
#
# 做两件事：
#   1. 从 Claude Code 用户级配置 ~/.claude.json 移除 reconbridge（优先用 exe 自身 --unregister，稳）
#   2. 删除安装目录 %LOCALAPPDATA%\ReconBridge\reconbridge-mcp
#
# 默认保留 work\（拉包 / dump 等数据）与 tools\（jadx/Ghidra）。要连数据一起删：
#   -Purge 或 `irm|iex` 前设 $env:RB_PURGE="1"

param([switch]$Purge)
$ErrorActionPreference = "Stop"

$purgeAll = $Purge -or ($env:RB_PURGE -eq "1")
$dest = Join-Path $env:LOCALAPPDATA "ReconBridge"
$app  = Join-Path $dest "reconbridge-mcp"
$exe  = Join-Path $app  "reconbridge-mcp.exe"

Write-Host "== ReconBridge MCP 卸载 ==" -ForegroundColor Cyan

# 1) 注销 Claude Code 配置
Write-Host "[1/2] 从 Claude Code 注销 ..." -ForegroundColor Yellow
if (Test-Path $exe) {
    & $exe --unregister
} else {
    # exe 不在（已被删过）——PS 兜底：从 ~/.claude.json 移除 reconbridge 键
    $cfg = Join-Path $HOME ".claude.json"
    if (Test-Path $cfg) {
        try {
            $j = Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($j.mcpServers -and ($j.mcpServers.PSObject.Properties.Name -contains "reconbridge")) {
                Copy-Item $cfg "$cfg.bak" -Force
                $j.mcpServers.PSObject.Properties.Remove("reconbridge")
                ($j | ConvertTo-Json -Depth 30) | Set-Content $cfg -Encoding UTF8
                Write-Host "  已从 $cfg 移除 reconbridge（PS 兜底）。"
            } else {
                Write-Host "  $cfg 里没有 reconbridge，跳过。"
            }
        } catch {
            Write-Warning "  无法自动清理 $cfg，请手动删除其中的 reconbridge 项。"
        }
    } else {
        Write-Host "  $cfg 不存在，跳过。"
    }
}

# 2) 删文件
Write-Host "[2/2] 删除安装文件 ..." -ForegroundColor Yellow
if ($purgeAll) {
    if (Test-Path $dest) {
        Remove-Item $dest -Recurse -Force
        Write-Host "  已删除 $dest（含 work\ 与 tools\ 数据）。"
    } else {
        Write-Host "  $dest 不存在。"
    }
} else {
    if (Test-Path $app) {
        Remove-Item $app -Recurse -Force
        Write-Host "  已删除 $app。"
    } else {
        Write-Host "  $app 不存在。"
    }
    if (Test-Path $dest) {
        Write-Host "  保留了 $dest 下的 work\（拉包/dump 数据）与 tools\。要一并删除：-Purge 或 `$env:RB_PURGE=`"1`"。" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "✓ 卸载完成。重启 Claude Code 生效。" -ForegroundColor Green
Write-Host "  注：设备端 KernelSU 模块（若刷过）请在 KernelSU 管理器里单独移除。" -ForegroundColor DarkGray
