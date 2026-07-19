# ReconBridge - uninstall the PC-side MCP tool (Windows / PowerShell).
#
# Run via `irm <url> | iex`, or locally `./uninstall.ps1 [-Purge]`:
#   irm https://github.com/lm060719/reconbridge/releases/latest/download/uninstall.ps1 | iex
#
# Does two things:
#   1. remove reconbridge from the client config(s): Claude Code (~/.claude.json)
#      and/or ChatGPT Codex (~/.codex/config.toml)  (prefer exe --unregister)
#   2. delete the install dir %LOCALAPPDATA%\ReconBridge\reconbridge-mcp
#
# Keeps work\ (pulled apks / dumps) and tools\ (jadx/Ghidra) by default.
# To wipe those too: -Purge, or set $env:RB_PURGE="1" before piping to iex.
#   RB_TARGET = both (default) | claude | codex   which client(s) to unregister from
#
# NOTE: keep this script pure ASCII (see install.ps1 for why: irm|iex encoding).

param([switch]$Purge)
$ErrorActionPreference = "Stop"

$purgeAll = $Purge -or ($env:RB_PURGE -eq "1")
$target = if ($env:RB_TARGET) { $env:RB_TARGET } else { "both" }
$dest = Join-Path $env:LOCALAPPDATA "ReconBridge"
$app  = Join-Path $dest "reconbridge-mcp"
$exe  = Join-Path $app  "reconbridge-mcp.exe"

Write-Host "== ReconBridge MCP uninstall ==" -ForegroundColor Cyan

# 1) unregister from the selected client(s)
Write-Host "[1/2] unregistering (target=$target) ..." -ForegroundColor Yellow
if (Test-Path $exe) {
    & $exe --unregister --target $target
} else {
    # exe already gone - PS fallback: clean the config file(s) directly
    if ($target -eq "both" -or $target -eq "claude") {
        $cfg = Join-Path $HOME ".claude.json"
        if (Test-Path $cfg) {
            try {
                $j = Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($j.mcpServers -and ($j.mcpServers.PSObject.Properties.Name -contains "reconbridge")) {
                    Copy-Item $cfg "$cfg.bak" -Force
                    $j.mcpServers.PSObject.Properties.Remove("reconbridge")
                    ($j | ConvertTo-Json -Depth 30) | Set-Content $cfg -Encoding UTF8
                    Write-Host "  removed reconbridge from $cfg (PS fallback)."
                } else {
                    Write-Host "  no reconbridge in $cfg, skipped."
                }
            } catch {
                Write-Warning "  could not auto-clean $cfg; please remove the reconbridge entry manually."
            }
        } else {
            Write-Host "  $cfg not found, skipped."
        }
    }
    if ($target -eq "both" -or $target -eq "codex") {
        # PS fallback for Codex config.toml: drop the [mcp_servers.reconbridge*] table blocks.
        $ctoml = Join-Path $HOME ".codex\config.toml"
        if (Test-Path $ctoml) {
            try {
                $raw = Get-Content $ctoml -Raw -Encoding UTF8
                if ($raw -match "mcp_servers\.reconbridge") {
                    Copy-Item $ctoml "$ctoml.bak" -Force
                    $lines = $raw -split "\r?\n"
                    $out = New-Object System.Collections.Generic.List[string]
                    $skip = $false
                    foreach ($ln in $lines) {
                        if ($ln -match '^\s*\[\s*mcp_servers\.reconbridge(\.[^\]]*)?\s*\]\s*$') { $skip = $true; continue }
                        if ($skip) { if ($ln -match '^\s*\[') { $skip = $false } else { continue } }
                        $out.Add($ln)
                    }
                    ($out -join "`n").TrimEnd("`n") + "`n" | Set-Content $ctoml -Encoding UTF8 -NoNewline
                    Write-Host "  removed reconbridge from $ctoml (PS fallback)."
                } else {
                    Write-Host "  no reconbridge in $ctoml, skipped."
                }
            } catch {
                Write-Warning "  could not auto-clean $ctoml; please remove the [mcp_servers.reconbridge] block manually."
            }
        } else {
            Write-Host "  $ctoml not found, skipped."
        }
    }
}

# 1b) remove the skill dir(s) (exe --unregister already does this; this is a
#     safety net for the PS fallback path where the exe was already gone).
$skillDirs = @()
if ($target -eq "both" -or $target -eq "claude") { $skillDirs += (Join-Path $HOME ".claude\skills\reconbridge") }
if ($target -eq "both" -or $target -eq "codex")  { $skillDirs += (Join-Path $HOME ".codex\skills\reconbridge") }
foreach ($skill in $skillDirs) {
    if (Test-Path $skill) {
        Remove-Item $skill -Recurse -Force
        Write-Host "  removed skill $skill"
    }
}

# 2) delete files
Write-Host "[2/2] deleting install files ..." -ForegroundColor Yellow
if ($purgeAll) {
    if (Test-Path $dest) {
        Remove-Item $dest -Recurse -Force
        Write-Host "  deleted $dest (including work\ and tools\ data)."
    } else {
        Write-Host "  $dest not found."
    }
} else {
    if (Test-Path $app) {
        Remove-Item $app -Recurse -Force
        Write-Host "  deleted $app."
    } else {
        Write-Host "  $app not found."
    }
    if (Test-Path $dest) {
        Write-Host "  kept work\ and tools\ under $dest. To wipe too: -Purge or `$env:RB_PURGE=`"1`"." -ForegroundColor DarkGray
    }
}

# remove the install dir from the user PATH (added by install.ps1)
$pathCur = [Environment]::GetEnvironmentVariable("Path", "User")
if ($pathCur -and (($pathCur -split ';') -contains $app)) {
    $newPath = (($pathCur -split ';') | Where-Object { $_ -ne $app }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "  removed from user PATH: $app"
}

Write-Host ""
Write-Host "OK - uninstall complete. Restart the client(s) (Claude Code / Codex) to take effect." -ForegroundColor Green
Write-Host "  Note: remove the device-side KernelSU module (if flashed) in the KernelSU manager." -ForegroundColor DarkGray
