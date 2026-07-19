# ReconBridge - one-line online installer for the PC-side MCP tool (Windows / PowerShell).
#
# Run directly via `irm <url> | iex` (no repo clone needed):
#   irm https://github.com/lm060719/reconbridge/releases/latest/download/install.ps1 | iex
#
# Steps:
#   1. download reconbridge-mcp-win64.zip from the GitHub Release (onedir-packaged exe)
#   2. extract to %LOCALAPPDATA%\ReconBridge\
#   3. run reconbridge-mcp.exe --register to write the client config(s):
#        Claude Code (~/.claude.json) and/or ChatGPT Codex (~/.codex/config.toml)
#
# Optional env vars (set before piping to iex):
#   RB_TRANSPORT = adb (default) | wifi
#   RB_TARGET    = both (default) | claude | codex   which client(s) to register into
#   RB_REPO      = override repo (default lm060719/reconbridge)
#   RB_ASSET_URL = direct zip URL (skip Release lookup; may be a local file for testing)
#
# NOTE: keep this script pure ASCII. `irm | iex` decodes the downloaded text with the
# PS 5.1 default encoding (no charset from GitHub), so non-ASCII would render as mojibake,
# and a UTF-8 BOM would make the first line fail under iex. ASCII avoids both.

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$transport = if ($env:RB_TRANSPORT) { $env:RB_TRANSPORT } else { "adb" }
$target    = if ($env:RB_TARGET) { $env:RB_TARGET } else { "both" }
$repo      = if ($env:RB_REPO) { $env:RB_REPO } else { "lm060719/reconbridge" }
$asset     = "reconbridge-mcp-win64.zip"
$assetUrl  = if ($env:RB_ASSET_URL) { $env:RB_ASSET_URL } `
             else { "https://github.com/$repo/releases/latest/download/$asset" }

$dest = Join-Path $env:LOCALAPPDATA "ReconBridge"
$app  = Join-Path $dest "reconbridge-mcp"
$exe  = Join-Path $app  "reconbridge-mcp.exe"

Write-Host "== ReconBridge MCP online install ==" -ForegroundColor Cyan
Write-Host "  source: $assetUrl"
Write-Host "  target: $dest"

# 1) download to a temp zip
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("reconbridge-mcp-" + [Guid]::NewGuid().ToString("N") + ".zip")
Write-Host "[1/3] downloading ..." -ForegroundColor Yellow
if ($assetUrl -match '^https?://') {
    Invoke-WebRequest -Uri $assetUrl -OutFile $tmp -UseBasicParsing
} else {
    # local testing: RB_ASSET_URL points at a built zip (plain path or file:// URI)
    Copy-Item ($assetUrl -replace '^file:///?','') $tmp -Force
}

# 2) clean old + extract (only the reconbridge-mcp subdir; keeps sibling work\ etc.)
Write-Host "[2/3] extracting to $app ..." -ForegroundColor Yellow
if (Test-Path $app) { Remove-Item $app -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Expand-Archive -Path $tmp -DestinationPath $dest -Force
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $exe)) { throw "exe not found after extract: $exe" }

# 3) self-register into the selected client(s)
Write-Host "[3/3] registering (target=$target, transport=$transport) ..." -ForegroundColor Yellow
& $exe --register --target $target --transport $transport
if ($LASTEXITCODE -ne 0) { throw "register failed (exit $LASTEXITCODE)" }

# add the install dir to the user PATH so `reconbridge-mcp --serve` works from any new terminal
$pathCur = [Environment]::GetEnvironmentVariable("Path", "User")
$pathParts = if ($pathCur) { $pathCur -split ';' } else { @() }
if ($pathParts -notcontains $app) {
    $newPath = if ($pathCur) { "$pathCur;$app" } else { $app }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "[PATH] added to user PATH (open a new terminal to use it): $app" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "OK - install complete (target=$target)." -ForegroundColor Green
Write-Host "  Restart the client(s) to take effect:" -ForegroundColor Green
Write-Host "   - Claude Code: verify with 'claude mcp list' or /mcp (look for reconbridge)." -ForegroundColor Green
Write-Host "   - ChatGPT Codex: [mcp_servers.reconbridge] is now in ~/.codex/config.toml." -ForegroundColor Green
Write-Host ""
Write-Host "  Notes:" -ForegroundColor DarkGray
Write-Host "   - Needs adb on PATH (for a real device; not needed in wifi mode)." -ForegroundColor DarkGray
Write-Host "   - jadx / Ghidra are optional; unzip into $dest\tools\ to be auto-detected (see toolchain_status)." -ForegroundColor DarkGray
Write-Host "   - The device-side KernelSU module is flashed separately (see README)." -ForegroundColor DarkGray
Write-Host "   - Update: re-run this command (overwrites in place, keeps work\). Uninstall: run uninstall.ps1." -ForegroundColor DarkGray
Write-Host "   - GUI console: open a NEW terminal then 'reconbridge-mcp --serve' (or run & `"$exe`" --serve right now)." -ForegroundColor DarkGray
