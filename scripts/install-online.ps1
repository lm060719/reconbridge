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
#   RB_TRANSPORT     = adb (default) | wifi
#   RB_TARGET        = both (default) | claude | codex   which client(s) to register into
#   RB_REPO          = override repo (default lm060719/reconbridge)
#   RB_ASSET_URL     = direct zip URL (skip Release lookup; may be a local file for testing)
#   RB_INSTALL_JADX   = yes | no   skip the interactive jadx prompt
#   RB_INSTALL_GHIDRA = yes | no   skip the interactive Ghidra+JDK21 prompt
#
# jadx and Ghidra+JDK21 are optional local decompilers (dexkit_search already works out of
# the box via bundled androguard). The installer asks [y/N] whether to auto-download each;
# default is no if you just press Enter. Set the env vars above to answer non-interactively.
#
# NOTE: keep this script pure ASCII. `irm | iex` decodes the downloaded text with the
# PS 5.1 default encoding (no charset from GitHub), so non-ASCII would render as mojibake,
# and a UTF-8 BOM would make the first line fail under iex. ASCII avoids both.

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---- optional-tools helpers (jadx / Ghidra+JDK21) --------------------------
function Confirm-Yes([string]$promptText, [string]$envVar) {
    $ev = [Environment]::GetEnvironmentVariable($envVar)
    if ($ev) { return ($ev -match '^(?i)(y|yes|1|true)$') }
    try {
        $ans = Read-Host $promptText
    } catch {
        return $false
    }
    return ($ans -match '^(?i)y(es)?$')
}

function Get-LatestReleaseAssetUrl([string]$repo, [string]$namePattern) {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" `
                              -Headers @{ "User-Agent" = "reconbridge-installer" }
    $a = $rel.assets | Where-Object { $_.name -match $namePattern } | Select-Object -First 1
    if (-not $a) { throw "no asset matching '$namePattern' in latest release of $repo" }
    return $a.browser_download_url
}

function Install-Jadx([string]$toolsDir) {
    $jadxDir = Join-Path $toolsDir "jadx"
    Write-Host "  looking up latest jadx release ..." -ForegroundColor Yellow
    $url = Get-LatestReleaseAssetUrl "skylot/jadx" '^jadx-[0-9].*\.zip$'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("jadx-" + [Guid]::NewGuid().ToString("N") + ".zip")
    Write-Host "  downloading $url ..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    if (Test-Path $jadxDir) { Remove-Item $jadxDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $jadxDir | Out-Null
    Expand-Archive -Path $tmp -DestinationPath $jadxDir -Force
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Host "  OK - jadx installed to $jadxDir" -ForegroundColor Green
}

function Stop-RunningReconbridgeMcp() {
    # an in-place update/reinstall fails to delete files while the exe (e.g. the MCP
    # subprocess a running Claude Code / Codex session already spawned) is loaded -
    # Windows keeps its .pyd/.dll files locked. Stop it first so extraction can proceed;
    # the client just needs restarting afterwards to relaunch the new build anyway.
    $running = Get-Process -Name "reconbridge-mcp" -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host "  stopping running reconbridge-mcp.exe (PID $($running.Id -join ', ')) to release file locks ..." -ForegroundColor Yellow
        Write-Host "  (this is the MCP subprocess of an already-open Claude Code / Codex session; restart it after install)" -ForegroundColor DarkGray
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
    }
}

function Remove-DirWithRetry([string]$path, [int]$retries = 6) {
    for ($i = 0; $i -lt $retries; $i++) {
        try {
            Remove-Item $path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ($i -eq $retries - 1) {
                throw "could not remove old install dir $path (still locked). " +
                      "Close Claude Code / ChatGPT Codex (or any terminal using reconbridge-mcp) and re-run this installer. Original error: $_"
            }
            Start-Sleep -Milliseconds 700
        }
    }
}

function Install-GhidraAndJdk([string]$nativeDir) {
    New-Item -ItemType Directory -Force -Path $nativeDir | Out-Null

    Write-Host "  looking up latest Ghidra release ..." -ForegroundColor Yellow
    $ghUrl = Get-LatestReleaseAssetUrl "NationalSecurityAgency/ghidra" '^ghidra_.*_PUBLIC_.*\.zip$'
    $ghTmp = Join-Path ([IO.Path]::GetTempPath()) ("ghidra-" + [Guid]::NewGuid().ToString("N") + ".zip")
    Write-Host "  downloading $ghUrl (large file, this can take a while) ..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $ghUrl -OutFile $ghTmp -UseBasicParsing
    Expand-Archive -Path $ghTmp -DestinationPath $nativeDir -Force
    Remove-Item $ghTmp -Force -ErrorAction SilentlyContinue
    Write-Host "  OK - Ghidra extracted under $nativeDir" -ForegroundColor Green

    Write-Host "  downloading JDK 21 (Eclipse Temurin, required by Ghidra 12) ..." -ForegroundColor Yellow
    $jdkUrl = "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"
    $jdkTmp = Join-Path ([IO.Path]::GetTempPath()) ("jdk21-" + [Guid]::NewGuid().ToString("N") + ".zip")
    Invoke-WebRequest -Uri $jdkUrl -OutFile $jdkTmp -UseBasicParsing
    Expand-Archive -Path $jdkTmp -DestinationPath $nativeDir -Force
    Remove-Item $jdkTmp -Force -ErrorAction SilentlyContinue
    Write-Host "  OK - JDK 21 extracted under $nativeDir" -ForegroundColor Green
}

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
Write-Host "[1/4] downloading ..." -ForegroundColor Yellow
if ($assetUrl -match '^https?://') {
    Invoke-WebRequest -Uri $assetUrl -OutFile $tmp -UseBasicParsing
} else {
    # local testing: RB_ASSET_URL points at a built zip (plain path or file:// URI)
    Copy-Item ($assetUrl -replace '^file:///?','') $tmp -Force
}

# 2) clean old + extract (only the reconbridge-mcp subdir; keeps sibling work\ etc.)
Write-Host "[2/4] extracting to $app ..." -ForegroundColor Yellow
if (Test-Path $app) {
    Stop-RunningReconbridgeMcp
    Remove-DirWithRetry $app
}
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Expand-Archive -Path $tmp -DestinationPath $dest -Force
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $exe)) { throw "exe not found after extract: $exe" }

# 3) self-register into the selected client(s)
Write-Host "[3/4] registering (target=$target, transport=$transport) ..." -ForegroundColor Yellow
& $exe --register --target $target --transport $transport
if ($LASTEXITCODE -ne 0) { throw "register failed (exit $LASTEXITCODE)" }

# 4) optional decompile toolchain (jadx / Ghidra+JDK21) - dexkit_search already works
#    without these, via the androguard bundled in the exe.
Write-Host "[4/4] optional decompile toolchain ..." -ForegroundColor Yellow
$toolsDir  = Join-Path $dest "tools"
$nativeDir = if ($env:RECONBRIDGE_NATIVE_TOOLS) { $env:RECONBRIDGE_NATIVE_TOOLS } `
             else { (Split-Path -Qualifier $dest) + "\ReconBridgeTools" }

if (Confirm-Yes "  install jadx now? decompiler, ~30MB [y/N]" "RB_INSTALL_JADX") {
    try {
        Install-Jadx $toolsDir
    } catch {
        Write-Warning "  jadx auto-install failed: $_"
        Write-Host "  install manually later: unzip a jadx release into $toolsDir\jadx" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  skipped. install later: unzip into $toolsDir\jadx (or set RB_INSTALL_JADX=yes and re-run)." -ForegroundColor DarkGray
}

if (Confirm-Yes "  install Ghidra + JDK21 now? native .so reverse engineering, ~700MB, takes a while [y/N]" "RB_INSTALL_GHIDRA") {
    try {
        Install-GhidraAndJdk $nativeDir
    } catch {
        Write-Warning "  Ghidra/JDK21 auto-install failed: $_"
        Write-Host "  install manually later: Ghidra -> $nativeDir\ghidra_*, JDK21 -> $nativeDir\jdk-21*" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  skipped. install later into $nativeDir (or set RB_INSTALL_GHIDRA=yes and re-run)." -ForegroundColor DarkGray
}

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
Write-Host "   - jadx / Ghidra status: check with the toolchain_status MCP tool, or re-run this installer" -ForegroundColor DarkGray
Write-Host "     to be asked again (RB_INSTALL_JADX / RB_INSTALL_GHIDRA=yes to skip the prompt)." -ForegroundColor DarkGray
Write-Host "   - The device-side KernelSU module is flashed separately (see README)." -ForegroundColor DarkGray
Write-Host "   - Update: re-run this command (overwrites in place, keeps work\). Uninstall: run uninstall.ps1." -ForegroundColor DarkGray
Write-Host "   - GUI console: open a NEW terminal then 'reconbridge-mcp --serve' (or run & `"$exe`" --serve right now)." -ForegroundColor DarkGray
