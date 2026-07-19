# ReconBridge —— 一行在线安装 PC 侧 MCP 工具（Windows / PowerShell）。
#
# 设计成可直接 `irm <url> | iex` 执行，无需 clone 仓库：
#   irm https://github.com/lm060719/reconbridge/releases/latest/download/install.ps1 | iex
#
# 步骤：
#   1. 从 GitHub Release 下载 reconbridge-mcp-win64.zip（onedir 打包的 exe）
#   2. 解压到 %LOCALAPPDATA%\ReconBridge\
#   3. 调 reconbridge-mcp.exe --register 写入 Claude Code 用户级配置 ~/.claude.json
#
# 环境变量（可选，`iex` 前先 `$env:...` 设）：
#   RB_TRANSPORT  = adb（默认）| wifi
#   RB_REPO       = 覆盖仓库（默认 lm060719/reconbridge）
#   RB_ASSET_URL  = 直接指定 zip 下载地址（跳过 Release 推断；也可指向本地文件做联调）

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$transport = if ($env:RB_TRANSPORT) { $env:RB_TRANSPORT } else { "adb" }
$repo      = if ($env:RB_REPO) { $env:RB_REPO } else { "lm060719/reconbridge" }
$asset     = "reconbridge-mcp-win64.zip"
$assetUrl  = if ($env:RB_ASSET_URL) { $env:RB_ASSET_URL } `
             else { "https://github.com/$repo/releases/latest/download/$asset" }

$dest = Join-Path $env:LOCALAPPDATA "ReconBridge"
$app  = Join-Path $dest "reconbridge-mcp"
$exe  = Join-Path $app  "reconbridge-mcp.exe"

Write-Host "== ReconBridge MCP 在线安装 ==" -ForegroundColor Cyan
Write-Host "  来源: $assetUrl"
Write-Host "  目标: $dest"

# 1) 下载到临时 zip
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("reconbridge-mcp-" + [Guid]::NewGuid().ToString("N") + ".zip")
Write-Host "[1/3] 下载 ..." -ForegroundColor Yellow
if ($assetUrl -match '^https?://') {
    Invoke-WebRequest -Uri $assetUrl -OutFile $tmp -UseBasicParsing
} else {
    # 联调：RB_ASSET_URL 指向本地已构建的 zip（普通路径或 file:// URI）
    Copy-Item ($assetUrl -replace '^file:///?','') $tmp -Force
}

# 2) 清旧 + 解压。只删 reconbridge-mcp 子目录，保留同级 work/ 等用户数据。
Write-Host "[2/3] 解压到 $app ..." -ForegroundColor Yellow
if (Test-Path $app) { Remove-Item $app -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
# zip 顶层即 reconbridge-mcp\，解到 $dest 后正好落成 $app
Expand-Archive -Path $tmp -DestinationPath $dest -Force
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $exe)) { throw "解压后未找到 $exe，zip 结构异常。" }

# 3) 自注册进 Claude Code
Write-Host "[3/3] 注册到 Claude Code（transport=$transport）..." -ForegroundColor Yellow
& $exe --register --transport $transport
if ($LASTEXITCODE -ne 0) { throw "注册失败（exit $LASTEXITCODE）" }

Write-Host ""
Write-Host "✓ 安装完成。" -ForegroundColor Green
Write-Host "  重启 Claude Code 后用 ``claude mcp list`` 或 /mcp 验证 reconbridge。" -ForegroundColor Green
Write-Host ""
Write-Host "  提示：" -ForegroundColor DarkGray
Write-Host "   · 需要 adb 在 PATH（连真机；wifi 模式除外）。" -ForegroundColor DarkGray
Write-Host "   · jadx / Ghidra 为可选反编译工具，解压到 $dest\tools\ 即被自动探测（toolchain_status 查看）。" -ForegroundColor DarkGray
Write-Host "   · 设备端仍需在 KernelSU 管理器刷入 ReconBridge 模块（见 README 设备端章节）。" -ForegroundColor DarkGray
Write-Host "   · 更新：重跑本命令即原地覆盖（保留 work\ 数据）。卸载：跑 uninstall.ps1。" -ForegroundColor DarkGray
