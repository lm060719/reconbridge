# ReconBridge —— 把 PC 侧 MCP server 打成 onedir exe 并压成发布 zip（Windows / PowerShell）。
#
#   1. 在 pc\.venv-build 建独立构建虚拟环境（不污染运行用的 pc\.venv）
#   2. 装 requirements.txt + pyinstaller
#   3. 跑 pc\reconbridge-mcp.spec → dist\reconbridge-mcp\（含 reconbridge-mcp.exe + _internal\）
#   4. 用正斜杠 ZipArchive 助手压成 dist\reconbridge-mcp-win64.zip（发布到 GitHub Release）
#
# 用法：./build_exe.ps1
# 产物随后配合 scripts\install-online.ps1 走「一行在线安装」。

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$pc   = Join-Path $root "pc"
$dist = Join-Path $root "dist"
$venv = Join-Path $pc ".venv-build"

Write-Host "== ReconBridge MCP exe 构建 ==" -ForegroundColor Cyan

# 1) 找 python
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue) }
if (-not $py) { throw "未找到 python，请先安装 Python 3.10+ 并加入 PATH。" }

# 2) 构建 venv
if (-not (Test-Path $venv)) {
    Write-Host "[1/4] 创建构建虚拟环境 $venv ..." -ForegroundColor Yellow
    & $py.Source -m venv $venv
} else {
    Write-Host "[1/4] 构建虚拟环境已存在，跳过。" -ForegroundColor Yellow
}
$venvPy = Join-Path $venv "Scripts\python.exe"

# 3) 装依赖 + pyinstaller
Write-Host "[2/4] 安装依赖 + pyinstaller ..." -ForegroundColor Yellow
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -r (Join-Path $pc "requirements.txt")
& $venvPy -m pip install pyinstaller

# 4) 跑 PyInstaller（工作目录切到 pc，spec 里 pathex=. 依赖此）
Write-Host "[3/4] PyInstaller 打包（onedir）..." -ForegroundColor Yellow
$specOutBuild = Join-Path $pc "build"
$specOutDist  = Join-Path $pc "dist"
Push-Location $pc
try {
    # PyInstaller 把 INFO 日志写到 stderr；在 $ErrorActionPreference='Stop' 下，原生命令的 stderr
    # 会被 PS 5.1 包成 NativeCommandError 并终止。故此处临时降为 Continue，仅凭 $LASTEXITCODE 判成败。
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $venvPy -m PyInstaller --noconfirm --clean `
        --distpath $specOutDist --workpath $specOutBuild `
        (Join-Path $pc "reconbridge-mcp.spec") 2>&1 | ForEach-Object { "$_" }
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $savedEAP
    if ($rc -ne 0) { throw "PyInstaller 失败（exit $rc）" }
} finally {
    Pop-Location
}

$appDir = Join-Path $specOutDist "reconbridge-mcp"
$exe    = Join-Path $appDir "reconbridge-mcp.exe"
if (-not (Test-Path $exe)) { throw "未生成 $exe" }

# 把 onedir 目录搬到仓库根 dist\reconbridge-mcp\（统一发布位置）
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$finalApp = Join-Path $dist "reconbridge-mcp"
if (Test-Path $finalApp) { Remove-Item $finalApp -Recurse -Force }
Move-Item $appDir $finalApp
$exe = Join-Path $finalApp "reconbridge-mcp.exe"   # 移动后更新路径，供下方报告用

# 5) 正斜杠 zip（Compress-Archive 会写反斜杠条目，某些解压器出错；沿用 pack.ps1 的 C# 助手）
Write-Host "[4/4] 打包 zip ..." -ForegroundColor Yellow
$zip = Join-Path $dist "reconbridge-mcp-win64.zip"
Add-Type -ReferencedAssemblies System.IO.Compression, System.IO.Compression.FileSystem -TypeDefinition @"
using System;
using System.IO;
using System.IO.Compression;
public static class RBExeZip {
  public static void Pack(string srcRoot, string zipPath) {
    if (File.Exists(zipPath)) File.Delete(zipPath);
    string parent = Path.GetFullPath(Path.Combine(srcRoot, ".."));
    string baseDir = parent.TrimEnd('\\') + "\\";
    using (var fs = new FileStream(zipPath, FileMode.Create))
    using (var arch = new ZipArchive(fs, ZipArchiveMode.Create)) {
      foreach (var f in Directory.GetFiles(srcRoot, "*", SearchOption.AllDirectories)) {
        string rel = Path.GetFullPath(f).Substring(baseDir.Length).Replace('\\', '/');
        var entry = arch.CreateEntry(rel, CompressionLevel.Optimal);
        using (var es = entry.Open())
        using (var ins = File.OpenRead(f)) ins.CopyTo(es);
      }
    }
  }
}
"@
# zip 内顶层为 reconbridge-mcp/ ——解压到 %LOCALAPPDATA%\ReconBridge 后即 ...\ReconBridge\reconbridge-mcp\exe
[RBExeZip]::Pack($finalApp, $zip)

$exeSz = [math]::Round((Get-Item $exe).Length / 1KB, 1)
$dirSz = [math]::Round(((Get-ChildItem $finalApp -Recurse | Measure-Object Length -Sum).Sum) / 1MB, 1)
$zipSz = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Host ""
Write-Host "✓ 完成。" -ForegroundColor Green
Write-Host "  exe : $exe ($exeSz KB)"
Write-Host "  目录: $finalApp ($dirSz MB)"
Write-Host "  zip : $zip ($zipSz MB)"
Write-Host ""
Write-Host "自检： & `"$exe`" --register --print-only" -ForegroundColor Cyan
Write-Host "发布： gh release ... 上传 $zip 与 scripts\install-online.ps1（重命名为 install.ps1）" -ForegroundColor Cyan
