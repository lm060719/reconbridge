# ReconBridge M1 构建脚本（Windows / PowerShell）
# 直接调用 NDK 的 clang++ 交叉编译 arm64-v8a 守护进程，无需安装 cmake / ninja。
# 输出：module\bin\reconbridge_daemon，随后可用 pack.ps1 打包成刷入 zip。

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# --- 定位 NDK ---
$ndk = $env:ANDROID_NDK_HOME
if (-not $ndk) { $ndk = $env:ANDROID_NDK_ROOT }
if (-not $ndk -or -not (Test-Path $ndk)) {
    $cand = Get-ChildItem "$env:LOCALAPPDATA\Android\Sdk\ndk" -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
    if ($cand) { $ndk = $cand.FullName }
}
if (-not $ndk -or -not (Test-Path $ndk)) { throw "未找到 NDK，请设置 ANDROID_NDK_HOME" }
Write-Host "NDK: $ndk"

$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android26-clang++.cmd"
if (-not (Test-Path $clang)) {
    $clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android26-clang++"
}
if (-not (Test-Path $clang)) { throw "未找到 clang++：$clang" }

$outDir = Join-Path $root "module\bin"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir "reconbridge_daemon"

$src = @((Join-Path $root "src\daemon.cpp"), (Join-Path $root "src\dynamic.cpp"))

Write-Host "编译中…"
& $clang `
    -std=c++17 -Os -fvisibility=hidden -ffunction-sections -fdata-sections `
    -Wall -Wextra -Wno-unused-parameter `
    @src `
    -static-libstdc++ -pthread `
    "-Wl,--gc-sections" "-Wl,--strip-all" `
    -o $out
if ($LASTEXITCODE -ne 0) { throw "编译失败" }

$sz = [math]::Round((Get-Item $out).Length / 1KB, 1)
Write-Host "守护进程 OK -> $out ($sz KB)"

# --- M3：编译 Zygisk 注入层 .so ---
$zygSrc = Join-Path $root "m3\zygisk\module.cpp"
if (Test-Path $zygSrc) {
    Write-Host "编译 Zygisk 注入层…"
    $zygOutDir = Join-Path $root "module\zygisk"
    New-Item -ItemType Directory -Force -Path $zygOutDir | Out-Null
    $zygOut = Join-Path $zygOutDir "arm64-v8a.so"
    & $clang `
        -std=c++17 -O2 -fPIC -shared `
        -Wall -Wextra -Wno-unused-parameter `
        -I (Join-Path $root "m3\zygisk") `
        $zygSrc `
        -static-libstdc++ -llog -ldl `
        "-Wl,--gc-sections" "-Wl,--exclude-libs,ALL" `
        -o $zygOut
    if ($LASTEXITCODE -ne 0) { throw "Zygisk 编译失败" }
    $strip = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe"
    if (Test-Path $strip) { & $strip $zygOut }
    # 拷贝 shadowhook 预编译库到 module\system\lib64（KernelSU 挂到 /system/lib64，默认命名空间，
    # 其 nothing.so 同级——shadowhook 的 linker init 才能按名 dlopen 到它）
    $sysLib = Join-Path $root "module\system\lib64"
    New-Item -ItemType Directory -Force -Path $sysLib | Out-Null
    Copy-Item (Join-Path $root "m3\prebuilt\libshadowhook.so") (Join-Path $sysLib "libshadowhook.so") -Force
    Copy-Item (Join-Path $root "m3\prebuilt\libshadowhook_nothing.so") (Join-Path $sysLib "libshadowhook_nothing.so") -Force
    $zsz = [math]::Round((Get-Item $zygOut).Length / 1KB, 1)
    Write-Host "Zygisk 层 OK -> $zygOut ($zsz KB)"
}
