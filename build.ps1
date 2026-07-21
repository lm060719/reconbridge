# ReconBridge M1 构建脚本（Windows / PowerShell）
# 直接调用 NDK 的 clang++ 交叉编译守护进程（arm64-v8a + x86_64），无需安装 cmake / ninja。
# 输出：module\bin\reconbridge_daemon(_x86_64)，随后可用 pack.ps1 打包成刷入 zip。
# x86_64 的动态 hook 层(M3) 用 Dobby 代替 shadowhook（shadowhook 官方不支持 x86_64）；
# libdobby_x86_64.so 需要单独用 m3\build_dobby_x86_64.ps1 构建一次，见该脚本注释。

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

$llvmBin = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$strip = Join-Path $llvmBin "llvm-strip.exe"
$outDir = Join-Path $root "module\bin"
$zygOutDir = Join-Path $root "module\zygisk"
$zygSrc = Join-Path $root "m3\zygisk\module.cpp"
$src = @((Join-Path $root "src\daemon.cpp"), (Join-Path $root "src\dynamic.cpp"))
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $zygOutDir | Out-Null

function Build-Daemon($clang, $outName) {
    $out = Join-Path $outDir $outName
    & $clang `
        -std=c++17 -Os -fvisibility=hidden -ffunction-sections -fdata-sections `
        -Wall -Wextra -Wno-unused-parameter `
        @src `
        -static-libstdc++ -pthread `
        "-Wl,--gc-sections" "-Wl,--strip-all" `
        -o $out
    if ($LASTEXITCODE -ne 0) { throw "守护进程编译失败: $outName" }
    $sz = [math]::Round((Get-Item $out).Length / 1KB, 1)
    Write-Host "守护进程 OK -> $out ($sz KB)"
}

function Build-Zygisk($clang, $abiName) {
    $zygOut = Join-Path $zygOutDir "$abiName.so"
    & $clang `
        -std=c++17 -O2 -fPIC -shared `
        -Wall -Wextra -Wno-unused-parameter `
        -I (Join-Path $root "m3\zygisk") `
        $zygSrc `
        -static-libstdc++ -llog -ldl `
        "-Wl,--gc-sections" "-Wl,--exclude-libs,ALL" `
        -o $zygOut
    if ($LASTEXITCODE -ne 0) { throw "Zygisk 编译失败: $abiName" }
    if (Test-Path $strip) { & $strip $zygOut }
    $zsz = [math]::Round((Get-Item $zygOut).Length / 1KB, 1)
    Write-Host "Zygisk 层 OK -> $zygOut ($zsz KB)"
}

# ===================== arm64-v8a（主力目标，shadowhook） =====================
$clangArm64 = Join-Path $llvmBin "aarch64-linux-android26-clang++.cmd"
if (-not (Test-Path $clangArm64)) { $clangArm64 = Join-Path $llvmBin "aarch64-linux-android26-clang++" }
if (-not (Test-Path $clangArm64)) { throw "未找到 clang++：$clangArm64" }

Write-Host "编译中（arm64-v8a）…"
Build-Daemon $clangArm64 "reconbridge_daemon"

if (Test-Path $zygSrc) {
    Write-Host "编译 Zygisk 注入层（arm64-v8a）…"
    Build-Zygisk $clangArm64 "arm64-v8a"
    # 拷贝 shadowhook 预编译库到按架构分开的 staging 目录（customize.sh 安装时按 $ARCH
    # 合并进真正的 module\system\lib64\，避免把两种架构的 ELF 都挂进 /system/lib64）。
    # KernelSU 挂到 /system/lib64，默认命名空间，其 nothing.so 同级——shadowhook 的
    # linker init 才能按名 dlopen 到它。
    $sysLibArm64 = Join-Path $root "module\system_lib64_arm64"
    New-Item -ItemType Directory -Force -Path $sysLibArm64 | Out-Null
    Copy-Item (Join-Path $root "m3\prebuilt\libshadowhook.so") (Join-Path $sysLibArm64 "libshadowhook.so") -Force
    Copy-Item (Join-Path $root "m3\prebuilt\libshadowhook_nothing.so") (Join-Path $sysLibArm64 "libshadowhook_nothing.so") -Force
}

# ===================== x86_64（次要目标，Dobby） =====================
# 未在真机/模拟器验证过运行时行为——见 m3/README.md「x86_64 支持」一节。
$clangX64 = Join-Path $llvmBin "x86_64-linux-android26-clang++.cmd"
if (-not (Test-Path $clangX64)) { $clangX64 = Join-Path $llvmBin "x86_64-linux-android26-clang++" }
if (Test-Path $clangX64) {
    Write-Host "编译中（x86_64）…"
    Build-Daemon $clangX64 "reconbridge_daemon_x86_64"

    if (Test-Path $zygSrc) {
        Write-Host "编译 Zygisk 注入层（x86_64）…"
        Build-Zygisk $clangX64 "x86_64"
        $dobby = Join-Path $root "m3\prebuilt\libdobby_x86_64.so"
        if (Test-Path $dobby) {
            $sysLibX64 = Join-Path $root "module\system_lib64_x64"
            New-Item -ItemType Directory -Force -Path $sysLibX64 | Out-Null
            Copy-Item $dobby (Join-Path $sysLibX64 "libdobby.so") -Force
        } else {
            Write-Host "! 缺少 m3\prebuilt\libdobby_x86_64.so，先跑 m3\build_dobby_x86_64.ps1（见脚本注释）"
        }
    }
} else {
    Write-Host "! 未找到 x86_64 clang++，跳过 x86_64 构建（不影响 arm64-v8a）"
}
