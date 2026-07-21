# 构建 m3\prebuilt\libdobby_x86_64.so ——
# ReconBridge M3 的 x86_64 动态 hook 引擎（shadowhook 官方不支持 x86_64，改用
# jmpews/Dobby: https://github.com/jmpews/Dobby）。
#
# 只需跑一次（产物已提交进仓库 m3\prebuilt\libdobby_x86_64.so），除非要升级 Dobby
# 版本或换个 commit。需要 cmake + ninja（本机若没装，见下方自动下载）。
#
# 背景：Dobby 在本脚本固定的 commit 上，Android/Linux 后端有三处上游 bug
# （详见 m3\dobby-android-build-fix.patch）：
#   1) common\os_arch_features.h 用到的 OSMemory 类因头文件循环 include 顺序
#      问题，在编译到它时还未定义（platform.h 顶部就 include 回 dobby/common.h，
#      而 dobby/common.h 又经 os_arch_features.h include 回 platform.h，
#      #pragma once 挡住二次展开，OSMemory/OSPrint 定义还在后面没走到）。
#   2) source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc 和
#      builtin-plugin/SymbolResolver/elf/dobby_symbol_resolver.cc 用
#      `module.load_address`，但 RuntimeModule 结构体字段其实叫 `base`
#     （另外 MemRange::start 是方法不是字段，也一并按 `.start()` 修正）。
#   3) code-patch-tool-posix.cc 引用的 core/arch/Cpu.h 在这个 commit 已被删除，
#      实际该用的 ClearCache 声明在 PlatformUnifiedInterface/ExecMemory/
#      ClearCacheTool.h（对应实现 clear-cache-tool-all.c 本就在编译列表里）。
# 这些都是 Dobby 自己一次未完成重构留下的坑，与 x86_64 本身无关（在这个 commit
# 上编译任何 Android/Linux 目标都会撞上），补丁只改这三处，不改行为。

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot  # m3/
$projRoot = Split-Path $root -Parent
$toolsDir = "E:\ReconBridgeTools"  # ASCII 路径；仓库在中文路径下部分工具链会炸
$dobbyCommit = "5dfc8546954ce3b3198132ab13fddb89ee92cdd7"  # tag "latest"（2024-03-14）

New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

# --- NDK ---
$ndk = $env:ANDROID_NDK_HOME
if (-not $ndk) { $ndk = $env:ANDROID_NDK_ROOT }
if (-not $ndk -or -not (Test-Path $ndk)) {
    $cand = Get-ChildItem "$env:LOCALAPPDATA\Android\Sdk\ndk" -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
    if ($cand) { $ndk = $cand.FullName }
}
if (-not $ndk -or -not (Test-Path $ndk)) { throw "未找到 NDK，请设置 ANDROID_NDK_HOME" }
Write-Host "NDK: $ndk"

# --- cmake / ninja：本机没装就下便携版（zip，不装系统） ---
$cmakeExe = (Get-Command cmake -ErrorAction SilentlyContinue).Source
if (-not $cmakeExe) {
    $cmakeExe = Get-ChildItem "$toolsDir\cmake-extract" -Recurse -Filter "cmake.exe" -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty FullName
}
if (-not $cmakeExe) {
    Write-Host "下载便携版 cmake…"
    $cmakeZip = Join-Path $toolsDir "cmake.zip"
    Invoke-WebRequest "https://github.com/Kitware/CMake/releases/download/v4.3.3/cmake-4.3.3-windows-x86_64.zip" -OutFile $cmakeZip
    Expand-Archive -Path $cmakeZip -DestinationPath (Join-Path $toolsDir "cmake-extract") -Force
    $cmakeExe = Get-ChildItem "$toolsDir\cmake-extract" -Recurse -Filter "cmake.exe" | Select-Object -First 1 -ExpandProperty FullName
}
$ninjaExe = (Get-Command ninja -ErrorAction SilentlyContinue).Source
if (-not $ninjaExe) { $ninjaExe = Join-Path $toolsDir "ninja\ninja.exe" }
if (-not (Test-Path $ninjaExe)) {
    Write-Host "下载便携版 ninja…"
    $ninjaZip = Join-Path $toolsDir "ninja-win.zip"
    Invoke-WebRequest "https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-win.zip" -OutFile $ninjaZip
    Expand-Archive -Path $ninjaZip -DestinationPath (Join-Path $toolsDir "ninja") -Force
}
Write-Host "cmake: $cmakeExe"
Write-Host "ninja: $ninjaExe"

# --- 拉源码 + 切到固定 commit + 打补丁 ---
$src = Join-Path $toolsDir "Dobby-src"
if (-not (Test-Path $src)) {
    git clone https://github.com/jmpews/Dobby.git $src
}
Push-Location $src
try {
    git fetch --unshallow 2>$null
    git checkout -f $dobbyCommit
    git apply --check (Join-Path $root "dobby-android-build-fix.patch")
    git apply (Join-Path $root "dobby-android-build-fix.patch")
} finally {
    Pop-Location
}

# --- 交叉编译（x86_64 Android，Release，共享库） ---
$build = Join-Path $toolsDir "Dobby-build-x86_64"
if (Test-Path $build) { Remove-Item -Recurse -Force $build }
New-Item -ItemType Directory -Force -Path $build | Out-Null

& $cmakeExe -S $src -B $build -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$ninjaExe" `
    "-DCMAKE_TOOLCHAIN_FILE=$ndk\build\cmake\android.toolchain.cmake" `
    "-DANDROID_ABI=x86_64" `
    "-DANDROID_PLATFORM=android-26" `
    "-DCMAKE_BUILD_TYPE=Release" `
    "-DCMAKE_ASM_FLAGS=-x assembler-with-cpp" `
    "-DDOBBY_DEBUG=OFF" `
    "-DPlugin.SymbolResolver=ON" `
    "-DDOBBY_BUILD_EXAMPLE=OFF" `
    "-DDOBBY_BUILD_TEST=OFF"
if ($LASTEXITCODE -ne 0) { throw "cmake 配置失败" }

& $cmakeExe --build $build --target dobby -j 8
if ($LASTEXITCODE -ne 0) { throw "Dobby 编译失败" }

# --- strip + 落地到仓库 ---
$stripExe = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe"
$outSo = Join-Path $build "libdobby.so"
if (Test-Path $stripExe) { & $stripExe $outSo }

$dest = Join-Path $projRoot "m3\prebuilt\libdobby_x86_64.so"
Copy-Item $outSo $dest -Force
$destHeader = Join-Path $projRoot "m3\zygisk\third_party\dobby.h"
Copy-Item (Join-Path $src "include\dobby.h") $destHeader -Force

$sz = [math]::Round((Get-Item $dest).Length / 1KB, 1)
Write-Host "OK -> $dest ($sz KB)"
Write-Host "记得跑一遍 build.ps1 重新打包（会把 libdobby_x86_64.so 塞进 module\system_lib64_x64\）。"
