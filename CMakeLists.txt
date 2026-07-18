# ReconBridge 守护进程 —— NDK 交叉编译（arm64-v8a）
# 用法（需已安装 cmake + ninja）：
#   cmake -B build -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
#     -DCMAKE_BUILD_TYPE=MinSizeRel
#   cmake --build build
# 若未安装 cmake，可直接用 build.ps1（调用 NDK clang++ 编译）。

cmake_minimum_required(VERSION 3.18)
project(reconbridge CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(reconbridge_daemon src/daemon.cpp)

# 体积优化 + 静态链接 libc++（bionic libc 设备自带，保持动态）
target_compile_options(reconbridge_daemon PRIVATE
  -Os -fvisibility=hidden -ffunction-sections -fdata-sections
  -Wall -Wextra -Wno-unused-parameter)
target_link_options(reconbridge_daemon PRIVATE
  -static-libstdc++ -Wl,--gc-sections -Wl,--strip-all)

find_package(Threads REQUIRED)
target_link_libraries(reconbridge_daemon PRIVATE Threads::Threads)
