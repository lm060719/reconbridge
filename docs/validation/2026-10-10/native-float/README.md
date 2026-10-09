# Native 浮点支持验证记录

基线：`8f4ff41ec24766e8e4a153d832eb3380ddf8a966`。
范围、示例与限制见 [NATIVE_FLOAT.md](../../../../pc/NATIVE_FLOAT.md)。

| 验证 | 原始输出 |
|---|---|
| Python 194 passed / 1 skipped（设备 e2e 未启用）与工具清单 | [pc-tests.txt](pc-tests.txt) |
| MSVC C++17 配置校验、实时分派与并发测试 | [cpp-tests.txt](cpp-tests.txt) |
| NDK r27c 双 ABI daemon / Zygisk | [native-build.txt](native-build.txt) |
| 双 ABI 汇编调用测试交叉编译（成功无输出） | [abi-compile.txt](abi-compile.txt) |
| 新模块包及独立校验 | [package.txt](package.txt) |
| 二进制、源码、ZIP SHA-256 | [artifacts.json](artifacts.json) |

主要命令（仓库根目录；Python 使用 pc/.venv，NDK 使用本机 r27c）：

```text
cd pc && python -m pytest -q
python scripts/generate_tool_catalog.py --check
cl /std:c++17 /EHsc /utf-8 /O2 tests/native_live_test.cpp
native-live-test.exe
python scripts/build_native.py --ndk <android-ndk-r27c>
clang++ --target=<aarch64|x86_64>-linux-android26 -std=c++17 -O2 -pthread tests/native_abi_test.cpp m3/zygisk/native_bridge.S -static-libstdc++ -o <test>
python scripts/package_module.py --output dist/ReconBridge-native-float.zip
python scripts/package_module.py --verify dist/ReconBridge-native-float.zip
```

CI 在 ubuntu-24.04 与 ubuntu-24.04-arm 上用 g++ 编译并实际运行同一汇编网关测试，
覆盖混合整数/float/double/指针、FP8、GP8 栈传递、混合参数溢出、零参数、参数/返回值替换、
在途停用、重新启用、签名变更拒绝、NaN payload/Inf/负零透传及 C++ 异常展开。
其余 CI 包含三平台 Python、Tracer、daemon 集成测试、Android 双 ABI 构建和模块校验。
完整 CI 输出在推送后存入本地 `dist/native-float-ci.log`，提交/推送及验证合并日志为
`dist/native-float-complete.log`；远端 Actions 与提交关联。

本机 Windows 不执行 Linux ABI 二进制；交叉编译成功不记作运行通过。
Android 真机 Hook 引擎、物理撤钩及库卸载测试未执行。
