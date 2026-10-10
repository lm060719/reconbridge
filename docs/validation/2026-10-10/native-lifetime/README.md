# Native 撤钩与库生命周期验证

基线：`0a43ce7a00bc51a1b2b4ade2c03e4f015a7b5612`（master）。
使用与限制：[NATIVE_LIFECYCLE.md](../../../../pc/NATIVE_LIFECYCLE.md)。

| 本地检查 | 输出 |
|---|---|
| Python 216 passed / 1 skipped | [pc-tests.txt](pc-tests.txt) |
| 在途计数、失败保留、2,000 次槽位复用、库代次、JNI 乱序 | [cpp-tests.txt](cpp-tests.txt) |
| JNI 观察器 | [jni-observer.txt](jni-observer.txt) |
| NDK r27c 双 ABI daemon/Zygisk | [native-build.txt](native-build.txt) |
| 源码指纹、两种 ABI 清单与安装包 SHA-256 | [artifacts.json](artifacts.json) |

模块：`dist/ReconBridge-native-lifetime.zip`，通过 scripts/package_module.py 打包及 verify。
安装包使用 build/native 新产物，未使用 module 目录旧二进制。
未修改原有未跟踪的 m5/ReconBridge-Tracer.apk。

PC 冻结版：`dist/ReconBridge-PC-native-lifetime-win64.zip`。stdio MCP 冒烟验证 103 工具枚举、
离线预览、模拟异步关联及报告 ZIP 校验，无设备调用；日志 `dist/native-lifetime-frozen-smoke.log`。

复现：Python 环境使用 pc/.venv，NDK 27.2.12479018，MSVC C++17，JNI 测试使用 Java 17 头文件。

```text
python -m pytest -q pc
python scripts/generate_tool_catalog.py --check
python scripts/build_native.py --ndk <Android NDK r27c>
python scripts/package_module.py --output dist/ReconBridge-native-lifetime.zip
python scripts/package_module.py --verify dist/ReconBridge-native-lifetime.zip
```

原生 CPU 网关及真实 Dobby 测试完整编译命令保存在 `.github/workflows/pc-tests.yml`。

CI 新增两种 CPU 的生产 RX 入口执行，以及固定 Dobby 的 100 次真实安装/撤钩和原指令比对。
CI 原始日志、元数据、提交同步记录与本地输出合并至 `dist/native-lifetime-complete.log`。
[最终 CI 38043691260](https://github.com/lm060719/reconbridge/actions/runs/38043691260)
在 `4ed4e1a5c8a511aa055e1e29ae42db90e62356db` 上 **10/10 jobs 成功**；
包括三平台 Python、两种 CPU 网关、真实 Dobby 100 次安装/撤钩、双 ABI NDK、Tracer 和模块校验。
机器可读结果见 [ci-result.json](ci-result.json)。后续验证归档提交仅更新本目录，不改变已测试代码。

前四次 CI 的 Dobby 宿主构建分别发现 GCC 不支持上游 `__has_feature` 宏、x86 汇编未预处理，
以及缺少固定宽度整数和 POSIX 时间声明。已显式选择 Clang、assembler-with-cpp 和标准头文件；
完整失败日志也会保留，不删减成仅成功摘要。

本轮不连接或部署 Android 设备。仍需真机验证 linker 回调、并发 dlclose、长时间内存开销及设备兼容性。
入口上下文最多保留 4096 个，引擎自身部分内存保留；64 个逻辑槽位可以回收复用。
