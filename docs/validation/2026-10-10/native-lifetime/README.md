# Native 撤钩与库生命周期验证

基线：`0a43ce7a00bc51a1b2b4ade2c03e4f015a7b5612`（master）。
使用与限制：[NATIVE_LIFECYCLE.md](../../../../pc/NATIVE_LIFECYCLE.md)。

| 本地检查 | 输出 |
|---|---|
| Python 216 passed / 1 skipped | [pc-tests.txt](pc-tests.txt) |
| 在途计数、失败保留、2,000 次槽位复用、库代次、JNI 乱序 | [cpp-tests.txt](cpp-tests.txt) |
| JNI 观察器 | [jni-observer.txt](jni-observer.txt) |
| NDK r27c 双 ABI daemon/Zygisk | [native-build.txt](native-build.txt) |

模块：`dist/ReconBridge-native-lifetime.zip`，通过 scripts/package_module.py 打包及 verify。
安装包使用 build/native 新产物，未使用 module 目录旧二进制。
未修改原有未跟踪的 m5/ReconBridge-Tracer.apk。

CI 新增两种 CPU 的生产 RX 入口执行，以及固定 Dobby 的 100 次真实安装/撤钩和原指令比对。
CI 原始日志、元数据、提交同步记录与本地输出合并至 `dist/native-lifetime-complete.log`。
完整 CI 结果在推送后记录；本地成功不代表 CI 或真机成功。

本轮不连接或部署 Android 设备。仍需真机验证 linker 回调、并发 dlclose、长时间内存开销及设备兼容性。
入口上下文最多保留 4096 个，引擎自身部分内存保留；64 个逻辑槽位可以回收复用。
