# 2026-10-09 提交前验证记录

本目录保存本次实际执行的验证输出。正文、源码、测试及设备端二进制一起提交。
此前工作区未跟踪的 `m5/ReconBridge-Tracer.apk` 保留在本地；APK 由 Gradle/CI 构建交付，不纳入此提交。

| 项目 | 原始记录 |
|---|---|
| Python 回归 | [pc-tests.txt](pc-tests.txt) |
| Tracer 单元测试与 APK | [tracer-tests.txt](tracer-tests.txt) |
| C++ 宿主测试 | [cpp-tests.txt](cpp-tests.txt) |
| NDK 双架构编译 | [native-build.txt](native-build.txt) |
| 工具清单、ZIP 校验、产物指纹和测试计数 | [artifacts.json](artifacts.json) |

`git log --stat` / `git show` 提供提交文件级变更记录；功能与边界见根目录 [CHANGELOG.md](../../../CHANGELOG.md)。
本机为 Windows。工作流的 Linux/macOS 结果与真机测试结果不由本地测试推断。
