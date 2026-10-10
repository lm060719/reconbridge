# UI、异步关联、报告与工具接入验证

基线：`1133177cf5a39992493a93f8044e6a2f47ec341e`（master）。
使用说明和覆盖边界：[UI_ASYNC_WORKFLOW.md](../../../../pc/UI_ASYNC_WORKFLOW.md)。

| 验证 | 原始输出 |
|---|---|
| Python 211 passed / 1 skipped；新增工作流和平台启动回归 | [pc-tests.txt](pc-tests.txt) |
| 定向工作流/平台回归 24 passed | [workflow-tests.txt](workflow-tests.txt) |
| Tracer 58 tests、debug APK 构建成功 | [tracer-tests.txt](tracer-tests.txt) |
| 工具清单、源码及 APK SHA-256 | [artifacts.json](artifacts.json) |

复现命令（仓库根目录，Python 使用 pc/.venv；Gradle 使用 Java 17）：

```text
python -m pytest -q pc
python scripts/generate_tool_catalog.py --check
cd m5/tracer
gradlew.bat :app:testDebugUnitTest :app:assembleDebug --no-daemon
```

产物为 `dist/ReconBridge-Tracer-1.2.0-debug.apk`。保留原有未跟踪的 `m5/ReconBridge-Tracer.apk`，
本次构建没有覆盖它。Native 源码无变化，本地未重复编译；CI 继续双 CPU ABI、NDK 双架构与模块校验。

Python 检查二进制/超时/输出限额、设备 shell 转义、UI 歧义/页面变化/失败停止、事件窗口、
跨进程任务隔离、失败入队、报告 HTML 转义/脱敏/ZIP 哈希，以及实际平台脚本参数传递。
Kotlin 检查任务对象身份（不用 equals）、真实 JVM 跨线程、重复任务歧义、TTL/容量/取消/namespace、
嵌套 span 与 ThreadLocal 清理。本地无 SDK apkanalyzer，真实 SDK 工具在 Linux CI 中验证四种操作。

推送后完整 CI 原始日志保存为 `dist/ui-async-tools-ci.log`，CI 元数据、提交/同步记录与本地输出
合并为 `dist/ui-async-tools-complete.log`。最终 CI 结果以本次提交关联的 Actions 为准。
这些生成日志与 APK 留在 dist，不提交二进制或原始运行数据。

本轮未连接/部署 Android 设备。UI/Perfetto 及 Xposed 回调联调未执行；无设备测试不代表真机兼容性验证。

首次 CI（38025007841）的三平台 Python 回归通过，但真实 apkanalyzer permissions 失败。
本机 aapt 复现为系统图标引用 `0x01080093` 无法解析，已将 Tracer 图标改为 APK 内置资源。
首次 CI 全日志保留在 `dist/ui-async-tools-ci-first.log`；后续 CI 继续执行全部四种 SDK 操作。
Windows 冻结版另通过 stdio MCP 的 103 工具枚举、离线 UI 预览、模拟任务关联、报告导出及 ZIP 哈希检查，
输出为 `dist/ui-async-tools-frozen-smoke.log`，交付包为 `dist/ReconBridge-PC-ui-async-tools-win64.zip`。
