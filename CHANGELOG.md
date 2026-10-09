# 变更日志

## 2026-10-09：动作学习、可观测性、JNI 注册观察与跨平台构建

本次将工作区中此前未提交的动作学习基础，与后续补齐的诊断、事件、JNI 和构建工作一起纳入版本控制。
提交前基线：`2703bd8`（master）。构建产物不代表已经完成真机兼容性验证。

### 动作学习基础

- PC 提供操作采集、多次示范比较、动态参数绑定、计划预览、单次执行、结果验证、导出与安装。
- Tracer 1.1.0 增加持久化执行预留、业务键去重、次数/间隔限制及结果确认。
- 捕获 Java 抛异常和字符串截断信息，避免误判示范/执行结果。
- Runtime Program 权限扫描覆盖 guarded actions；冻结版收集新增模块。
- stdio 使用既有标准流，避免冻结进程退出时包装器关闭底层句柄。
- 说明：[ACTION_LEARNING.md](pc/ACTION_LEARNING.md)。

### 统一诊断与事件完整性

- 新增 `diagnose_target`，汇总工具、daemon、安装版本、期望/实际 Hook、pending 类和 native observer 状态。
- 每条 daemon 事件附加递增序号与重启标识；快照原子读取事件和游标。
- 报告缓冲覆盖、请求截断、订阅队列丢弃与游标失效。
- 新增 `event_stream_status` 与按调查会话落盘的 `capture_event_window`。
- 动作示范遇到旧 daemon、重启或丢失时标记不完整并阻止生成可执行计划。
- 完整性仅覆盖 daemon 已收到的事件，上游丢失仍未知。

### JNI 注册观察

- 新增 `configure_jni_capture` / `inspect_jni_bindings`；PC 和手机 MCP 均可调用。
- 原生观察器记录成功 RegisterNatives 的 Java 类、方法、签名、地址、模块与偏移。
- 独立有界缓存保存注册历史；安装结果由 native runtime 回报。
- 仅观察启用后的注册，不枚举历史/静态绑定；未跟踪注销和卸载，地址可能过期。
- 原函数返回值与待处理异常保持不变；native 执行器跳过 Java/runtime targets。
- 说明：[OBSERVABILITY.md](pc/OBSERVABILITY.md)。

### 平台与构建

- jadx/Ghidra 在 Linux/macOS 直接执行脚本；Windows 批处理正确引用带空格及特殊字符的参数。
- 修复 Unix native 工具默认目录、按平台查找 adb、macOS JDK Contents/Home 布局。
- macOS 不再错误声称施加进程硬内存上限；保留超时、日志、并发和 JVM 堆预算。
- 新增跨平台 NDK 构建脚本和仅接受新构建产物的模块打包器。
- 校验源码指纹、NDK/API 一致性、ELF 架构、SHA-256、ZIP 路径和设备脚本换行。
- CI 新增三平台 PC 测试、NDK 双架构编译、验证后模块打包和 artifact 上传。
- 工具清单由注册信息生成，并由 CI 检查：PC 94 个、手机端 48 个。
- 说明：[BUILD_VALIDATION.md](BUILD_VALIDATION.md)、[TOOL_CATALOG.md](pc/TOOL_CATALOG.md)。

### 验证与交付记录

- PC：176 项测试通过。
- Tracer：54 项单元测试通过，debug APK 构建成功。
- C++：事件广播器并发/截断/重启测试、JNI 返回值/异常保持测试通过。
- NDK r27c：arm64-v8a/x86_64 的 daemon 与 Zygisk 编译成功。
- 模块 ZIP：打包与独立完整性校验通过。
- 本机真实 jadx 启动成功；Ghidra 启动到 Java headless usage（help 调用按工具行为返回 1）。
- 上一轮冻结版 MCP 通过 stdio 初始化和 94 工具枚举；后续跨平台修复以本次源码/CI 为准。
- 本地验证原始输出和产物摘要：[验证记录](docs/validation/2026-10-09/README.md)。
- 未执行真机部署/验证；按用户指示留待后续。远端 CI 结果以 GitHub Actions 记录为准。

### 后续工作

native Hook 物理撤钩/回收与浮点支持；UI 采集/回放；异步关联；报告/故障包；
JNI 静态导出与注销/卸载跟踪；apkanalyzer/UI Automator/Perfetto 接入。

## 2026-10-09：后续 native Hook 安装状态与错误反馈

- 第一批提交 `415d394` 已推送到 `master`，远端 8 个 CI 任务全部通过。
- Native Runtime 回报引擎状态、配置解析结果及每条 Hook 的真实安装结果。
- 修正非空 ShadowHook pending 句柄被误判为安装成功的问题，接入符号完成回调。
- 区分 pending/installing/installed/failed/timeout/rejected，保留错误码、原因和可获得的地址。
- x86_64 超时显式报告；永久安装失败停止重试。arm64 offset 注册加载回调后再次扫描，避免漏过加载窗口。
- 并发回调只允许一次安装；较晚到达的 pending 返回值不能覆盖安装完成结果。
- 无效配置与超出 slot 限制可见；引擎加载失败保持诊断连接至进程结束。
- PC 诊断对比期望与实际 native ID，不再把仅有 JNI/旧状态的连接认定为 Hook 健康。
- 更新双架构设备二进制、文档及 CI 宿主测试。
- 本地 Python 回归 189 项通过，新增 C++ 状态并发/异步顺序回归通过；详见 [后续验证记录](docs/validation/2026-10-09/native-status/README.md)。
- 仍未执行真机测试；native 实时卸载/替换、库卸载跟踪及浮点 ABI 支持留待后续。

## 2026-10-09：Native 运行中新增、停用与替换

- Native 连接声明 H(kind=native)，接收 R 完整配置并回报 v2 实际状态。
- 配置解析、唯一性和容量校验成功后原子切换；无效更新保留上一版本。
- 同一点复用跳板；代理对一次调用持有固定配置版本，事件附 native_config_revision。
- 移除采用透传停用，保留跳板和在途调用引用；不声明物理撤钩或槽位回收已完成。
- Dobby 安装改为单线程；稳定槽位不重用，停用/重新启用不重复消耗容量。
- daemon 握手补发最新配置，配置合并、写入和下发串行化；回复区分投递成功与实际生效。
- PC 正确区分支持实时更新的 native 与 Java 连接，并提示 JNI 变更仍需重启。
- 增加实际代理分派并发测试和 daemon socketpair 集成测试，更新双架构构建及工具文档。
- 本地 Python 193 项通过，C++ 实时配置/代理分派测试通过；完整记录见 [本批验证](docs/validation/2026-10-09/native-live/README.md)。
- 真机、Native 物理撤钩、库卸载和浮点支持仍未完成。
