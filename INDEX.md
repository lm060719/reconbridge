**中文** | 索引 · Project Index

# ReconBridge 项目索引

> 本文件是整个仓库的**导航地图**：按模块列出每个目录与关键文件的职责，方便人或 AI agent 快速定位。
> 上手请先读 [`AGENTS_QUICKSTART.md`](AGENTS_QUICKSTART.md)（全部 MCP 工具签名 + 工作流），背景见 [`README.md`](README.md)。
> 维护提示:新增/移动源码文件后，更新对应小节的一行描述即可。

---

## 1. 这是什么

**ReconBridge** —— 运行在 Android（KernelSU root）设备上的通用逆向分析后端。架构上**能力下沉、智能上移**:

- **手机侧** 只做原子能力:拉包 / 读文件 / 列 so / procfs / 注入 hook / 下发 trace。(C++ daemon + Zygisk native + LSPosed Java tracer)
- **PC 侧** 承载全部智能:定位函数、生成 hook、建 DEX 索引、证据图、根因分析，经 **MCP** 暴露给 Claude Code / ChatGPT Codex。(Python)

进度:M1–M5 均已完成并真机验证(Xiaomi SM8750 / Android 16 / KernelSU + ZygiskNext + LSPosed)。

| 里程碑 | 内容 | 主要位置 |
|---|---|---|
| **M1** | 静态传输层守护进程(HTTP 原子能力) | [`src/daemon.cpp`](src/daemon.cpp)、[`module/`](module/) |
| **M2** | PC 端 MCP server + 本地反编译工具链 | [`pc/reconbridge_mcp/`](pc/reconbridge_mcp/) |
| **M3** | Zygisk 注入 + ShadowHook native hook + 事件推流 | [`m3/`](m3/)、[`src/dynamic.cpp`](src/dynamic.cpp) |
| **M4** | hook 配置模板(反调试 / 脱壳 / root 检测定位) | [`m4/templates/`](m4/templates/) |
| **M5** | 通用 Java trace + 实时篡改(LSPosed 模块) | [`m5/tracer/`](m5/tracer/) |

---

## 2. 顶层目录速览

Native v3 生命周期入口见 [NATIVE_LIFECYCLE.md](pc/NATIVE_LIFECYCLE.md)：
`m3/zygisk/native_runtime.h` 管理引擎和 loader；`native_lifetime.h` 管理在途计数；
`native_gateway.h` 提供不可变 RX 入口；`library_lifetime.h` 跟踪库代次；
`native_observation.h` 为 JNI 与 loader 提供共同观察序号。

| 路径 | 说明 |
|---|---|
| [`pc/`](pc/) | **PC 端 MCP server**(Python)+ 全部单元/e2e 测试。项目智能主体。 |
| [`src/`](src/) | 手机侧 **C++** 源码:M1 守护进程 + M3 动态子系统 + mobile_mcp。 |
| [`module/`](module/) | 可刷入的 **KernelSU 模块**成品(daemon 二进制、zygisk .so、rbctl、安装脚本)。 |
| [`m3/`](m3/) | M3 Zygisk 注入层源码、ShadowHook 预编译库、hook 协议文档。 |
| [`m4/`](m4/) | M4 hook 配置 **JSON 模板**。 |
| [`m5/`](m5/) | M5 **LSPosed tracer**(Kotlin Android 工程)+ Java hook 协议 + 成品 APK。 |
| [`scripts/`](scripts/) | 安装 / 卸载 / 在线安装 / MCP 注册脚本。 |
| [`skills/`](skills/) | `reconbridge` skill(逆向任务时自动加载的工作流)。 |
| [`dist/`](dist/) | PyInstaller 打包的 MCP exe 成品(onedir)。 |
| `*.ps1` / `*.sh` | 根级构建/打包/安装脚本(见 §8)。 |
| `README*.md` / `AGENTS_QUICKSTART.md` | 文档(见 §3)。 |

---

## 3. 文档索引

| 文件 | 内容 |
|---|---|
| [`README.md`](README.md) / [`README_en.md`](README_en.md) | 项目总览、快速开始、安装方式、免责声明。 |
| [`AGENTS_QUICKSTART.md`](AGENTS_QUICKSTART.md) | **一页纸速查**:全部 MCP 工具签名、M5 用法、典型工作流、高频坑。给 AI agent 的首选入口。 |
| [`m3/HOOK_PROTOCOL.md`](m3/HOOK_PROTOCOL.md) | M3 native hook 配置下发 + 事件推流协议。 |
| [`m3/README.md`](m3/README.md) / [`_en`](m3/README_en.md) | M3 Zygisk 注入层说明。 |
| [`m4/README.md`](m4/README.md) / [`_en`](m4/README_en.md) | M4 模板用法。 |
| [`m5/README.md`](m5/README.md) / [`_en`](m5/README_en.md) | M5 tracer 用法、`trace_java` / `patch_java`。 |
| [`m5/JAVA_HOOK_PROTOCOL.md`](m5/JAVA_HOOK_PROTOCOL.md) | M5 Java hook / Action Pipeline / Runtime Program 协议。 |
| [`LICENSE`](LICENSE) | 许可证。 |
| [`pc/UI_ASYNC_WORKFLOW.md`](pc/UI_ASYNC_WORKFLOW.md) | UI 采集/回放、任务对象异步关联、离线报告与 Android 工具入口。 |

---

## 4. PC 端 MCP Server — `pc/reconbridge_mcp/`

Python 包,入口 `python -m reconbridge_mcp`(stdio MCP)。

### 入口 & 基础设施
| 文件 | 职责 |
|---|---|
| [`observability.py`](pc/reconbridge_mcp/observability.py) | 统一诊断、事件完整性判定与会话 JSONL 采集。 |
| [`device_tools.py`](pc/reconbridge_mcp/device_tools.py) | 有界二进制 adb、SDK apkanalyzer 与设备 Perfetto。 |
| [`ui_workflow.py`](pc/reconbridge_mcp/ui_workflow.py) | UI 层级/截图、精确选择器回放与事件窗口回执。 |
| [`async_analysis.py`](pc/reconbridge_mcp/async_analysis.py) | 显式任务 Hook 配置与跨线程对象身份关联。 |
| [`reports.py`](pc/reconbridge_mcp/reports.py) / [`workflow_artifacts.py`](pc/reconbridge_mcp/workflow_artifacts.py) | 会话证据归档、HTML/JSON 报告、脱敏故障包及哈希清单。 |
| [`jni.py`](pc/reconbridge_mcp/jni.py) | 显式配置 native JNI 注册观察器与读取映射历史。 |
| [`server.py`](pc/reconbridge_mcp/server.py) | **MCP 工具总入口**(~187 KB):把 M1 静态接口 + 本地工具链 + 各分析器注册为 Claude Code 可调用工具。 |
| [`__main__.py`](pc/reconbridge_mcp/__main__.py) / [`__init__.py`](pc/reconbridge_mcp/__init__.py) | 包入口。 |
| [`settings.py`](pc/reconbridge_mcp/settings.py) | 运行配置,全部走环境变量。 |
| [`client.py`](pc/reconbridge_mcp/client.py) | 与手机 M1 守护进程通信的 HTTP 客户端(adb / wifi 两种传输)。 |
| [`resource.py`](pc/reconbridge_mcp/resource.py) | 重型本地工具(jadx/Ghidra/Hermes/Androguard worker)统一资源治理与并发限制。 |
| [`external.py`](pc/reconbridge_mcp/external.py) | 本地反编译工具链集成:jadx / DexKit / Ghidra headless / Hermes,带缺失指引。 |
| [`register.py`](pc/reconbridge_mcp/register.py) | 把 MCP server 注册进 Claude Code / Codex 用户级配置。 |
| [`webconsole.py`](pc/reconbridge_mcp/webconsole.py) + [`webconsole.html`](pc/reconbridge_mcp/webconsole.html) | 本地 Web 控制台(`--serve`):选连接方式 / 看状态 / 只读监控。 |

### DEX 索引 & 候选定位
| 文件 | 职责 |
|---|---|
| [`dex_index.py`](pc/reconbridge_mcp/dex_index.py) | APK DEX **持久 SQLite 索引**:搜索 / 字符串 xref / 调用关系直接查库。 |
| [`dex_worker.py`](pc/reconbridge_mcp/dex_worker.py) | Androguard **隔离 worker**:重解析放短生命周期子进程,一次性建库。 |
| [`candidate.py`](pc/reconbridge_mcp/candidate.py) | 候选方法确定性启发式排序(带 reasons 解释)。 |

### 调查会话 & 证据
| 文件 | 职责 |
|---|---|
| [`investigation.py`](pc/reconbridge_mcp/investigation.py) | 高层**分析会话**:持久化包名/APK/JADX 目录/搜索状态(~42 KB)。 |
| [`pipeline.py`](pc/reconbridge_mcp/pipeline.py) | 自动 Investigation Pipeline 纯逻辑。 |
| [`evidence.py`](pc/reconbridge_mcp/evidence.py) | **Evidence Graph**:静态搜索/xref/源码命中/运行时 trace 自动沉淀为证据图。 |

### 场景差分 & 根因分析
| 文件 | 职责 |
|---|---|
| [`scenario_path.py`](pc/reconbridge_mcp/scenario_path.py) | 调用图场景采集与差异分析纯逻辑(A/B 比较命中节点/边覆盖/首次分叉)。 |
| [`branch_condition.py`](pc/reconbridge_mcp/branch_condition.py) | A/B 首次分叉的**源码条件定位**(if/else/switch/when/三元)。 |
| [`condition_probe.py`](pc/reconbridge_mcp/condition_probe.py) | 分叉条件的运行时探针值提取与比较。 |
| [`state_origin.py`](pc/reconbridge_mcp/state_origin.py) | 条件字段/方法的静态值来源解释。 |
| [`writer_probe.py`](pc/reconbridge_mcp/writer_probe.py) | 字段 writer 的运行时 before/after 变化分析。 |
| [`value_lineage.py`](pc/reconbridge_mcp/value_lineage.py) | 跨方法 Value Lineage 图的构建与解析。 |
| [`runtime_lineage.py`](pc/reconbridge_mcp/runtime_lineage.py) | 跨方法 Value Lineage 的运行时验证与 A/B 比较。 |
| [`runtime_path.py`](pc/reconbridge_mcp/runtime_path.py) | 静态代表路径的运行时验证与时间线分析。 |
| [`root_cause.py`](pc/reconbridge_mcp/root_cause.py) | 综合静态 + 运行时 lineage 的**根因候选排序**。 |
| [`hypothesis_verify.py`](pc/reconbridge_mcp/hypothesis_verify.py) | Root Cause 假设实验规划、单场景摘要与 A/B 验证。 |

### Runtime Program(M5 可移植程序)
| 文件 | 职责 |
|---|---|
| [`program_package.py`](pc/reconbridge_mcp/program_package.py) | Runtime Program 可移植**签名包**、权限扫描与 signer 信任管理。 |
| [`resource.py`](pc/reconbridge_mcp/resource.py) | (见上)资源治理。 |

### 其他
| 文件 | 职责 |
|---|---|
| [`mcp_entry.py`](pc/mcp_entry.py) | 打包 exe 的入口包装。 |

---

## 5. 手机侧 C++ — `src/`

| 文件 | 职责 |
|---|---|
| [`daemon.cpp`](src/daemon.cpp) | **M1 静态传输层守护进程**:KernelSU root 下提供局域网 HTTP 原子能力(拉包/读文件/列 so/procfs/白名单 shell)。 |
| [`dynamic.cpp`](src/dynamic.cpp) + [`dynamic.h`](src/dynamic.h) | **M3 动态子系统**:`/hook` `/unhook` `/hooks` + SSE/WS 事件推流,与 M1 解耦。 |
| [`event_stream.h`](src/event_stream.h) | 带序号、重启标识、丢弃统计与原子快照的事件广播器。 |
| [`mobile_mcp.cpp`](src/mobile_mcp.cpp) + [`mobile_mcp.h`](src/mobile_mcp.h) | 手机侧 mobile-mcp 能力。 |
| [`third_party/httplib.h`](src/third_party/httplib.h) · [`json.hpp`](src/third_party/json.hpp) | 第三方库(cpp-httplib / nlohmann-json)。 |

构建:[`CMakeLists.txt`](CMakeLists.txt) + [`build.ps1`](build.ps1)(NDK 交叉编译 arm64 + x86_64)。

---

## 6. KernelSU 模块成品 — `module/`

刷入设备的模块包。

| 路径 | 说明 |
|---|---|
| [`module.prop`](module/module.prop) | 模块元信息。 |
| [`customize.sh`](module/customize.sh) / [`service.sh`](module/service.sh) | 安装 / 开机启动脚本。 |
| [`sepolicy.rule`](module/sepolicy.rule) | SELinux 策略。 |
| [`rbctl`](module/rbctl) | 设备侧控制 CLI。 |
| `bin/reconbridge_daemon*` | M1 daemon 二进制(arm64 + x86_64)。 |
| `zygisk/arm64-v8a.so` · `x86_64.so` | M3 Zygisk 注入模块。 |
| `system_lib64_*/` | ShadowHook / Dobby 运行时库。 |
| [`webroot/index.html`](module/webroot/index.html) | 模块 WebUI。 |

---

## 7. M3 Zygisk 注入层 — `m3/`

| 路径 | 说明 |
|---|---|
| [`zygisk/module.cpp`](m3/zygisk/module.cpp) | **Zygisk 注入层 + 数据驱动 ShadowHook 执行器**。 |
| [`zygisk/jni_observer.h`](m3/zygisk/jni_observer.h) | 观察成功 RegisterNatives 调用，报告 Java 签名到模块地址/偏移的映射历史。 |
| [`zygisk/third_party/`](m3/zygisk/third_party/) | dobby.h / shadowhook.h / zygisk.hpp / json.hpp。 |
| [`prebuilt/`](m3/prebuilt/) | libshadowhook / libdobby 预编译 .so。 |
| [`build_dobby_x86_64.ps1`](m3/build_dobby_x86_64.ps1) + [`dobby-android-build-fix.patch`](m3/dobby-android-build-fix.patch) | Dobby 构建脚本与补丁。 |

---

## 8. M4 模板 — `m4/templates/`

数据驱动的 hook 配置 JSON,直接下发即可定位常见对抗点:

| 模板 | 用途 |
|---|---|
| [`anti_debug_ptrace.json`](m4/templates/anti_debug_ptrace.json) | 反调试 ptrace 定位。 |
| [`dump_dex_art.json`](m4/templates/dump_dex_art.json) | ART dex 脱壳。 |
| [`frida_xposed_locate.json`](m4/templates/frida_xposed_locate.json) | Frida/Xposed 检测点定位。 |
| [`root_detection_locate.json`](m4/templates/root_detection_locate.json) | root 检测定位。 |

---

## 9. M5 LSPosed Tracer — `m5/tracer/`

通用 Java trace + 实时篡改 Android 工程(Kotlin,LSPosed 模块)。源码在 `app/src/main/java/com/reconbridge/tracer/`:

| 文件 | 职责 |
|---|---|
| [`HookEntry.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/HookEntry.kt) | Xposed 入口;双通道日志(logcat + XposedBridge)。 |
| [`HookRegistry.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/HookRegistry.kt) | Java 方法 hook 的注册与生命周期管理。 |
| [`ActionExecutor.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/ActionExecutor.kt) | Action Pipeline 执行器(实时篡改参数/返回值/字段)。 |
| [`RuntimeCommandDispatcher.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/RuntimeCommandDispatcher.kt) | PC 下发命令分发。 |
| [`RuntimeEventBus.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/RuntimeEventBus.kt) | 运行时事件推流总线。 |
| [`RuntimeStateStore.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/RuntimeStateStore.kt) | Runtime Program 状态存储。 |
| [`InjectSocket.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/InjectSocket.kt) | LocalSocket 注入通道(与 daemon 通信)。 |
| [`ClassLoaderRegistry.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/ClassLoaderRegistry.kt) / [`ClassLoaderWatcher.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/ClassLoaderWatcher.kt) | 动态 ClassLoader 监听与登记。 |
| [`ContextRegistry.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/ContextRegistry.kt) | Application/Activity Context 登记。 |
| [`DexStringSearcher.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/DexStringSearcher.kt) | 设备侧 dex 字符串搜索。 |
| [`LifecycleManager.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/LifecycleManager.kt) / [`LifecycleTrigger.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/LifecycleTrigger.kt) | 生命周期触发(`on_lifecycle`)。 |
| [`MainActivity.kt`](m5/tracer/app/src/main/java/com/reconbridge/tracer/MainActivity.kt) | 说明页(无本地配置,一切由 PC 下发)。 |

测试在 `app/src/test/kotlin/...`(9 个单元测试)。成品:[`m5/ReconBridge-Tracer.apk`](m5/ReconBridge-Tracer.apk)。

---

## 10. 构建 / 安装 / 打包脚本

跨平台构建与验证入口：[`scripts/build_native.py`](scripts/build_native.py) 编译两种 ABI，
[`scripts/package_module.py`](scripts/package_module.py) 校验清单并打包；流程见
[`BUILD_VALIDATION.md`](BUILD_VALIDATION.md)。

| 脚本 | 用途 |
|---|---|
| [`build.ps1`](build.ps1) | NDK 交叉编译手机侧 C++(daemon + zygisk)。 |
| [`build_exe.ps1`](build_exe.ps1) | PyInstaller 打包 MCP server 为 onedir exe(→ `dist/`)。 |
| [`pack.ps1`](pack.ps1) | 打包 KernelSU 模块 zip。 |
| [`install.ps1`](install.ps1) / [`install.sh`](install.sh) | 源码方式安装 MCP。 |
| [`scripts/install-online.ps1`](scripts/install-online.ps1) | 一行在线安装(下载 exe + 注册 + 铺 skill)。 |
| [`scripts/install_mcp.py`](scripts/install_mcp.py) | MCP 注册逻辑。 |
| [`scripts/uninstall.ps1`](scripts/uninstall.ps1) | 卸载。 |

---

## 11. 测试 / CI / 配置

- **测试**(`pc/test_*.py`,22 个):单元 + e2e,覆盖 dex_index、evidence、investigation、scenario_path、root_cause、runtime_*、program_package、MCP e2e(含真机 `test_mobile_mcp_e2e.py`)等。
- **CI**:[`.github/workflows/pc-tests.yml`](.github/workflows/pc-tests.yml) 跑 PC 端测试。
- **MCP 配置**:[`.mcp.json.example`](.mcp.json.example)(本地 `.mcp.json` 已 gitignore)。
- **Skill**:[`skills/reconbridge/SKILL.md`](skills/reconbridge/SKILL.md) —— 逆向任务工作流,安装时铺到客户端。

---

## 快速定位备忘

- **加/改一个 MCP 工具** → [`pc/reconbridge_mcp/server.py`](pc/reconbridge_mcp/server.py)(+ 对应分析器模块 + `pc/test_*.py`)。
- **改手机↔PC 传输** → [`client.py`](pc/reconbridge_mcp/client.py)(PC 侧)/ [`src/daemon.cpp`](src/daemon.cpp)(设备侧)。
- **改 native hook 行为** → [`m3/zygisk/module.cpp`](m3/zygisk/module.cpp) + [`src/dynamic.cpp`](src/dynamic.cpp)。
- **改 Java trace / 实时篡改** → `m5/tracer/app/src/main/java/com/reconbridge/tracer/`。
- **发版** → `build.ps1` → `build_exe.ps1` → `pack.ps1`,成品进 `dist/` 与 GitHub Release。
## Native 实时配置补充

- [运行中新增、停用、替换及能力边界](pc/NATIVE_LIVE.md)

- [Native float/double 签名、采集与替换](pc/NATIVE_FLOAT.md)

- [JNI 生命周期映射与静态导出候选](pc/JNI_MAPPINGS.md)
