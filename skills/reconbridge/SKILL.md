---
name: reconbridge
description: >-
  Drive the ReconBridge toolchain to reverse-engineer / recon / tamper Android
  apps on a rooted (KernelSU) device from the PC side. Use whenever the task
  involves: pulling an APK or native .so off a device, decompiling with jadx,
  locating classes/methods with DexKit/androguard, Ghidra native analysis,
  hooking or tracing Java methods (LSPosed) or native functions (Zygisk/
  ShadowHook), watching runtime args/return-values/fields via SSE events,
  dumping memory / unpacking dex, or comparing two behaviors of an app. Trigger
  on: 逆向, Android hook, trace APK, LSPosed 侦察, 脱壳, dex dump, 抓参数/返回值,
  reconbridge, or any `mcp__reconbridge__*` tool. Authorized security research /
  CTF / defensive use on your own or explicitly-authorized targets only.
---

# ReconBridge — Android 逆向侦察 & 篡改工作流

> 面向已授权的安全研究 / CTF / 逆向学习 / 防御性研究。分析对象须为你自有或明确授权的设备与应用。

**架构一句话**：手机侧（KernelSU 模块）只做原子能力（拉包 / 读文件 / native hook / Java hook），所有智能在 PC 侧。你通过 `mcp__reconbridge__*` 工具下发指令、收结果。手机上跑两样：C++ 守护进程（HTTP 静态接口 + hook 分发 + SSE/WS 事件流）+ LSPosed Tracer 模块（数据驱动 Java trace/篡改）。

> 📌 **本文件是路由层**——够你起步即可。**全部工具签名、完整工作流代码示例、协议/部署、全部踩坑、Runtime Program（Phase 6-8）** 见仓库 `AGENTS_QUICKSTART.md`（在线安装用户见 GitHub：https://github.com/lm060719/reconbridge ）。它是唯一真相源；本文件只保留起步必需。

## 什么时候用这个 skill
- 从设备拉 APK / split / native 库并反编译定位代码；
- **运行时**看某个 Java 方法或 native 函数的 this/参数/返回值/私有字段/调用栈；
- **实时篡改**参数或返回值（不建 APK、不重编译）；
- 脱壳 / dump 内存；
- 回答「同一个 App 两种操作为什么行为不同」（场景差分）。

## 每次开工前
1. **先 `device_status`**：返回 `/health` 即连得上，顺带看传输方式与 base_url。连不上先排这里。
2. **默认进任务模式**：已知包名先 `open_target(package_name)` 拿 `session_id`，后续优先走高层入口，不要手工串 `pull_apk → dexkit_search → recent_events → unhook`，除非高层入口覆盖不了。
3. 这些工具在会话里可能**延迟加载**：优先搜索加载 `device_status,open_target,search_target,prepare_target,trace_target,investigation_status,close_investigation`；特殊需求再加载原子工具。
4. 传输默认 **adb**（自动 `adb forward` + 自动读设备 token，localhost-only）；多设备自动挑唯一在线设备，仅当多台都在线才需设 `RECONBRIDGE_SERIAL=<序列号>`。

> **常用默认入口**：`open_target` `search_target` `investigate`（一键自然语言调查）`inspect_method` `inspect_call_graph` `trace_target` `evidence_graph` `investigation_status` `close_investigation`。**高层入口与原子工具的完整清单 + 签名**在 `AGENTS_QUICKSTART.md` §3。

## 三条主线（选一条走）

**A. 静态定位** —— 「这个功能的代码在哪」
默认：`open_target` → `investigate(goal=...)` → `verify_call_path`。
若问题是「A 与 B 为什么不同」，走场景差分根因链：`capture_call_graph_scenario A/B → diff_call_graph_scenarios → analyze_scenario_divergence → capture_divergence_probe A/B → compare_divergence_probes → inspect_condition_origin → inspect_value_lineage → verify_value_lineage A/B → compare_value_lineage_runtime → rank_root_causes → verify_root_cause_hypothesis A/B → compare_root_cause_hypothesis`（每步输出含义见 QUICKSTART §5）。native 逻辑用 `pull_libs` → `ghidra_analyze`。

**B. 动态 trace** —— 「运行时到底传了什么 / 返回了什么」
静态定位出候选方法后直接 `trace_target(session_id, class_name, method)`，临时 Hook 通过 HookRegistry live unhook 自动清理。读写 State / 主动发 Event / 操作当前 Activity，用 Phase 5 远程命令（`runtime_state_*` / `runtime_event_emit` / `runtime_context_status` / `runtime_activity_action`），**别为此临时造 Java Hook**。验证通过、要长期保存的一组逻辑，固化成 Runtime Program（`runtime_program_*`），别继续堆裸 `post_hook`。

**C. 场景差分** —— 「A 操作与 B 操作为什么行为不同」
装 hook → `capture_scenario("A")` 做操作 A → `capture_scenario("B")` 做操作 B → `diff_scenarios("A","B")` 拿方法级差异（只在 A / 只在 B / 参数不同）。

## 最致命的 5 个坑（完整高频坑清单见 QUICKSTART §6）
1. **LSPosed tracer 有作用域**：`trace_java`/`patch_java` 只在 LSPosed 里勾了作用域的那些包内生效。目标不在作用域 → hook 装不上，**且不报错**。（模块本身也必须先在 LSPosed 管理器里人工启用。）
2. **logcat 可能被压制**：MIUI/HyperOS 会压第三方 App 的 logcat，抓不到 `ReconTracer` tag **不代表 hook 没装**——是红鲱鱼，以事件流/命中数为准。
3. **稀疏事件靠环形缓冲**：偶发命中的方法别只等 SSE，用 `collect_events(until_first_hit=True)` 或 `recent_events` 事后补捞，避免空窗期提前返回收 0。
4. **adb 路径别被 Git Bash mangle**：跑 adb 前 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`，否则 `/data/...` 被改成 Windows 路径。
5. **改了 PC 侧 `pc/*.py` 要新会话生效**：MCP server 进程启动时加载代码；当前会话想测新 tracer 能力可用 `post_hook` 发原始 config 绕过。
