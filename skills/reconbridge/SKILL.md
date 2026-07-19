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

## 什么时候用这个 skill
- 要从设备拉 APK / split / native 库并反编译定位代码；
- 要**运行时**看某个 Java 方法或 native 函数的 this/参数/返回值/私有字段/调用栈；
- 要**实时篡改**参数或返回值（不建 APK、不重编译）；
- 要脱壳 / dump 内存；
- 要回答「同一个 App 两种操作为什么行为不同」（场景差分）。

## 开工前（每次）
1. **先 `device_status`**：返回 `/health` 即连得上，顺带看传输方式与 base_url。连不上先排这里。
2. 这些工具在会话里可能是**延迟加载**的：先 `ToolSearch("select:mcp__reconbridge__device_status,mcp__reconbridge__list_packages,...")` 拿 schema 再调。
3. 传输默认 **adb**（自动 `adb forward` + 自动读设备 token，localhost-only）；多设备会自动挑唯一在线设备，仅当多台都在线才要你设 `RECONBRIDGE_SERIAL`。

## 25 个工具（按用途分组，签名详见各工具描述）
- **设备原子能力（7）**：`device_status` `list_packages` `pull_apk` `pull_libs` `read_remote_file` `proc_info` `remote_shell`（白名单）
- **静态反编译（5）**：`decompile_apk`(jadx) `dexkit_search`(androguard 后端) `ghidra_analyze` `hermes_decompile`(RN Hermes) `toolchain_status`
- **动态 hook / 事件（native，M3/M4）**：`post_hook` `list_hooks` `unhook` `collect_events` `recent_events`（环形缓冲事后补捞） `dump_dex`(脱壳) `list_dumps`
- **Java trace / 篡改（LSPosed，M5）**：`trace_java`（读 this/参数/返回值/字段/栈；支持 `capture.paths` 挖嵌套字段 + `render:"deep"` 对象图） `patch_java`（replace_args / replace_return / skip_original）
- **场景 / 产出物**：`capture_scenario` `diff_scenarios` `list_scenarios` `list_artifacts` `list_dumps`

## 三条主线（选一条走）

**A. 静态定位** —— 「这个功能的代码在哪」
`list_packages` → `pull_apk` → `decompile_apk`(jadx) → `dexkit_search` 按字符串/方法特征定位类与方法。native 逻辑：`pull_libs` → `ghidra_analyze`。

**B. 动态 trace** —— 「运行时到底传了什么 / 返回了什么」
`trace_java`（Java，走 LSPosed）或 `post_hook`（native，走 Zygisk）装 hook → 触发一次目标行为 → `collect_events`（实时早返回）或 `recent_events`（事后从环形缓冲补捞）。要挖对象内部字段用 `capture.paths` + `render:"deep"`。看完 `unhook`，Java 篡改类还要 `am force-stop` 目标恢复。

**C. 场景差分** —— 「A 操作与 B 操作为什么行为不同」
装 hook → `capture_scenario("A")` 做操作 A → `capture_scenario("B")` 做操作 B → `diff_scenarios("A","B")` 拿方法级差异（只在 A / 只在 B / 参数不同）。

## 顶级坑（踩过血的，务必记住）
1. **LSPosed tracer 有作用域**：`trace_java`/`patch_java` 只在 LSPosed 里**勾了作用域的那些包**内生效。目标不在作用域 → hook 装不上，且不报错。
2. **首个 hook 必 restart，之后才能 hot**：Java trace 首发让目标带配置冷启动（`hot=False`），注册为「可热加」后，第 2..N 个 hook 才能 `hot=True` 免 force-stop。native 层不支持热加。
3. **native 是广域注入，tracer 是单包**：daemon.log 里刷屏「注入层已连接」是 native（Zygisk）层，不是 tracer。native tag=`ReconBridge`，tracer tag=`ReconTracer`。
4. **logcat 可能被压制**：MIUI/HyperOS 会压第三方 App 的 logcat，`ReconTracer` 抓不到 tag **不代表 hook 没装**——是红鲱鱼，以事件流/命中数为准。
5. **稀疏事件靠环形缓冲**：偶发命中的方法别只等 SSE，用 `recent_events` / `collect_events(include_recent=True)` 事后补捞，避免空窗期提前返回收 0。
6. **可靠冷启动测事件流**：要稳定触发，用 native hook 打**有 launcher 的 App**（如 `com.android.vending`，`monkey -p PKG -c android.intent.category.LAUNCHER 1`）；无 launcher 的目标（如 voiceassist）只能靠触发助手冷启动，偶发不灵。
7. **改了 PC 侧 `pc/*.py` 要新会话生效**：MCP server 进程启动时加载代码；当前会话测新 tracer 能力可用 `post_hook` 发原始 config 绕过。
8. **adb 路径别被 Git Bash mangle**：跑 adb 前 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`，否则 `/data/...` 被改成 Windows 路径。

## 更深的细节
完整一页纸（全工具签名、协议、部署、更多坑）见仓库 `AGENTS_QUICKSTART.md`；在线安装用户见 GitHub：https://github.com/lm060719/reconbridge （`AGENTS_QUICKSTART.md`）。
