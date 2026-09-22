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
2. **默认进入任务模式**：已知包名后先 `open_target(package_name)`，拿到 `session_id`。后续优先 `search_target` / `prepare_target` / `trace_target` / `investigation_status`，不要再手工串 `pull_apk → dexkit_search → recent_events → unhook`，除非高层入口覆盖不了需求。
3. 这些工具在会话里可能是**延迟加载**的：优先搜索 `device_status,open_target,search_target,prepare_target,trace_target,investigation_status,close_investigation`；只有特殊需求再加载原子工具。
4. 传输默认 **adb**（自动 `adb forward` + 自动读设备 token，localhost-only）；多设备会自动挑唯一在线设备，仅当多台都在线才要你设 `RECONBRIDGE_SERIAL`。

## 默认高层工具（优先使用）
- `open_target`：创建持久分析会话，自动绑定/按需拉取 APK 与已有产物。
- `search_target`：统一搜源码/字符串/类/方法/字段；已有 JADX 优先搜源码，否则查询 SQLite DEX 持久索引。首次索引由受限 Androguard worker 建立，之后不同关键词也不再解析 APK。
- `prepare_index`：可主动预热/重建当前 APK 的 DEX SQLite 索引；适合准备连续做大量静态搜索时先调用一次。
- `prepare_target`：只在确实需要完整源码时执行 JADX；已有结果直接复用。
- `investigate`：默认首选的一键调查入口；自然语言目标会自动走“关键词规划 → 索引 → 多词候选排序 → 可选批量 runtime 验证 → 主候选 callers/callees + JADX 源码上下文 → 证据汇总”，运行时不可用时仍保留静态与源码结果。
- `inspect_method`：已知具体类/方法时，直接展开一层 callers、callees、关联字符串、同类字段和 JADX 方法体；没有源码时默认自动准备一次。
- `inspect_call_graph`：递归向上/向下追调用链，默认各 2 层；返回完整 nodes/edges 和“入口 → 目标 → 下游”代表路径，并叠加已有 runtime 命中覆盖。
- `verify_call_path`：对一条代表路径上的方法统一挂 before Hook；触发一次目标行为后按 ts/seq/tid 还原真实顺序，返回 node/edge coverage、完整路径是否出现和相邻入口 delta_ms。
- `capture_call_graph_scenario`：围绕同一目标方法对整张局部调用图挂同一组 before Hook，采集一次命名场景；默认不展开框架节点，结果独立存盘，不塞进主会话 JSON。
- `diff_call_graph_scenarios`：比较两个同图同 Hook 集合的场景，输出公共前缀、首次分叉、仅 A/仅 B 节点与边，以及共享边耗时差。
- `analyze_scenario_divergence`：取 A/B 公共前缀最后一个方法，自动回到 JADX 源码识别 if/else、switch、Kotlin when、三元表达式，按两侧下一跳方法做可解释排序，并生成只读 trace 探针计划。
- `capture_divergence_probe`：按分叉条件排名自动执行一个安全探针；字段用 branch method 的 before 抓 `this.field`，条件方法用 after 抓返回值。结果压缩写回对应场景文件。
- `compare_divergence_probes`：比较同一探针在 A/B 下的稳定值；布尔条件会检查是否与 `a_false_b_true / a_true_b_false` 源码方向一致。
- `inspect_condition_origin`：从已验证的字段/条件方法继续追值来源。DEX v3 会直接给出字段所有 reader/writer 与 bytecode offset；JADX 再解释 writer 赋值右值来自 Preferences、Intent/Bundle、数据库/缓存、Repository/API、用户模型、参数或常量。
- `verify_condition_writer`：对同类实例字段的高排名 writer 同时抓 before/after 字段值，判断该方法是否真的在一次行为里改变目标条件字段。
- `inspect_value_lineage`：跨方法递归追条件值来源。字段从指定 writer 的赋值右值出发，条件方法从 return 出发；把源码调用与 DEX callees 对齐后继续进入下层方法 return，输出“上游来源 → … → 条件字段/方法”的 origin_paths。遇到同名 callee 歧义只报告 candidates，不自动猜类型。
- `verify_value_lineage`：对一条 origin_path 的应用方法统一抓 after 返回值；若路径最终落到同类实例字段，最后 writer 同时抓 before/after 字段值。按 tid/ts 还原真实返回顺序并保存压缩结果。
- `compare_value_lineage_runtime`：比较 A/B 同一条 Runtime Value Lineage，每层并排显示稳定返回值，定位最早稳定值差异，同时报告两侧完整链覆盖和最终 writer 字段变化。
- `rank_root_causes`：综合最早稳定值差异、A/B 实际命中、完整 Runtime Lineage、writer 字段变化、既有 runtime hits、静态来源置信度和路径支持度，对方法/来源节点做可解释根因排序；返回 score_breakdown、evidence_level 和下一步动作，并把排名写回 Evidence Graph。
- `verify_root_cause_hypothesis`：针对一个方法根因候选生成最小输入/输出实验。优先精确重载，只抓 descriptor 参数、源码实际引用的类字段和返回值；第二侧完成后自动判断“内部产生 / 上游输入已不同 / 未复现 / 证据不足”，并立即重排根因。
- `compare_root_cause_hypothesis`：重新比较已经保存的 A/B 最小实验，返回 baseline_rank/score 与 updated_candidate/updated_ranking；实验始终按 candidate_key 指纹绑定，不会因重排后名次变化而错配。
- `rank_candidates`：需要手工控制时，综合字符串 xref、方法名/类名和 Evidence Graph 对候选方法做可解释排序。
- `verify_candidates`：一次性给前 N 个候选装观测 Hook，共享一个采集窗口；触发一次行为即可知道谁真实命中。
- `trace_target`：已知具体方法时的单方法精细 trace，自动包名/游标/唯一 hook id，默认命中即返回并清理临时 Hook；命中会自动写入证据图。
- `evidence_graph`：查看当前会话的字符串、类、方法、字段、源码命中和运行时验证关系图。
- `explain_evidence`：围绕一个关键词/方法/字段展开已有证据链，快速回答“为什么怀疑这里、哪些已运行时确认”。
- `investigation_status`：查看会话资产、发现记录、运行时状态和证据图规模。
- `close_investigation`：结束会话并默认清理目标 Hook。

## 原子工具（高级/兜底用途，签名详见各工具描述）
- **设备原子能力（7）**：`device_status` `list_packages` `pull_apk` `pull_libs` `read_remote_file` `proc_info` `remote_shell`（白名单）
- **静态反编译（5）**：`decompile_apk`(jadx) `dexkit_search`(androguard 后端) `ghidra_analyze` `hermes_decompile`(RN Hermes) `toolchain_status`
- **动态 hook / 事件 / Runtime 状态（M3/M5/M4）**：`post_hook` `list_hooks`（磁盘期望配置） `runtime_hook_status`（运行中 M5：installed/pending/loader/watcher + Runtime State + Event Bus + Context/Lifecycle） `runtime_state_get/set/remove/increment/append/clear` `runtime_event_emit` `runtime_context_status` `runtime_activity_action` `runtime_program_install/replace/enable/disable/rollback/status` `unhook`（只管理手工 Hook；Program 用 Program API） `collect_events` `recent_events`（环形缓冲事后补捞） `dump_dex`(脱壳) `list_dumps`
- **Java trace / 篡改（LSPosed，M5）**：`trace_java`（读 this/参数/返回值/字段/栈；支持 `capture.paths` 挖嵌套字段 + `render:"deep"` 对象图） `patch_java` / `post_hook`（Action Pipeline 支持 State/Event；模板/条件还可直接读 `application/context/activity/lifecycle.*`；`kind:"runtime"` 可用 `on_event` 或 `on_lifecycle` 做事件/Activity 生命周期触发）
- **场景 / 产出物**：`capture_scenario` `diff_scenarios` `list_scenarios` `list_artifacts` `list_dumps`

## 三条主线（选一条走）

**A. 静态定位** —— 「这个功能的代码在哪」
默认：`open_target` → `investigate(goal=...)` → `verify_call_path`。如果问题是“A 与 B 为什么不同”，走 `capture_call_graph_scenario A/B → diff_call_graph_scenarios → analyze_scenario_divergence → capture_divergence_probe A/B → compare_divergence_probes → inspect_condition_origin → inspect_value_lineage → verify_value_lineage A/B → compare_value_lineage_runtime → rank_root_causes → verify_root_cause_hypothesis A/B → compare_root_cause_hypothesis`。字段条件可先用 `verify_condition_writer` 确认真实 writer。根因假设实验会反向加权/降权排名：入口一致而输出不同才支持内部产生；入口已不同则把方向推回上游。DEX v3 持久化字段 read/write xref；Lineage 对同名 callee 保守处理。对象接收者先解析实际类型；native 逻辑仍用 `pull_libs` → `ghidra_analyze`。

**B. 动态 trace** —— 「运行时到底传了什么 / 返回了什么」
Phase 5 远程 Runtime 控制优先使用 `runtime_state_get/set/remove/increment/append/clear`、`runtime_event_emit`、`runtime_context_status`、`runtime_activity_action`，不要为了读写 State、主动发 Event 或操作当前 Activity 临时造 Java Hook。验证通过、需要长期保存的一组 Hook/State/Event/Lifecycle 逻辑，优先固化成 Phase 6 Runtime Program，而不是继续堆裸 post_hook。多进程 App 若只想操作一个进程，显式传 `process`；不传会对所有在线 Runtime Command-capable 进程分别执行。远程命令不支持 thread scope，因为 socket 命令线程不能代表业务 Hook 的 ThreadLocal。

默认：静态定位出候选方法后直接 `trace_target(session_id, class_name, method)`，临时 Hook 通过 HookRegistry live unhook 自动清理。持续 patch 若存在跨 Hook 状态，优先用 Runtime State + Event Bus；若逻辑依赖“进入某 Activity / Application 已就绪 / 当前 Context”，优先用 `kind:"runtime"/on_lifecycle`，Action 里直接访问 `application/context/activity/lifecycle.*`，不要再额外 Hook 每个 Activity 子类的 onResume。用 `runtime_hook_status(package)` 核对 installed/pending、state/event、`context_runtime` 和 `lifecycle_runtime`。

**C. 场景差分** —— 「A 操作与 B 操作为什么行为不同」
装 hook → `capture_scenario("A")` 做操作 A → `capture_scenario("B")` 做操作 B → `diff_scenarios("A","B")` 拿方法级差异（只在 A / 只在 B / 参数不同）。

## 顶级坑（踩过血的，务必记住）
1. **LSPosed tracer 有作用域**：`trace_java`/`patch_java` 只在 LSPosed 里**勾了作用域的那些包**内生效。目标不在作用域 → hook 装不上，且不报错。
2. **首个 hook 先让 M5 Tracer 上线，之后全量 reconcile**：首发最稳妥仍用 `restart:true`。Tracer 已连接后，`hot=True` / `restart:false` 会同步完整期望配置，HookRegistry 可 live add/remove/replace；显式类当前不存在会进入 pending，BaseDexClassLoader / loadClass watcher 后续自动补装。同 ID 改配置会即时替换，`unhook` 会即时卸载 installed 并删除 pending。用 `runtime_hook_status` 核对 installed_count / pending_count / class_loaders / class_loader_watch。native M3 仍不支持这套 live 生命周期。
3. **native 是广域注入，tracer 是单包**：daemon.log 里刷屏「注入层已连接」是 native（Zygisk）层，不是 tracer。native tag=`ReconBridge`，tracer tag=`ReconTracer`。
4. **logcat 可能被压制**：MIUI/HyperOS 会压第三方 App 的 logcat，`ReconTracer` 抓不到 tag **不代表 hook 没装**——是红鲱鱼，以事件流/命中数为准。
5. **稀疏事件靠环形缓冲**：偶发命中的方法别只等 SSE，用 `recent_events` / `collect_events(include_recent=True)` 事后补捞，避免空窗期提前返回收 0。
6. **可靠冷启动测事件流**：要稳定触发，用 native hook 打**有 launcher 的 App**（如 `com.android.vending`，`monkey -p PKG -c android.intent.category.LAUNCHER 1`）；无 launcher 的目标（如 voiceassist）只能靠触发助手冷启动，偶发不灵。
7. **改了 PC 侧 `pc/*.py` 要新会话生效**：MCP server 进程启动时加载代码；当前会话测新 tracer 能力可用 `post_hook` 发原始 config 绕过。
8. **adb 路径别被 Git Bash mangle**：跑 adb 前 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`，否则 `/data/...` 被改成 Windows 路径。
9. **M5 unhook 已经是 live 的**：不要再机械地 force-stop。`unhook` 后优先 `runtime_hook_status(package)` 确认 id/member/事件 handler 已消失；对应 hook-scope State 会一并清理。同 ID replace 会保留 hook-scope State，适合热更新状态机逻辑。只有 native M3 或旧版 Tracer 才需要重启进程。
10. **Event Bus 是进程内同步分发**：handler 在 emit 的当前线程执行，修改 State 会立即可见；不要在 handler 里做无限递归 emit 或长时间阻塞。运行时有 max_depth=16 保护，但复杂耗时任务仍应谨慎。
11. **Lifecycle Context 不强持有 Activity**：当前 Activity 用 WeakReference；`activity.*` 在页面不存在/已回收时会 unresolved。需要页面级触发优先 `on_lifecycle`，Compose/Fragment 状态仍需业务 Hook。Lifecycle status 刷新会后台合并，不阻塞 Activity 主线程。

## 更深的细节
完整一页纸（全工具签名、协议、部署、更多坑）见仓库 `AGENTS_QUICKSTART.md`；在线安装用户见 GitHub：https://github.com/lm060719/reconbridge （`AGENTS_QUICKSTART.md`）。


- **Runtime Program Package（M5 Phase 7）**：跨设备/跨 PC 分享 Program 时，优先用 `runtime_program_export` 生成 Ed25519 签名 `.rbprog.json`，用 `runtime_program_verify_package` 验证哈希/签名/permissions/allowed_packages，再用 `runtime_program_import` 安装。默认只接受 trusted signer；`runtime_program_trust_signer` 前应先核对公钥指纹。daemon 会再次扫描 manifest 权限，不能靠绕过 PC 隐藏高风险 Action。


- **Runtime Program Permission Policy（M5 Phase 8）**：设备端通过 `runtime_program_policy_status/set` 管理 allow/ask/deny；`runtime_program_approve` / `runtime_program_revoke_approval` 管理 Program 持久批准，生命周期工具可用 `approve_once` 做当前 revision 激活批准。deny 永远优先；策略收紧会立即 live disable + cleanup。签名可信与设备权限放行是两件独立的事。
