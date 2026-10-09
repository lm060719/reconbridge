# MCP 工具清单

由 `scripts/generate_tool_catalog.py` 自动生成。PC 来自实际注册；手机端来自源码声明，非真机探测。

PC：**94**；手机端：**48**。接口及功能范围以各工具说明为准。

| 工具 | PC | 手机 | 说明 |
|---|---|---|---|
| `analyze_scenario_divergence` | ✓ | — | 从 A/B 调用图场景首次分叉自动定位源码条件。 |
| `begin_action_capture` | ✓ | — | Arm click/long-click + exact candidate methods, then return for manual demonstration. |
| `capture_call_graph_scenario` | ✓ | — | 围绕同一目标方法采集一次可做 A/B 差分的真实调用图场景。 |
| `capture_divergence_probe` | ✓ | — | 采集 A/B 首次分叉条件的一个运行时值探针。 |
| `capture_event_window` | ✓ | — | Poll events into a session JSONL file (up to 60s). Report every gap/restart/error. |
| `capture_scenario` | ✓ | ✓ | 记录一个「场景」的命中时间线，存盘供 diff_scenarios 比对（P2）。 |
| `check_action_compatibility` | ✓ | — | Check installed version and all locally bound APK hashes before execution. |
| `close_investigation` | ✓ | — | 结束分析会话；默认同时清理该目标包由分析过程留下的 hook。 |
| `collect_events` | ✓ | ✓ | 连 hook 事件流(SSE)收集命中事件（参数/返回值/调用栈/dump 通知）。 |
| `compare_action_demonstrations` | ✓ | — | Identify observed constants, dynamic values, missing parameters and ambiguous hits. |
| `compare_divergence_probes` | ✓ | — | 比较已经采集的 A/B 条件探针值，并判断是否与源码 true/false 分支方向一致。 |
| `compare_root_cause_hypothesis` | ✓ | — | 重新比较已采集的根因假设实验，并返回验证前/后的根因排名变化。 |
| `compare_value_lineage_runtime` | ✓ | — | 比较已采集的 A/B Runtime Value Lineage，找最早稳定值差异。 |
| `configure_jni_capture` | ✓ | ✓ | Enable/disable observation of future successful RegisterNatives calls. |
| `create_action_plan` | ✓ | — | Generate a module draft. Dynamic args require input/live-path bindings. |
| `decompile_apk` | ✓ | ✓ | 用 jadx 反编译 apk 到 Java 源码目录，返回反编译输出目录。 |
| `device_status` | ✓ | ✓ | 探测手机守护进程状态与连接方式，返回 /health 及当前传输配置。用于排查连不上的问题。 |
| `dexkit_search` | ✓ | ✓ | 用 DexKit 在 apk 的 dex 里做链式查询（定位类/方法/字段）。 |
| `diagnose_target` | ✓ | — | Diagnose connectivity, installed versions, desired/actual Java hooks and native observer. |
| `diff_call_graph_scenarios` | ✓ | — | 比较两个调用图场景，直接找共同链路、仅 A/仅 B、首次分叉和共享边耗时差。 |
| `diff_scenarios` | ✓ | ✓ | 比对两个已捕获场景，给出**方法级差异**（P2）——直接回答"A 与 B 行为为何不同"。 |
| `dump_dex` | ✓ | ✓ | 通用内存 dex dump（M4）：hook dex 加载入口，把内存中已解密的 dex 回传落盘。 |
| `event_stream_status` | ✓ | ✓ | Check daemon buffer loss/restart and subscriber drops; upstream loss remains unknown. |
| `evidence_graph` | ✓ | — | 查看分析会话证据图。 |
| `execute_action_plan` | ✓ | — | Preview or attempt once; verify independent outcomes; halt on ambiguity/failure. |
| `explain_evidence` | ✓ | — | 解释某个关键词/类/方法/字段当前已有的证据链。 |
| `export_action_plan` | ✓ | — | Export a reviewable plan + executable Runtime Program manifest (not a signed bundle). |
| `finish_action_capture` | ✓ | — | Finish a demonstration, associate clicks with methods and clean only its hooks. |
| `ghidra_analyze` | ✓ | ✓ | 用 Ghidra headless 分析 .so，返回导出表 / 导入表 / 字符串 / 函数列表 / 可疑函数。 |
| `hermes_decompile` | ✓ | ✓ | 反编译 React Native Hermes 字节码 .hbc（通常在 apk 的 assets/index.android.bundle）。 |
| `inspect_action_plan` | ✓ | — | Read the reviewable plan and durable attempt history. |
| `inspect_call_graph` | ✓ | — | 递归展开一个 Java 方法的静态调用图，并叠加会话里已有的 runtime 命中证据。 |
| `inspect_condition_origin` | ✓ | — | 从已确认的 A/B 分叉条件继续追踪字段 writer/readers 或条件方法返回值来源。 |
| `inspect_jni_bindings` | ✓ | ✓ | Read observed class/method/signature -> native address/module/offset mappings. |
| `inspect_method` | ✓ | — | 展开一个已知 Java 方法：调用者、被调用方法、关联字符串、同类字段和 JADX 源码上下文。 |
| `inspect_value_lineage` | ✓ | — | 跨方法递归追踪已确认 A/B 分叉条件的值来源。 |
| `install_action_plan` | ✓ | — | Install a successfully verified plan, retaining existing Runtime Program permission policy. |
| `investigate` | ✓ | — | 执行一轮自动调查：目标解析 → DEX 索引 → 多词候选排序 → 可选运行时验证 → 方法上下文 → 证据汇总。 |
| `investigation_status` | ✓ | — | 查看分析会话当前绑定的 APK、JADX 目录、发现记录和运行时游标。 |
| `list_action_captures` | ✓ | — | List demonstrations without returning raw argument values. |
| `list_artifacts` | ✓ | ✓ | 列出 PC 工作目录里某包（或全部包）已产出的物件：已拉的 apk、已拉的 native so、 |
| `list_call_graph_scenarios` | ✓ | — | 列出当前 Investigation 会话保存的调用图动态场景。 |
| `list_dumps` | ✓ | ✓ | 列出已落盘的内存 dump（用 read_remote_file 或 pull 取回）。 |
| `list_hooks` | ✓ | ✓ | 列出当前磁盘上的期望 hook 配置。 |
| `list_packages` | ✓ | ✓ | 列出设备上已安装应用（包名 / versionCode / 安装路径 / 是否系统应用）。 |
| `list_scenarios` | ✓ | ✓ | 列出已捕获的场景（work/scenarios/ 下）及各自命中数。 |
| `open_target` | ✓ | — | 开启一个持久化分析会话，并自动绑定该包现有 APK/JADX/so 产物。 |
| `patch_java` | ✓ | ✓ | 实时篡改与高级动作流水线（M5 v2）：改参数 / 改返回值 / 字段深层路径篡改 / 条件执行 / 副作用动作。 |
| `post_hook` | ✓ | ✓ | 下发原始 hook 配置（M3 native / M5 Java）。 |
| `prepare_index` | ✓ | — | 预热当前目标的 DEX SQLite 索引；首次解析 APK，之后所有新查询直接查数据库。 |
| `prepare_target` | ✓ | — | 为会话准备 JADX 源码。已有反编译产物时直接复用，否则只反编译当前主 APK。 |
| `proc_info` | ✓ | ✓ | 读取 /proc/<pid>/<what>，what ∈ maps\|status\|cmdline。 |
| `pull_apk` | ✓ | ✓ | 拉取某应用的**全部** apk（base.apk + 所有 split_config.*.apk）到 PC 工作目录。 |
| `pull_libs` | ✓ | ✓ | 拉取某应用 lib 目录下已落地的 native .so 到 PC 工作目录。 |
| `rank_candidates` | ✓ | — | 从字符串 xref、方法名、类名与 Evidence Graph 中生成可解释的候选方法排序。 |
| `rank_root_causes` | ✓ | — | 综合静态来源、Runtime Lineage 与 writer 变化，对根因节点做可解释排序。 |
| `read_remote_file` | ✓ | ✓ | root 读取设备上任意文件（流式）。 |
| `recent_events` | ✓ | ✓ | 取守护进程环形缓冲里**最近的命中事件**（事后采集，P0-1）——无需正连着 SSE。 |
| `remote_shell` | ✓ | ✓ | 在设备上以 root 执行**白名单内**命令。优先用 argv 数组（安全，无需引号）。 |
| `runtime_activity_action` | ✓ | ✓ | 在当前 Activity 上直接执行现有 Action Pipeline，不创建 Java Hook。 |
| `runtime_context_status` | ✓ | ✓ | 实时读取目标进程当前 Application/Context/Activity/Lifecycle 状态。 |
| `runtime_event_emit` | ✓ | ✓ | 从 PC 直接向在线 M5 Runtime EventBus 发事件。 |
| `runtime_hook_status` | ✓ | ✓ | 查看运行中 M5 Runtime 的真实状态。 |
| `runtime_program_approve` | ✓ | ✓ | 持久批准一个 Program 的 ask 权限；跨 revision 有效，deny 仍不可覆盖。 |
| `runtime_program_disable` | ✓ | ✓ | 禁用 Runtime Program；只移除该 Program 的 targets，并执行 state_cleanup。 |
| `runtime_program_enable` | ✓ | ✓ | 启用已安装 Runtime Program，并 live reconcile + 应用 state_init。 |
| `runtime_program_export` | ✓ | — | 把设备上的 Runtime Program 导出为 Ed25519 签名 .rbprog.json 包。 |
| `runtime_program_import` | ✓ | — | 验签后把 .rbprog.json 安装/替换到目标包。 |
| `runtime_program_install` | ✓ | ✓ | 安装一个命名 Runtime Program。 |
| `runtime_program_policy_set` | ✓ | ✓ | 设置设备端 Program 权限策略；策略收紧会立即禁用不再允许的在线 Program。 |
| `runtime_program_policy_status` | ✓ | ✓ | 查看设备端 Runtime Program 权限策略、批准和每个 Program 的有效状态。 |
| `runtime_program_replace` | ✓ | ✓ | 替换已安装 Runtime Program，并把旧版本压入最多 5 层 rollback 历史。 |
| `runtime_program_revoke_approval` | ✓ | ✓ | 撤销 Program 的持久权限批准；若当前运行依赖该批准，会立即 live disable/cleanup。 |
| `runtime_program_rollback` | ✓ | ✓ | 回滚 Runtime Program 到上一份 manifest；revision 继续单调递增。 |
| `runtime_program_signer_status` | ✓ | — | 查看 PC 本地 Runtime Program signer 与已信任公钥；绝不返回私钥。 |
| `runtime_program_status` | ✓ | ✓ | 查看一个包已持久化的 Runtime Program、版本、启用状态和 rollback 深度。 |
| `runtime_program_trust_signer` | ✓ | — | 把一个 Ed25519 Runtime Program signer 公钥加入本机信任列表。 |
| `runtime_program_verify_package` | ✓ | — | 离线校验 Runtime Program Package 的 SHA-256、Ed25519 签名、权限与包作用域。 |
| `runtime_state_append` | ✓ | ✓ | 向在线 Runtime State 列表追加一个 JSON 值。 |
| `runtime_state_clear` | ✓ | ✓ | 清空在线 Runtime 的一个 State scope；hook scope 需指定 hook_id。 |
| `runtime_state_get` | ✓ | ✓ | 直接读取在线 M5 Runtime State，不创建临时 Hook。 |
| `runtime_state_increment` | ✓ | ✓ | 原子增加在线 Runtime State 数值；不存在时从 0 开始。 |
| `runtime_state_remove` | ✓ | ✓ | 删除在线 M5 Runtime State 的一个 key，并返回旧值。 |
| `runtime_state_set` | ✓ | ✓ | 直接写入在线 M5 Runtime State；支持 JSON 标量、对象和数组。 |
| `search_target` | ✓ | — | 在当前分析目标中统一搜索源码 / 字符串 / 类 / 方法 / 字段。 |
| `toolchain_status` | ✓ | ✓ | 检查 PC 本地反编译工具链（jadx / DexKit / Ghidra / Hermes）是否就绪及其路径。 |
| `trace_java` | ✓ | ✓ | 一步下发一个 Java 方法 trace 并采集命中（M5）。 |
| `trace_target` | ✓ | — | 在当前会话目标上临时 trace 一个 Java 方法，命中即返回，并默认自动卸载 Hook。 |
| `unhook` | ✓ | ✓ | 移除某包 hook；运行中的 M5 Tracer 会立即 live unhook。 |
| `verify_call_path` | ✓ | — | 一次性动态验证一条代表业务路径，并按方法入口时间还原真实执行顺序。 |
| `verify_candidates` | ✓ | — | 把排名靠前的多个 Java 候选一次性装 Hook，并在一个共享窗口里验证谁真实命中。 |
| `verify_condition_writer` | ✓ | — | 动态验证字段 writer 是否真的在一次行为中改变已确认的分叉条件字段。 |
| `verify_root_cause_hypothesis` | ✓ | — | 对一个方法根因候选执行最小 A/B 输入输出实验。 |
| `verify_value_lineage` | ✓ | — | 一次性动态验证一条 Value Lineage 的方法返回顺序与最终字段变化。 |
