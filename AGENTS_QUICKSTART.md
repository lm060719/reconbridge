# ReconBridge —— Agent 快速上手（一页纸）

> 给**新会话的 AI agent** 看的：读完这一篇就能驱动整套 ReconBridge。
> 面向 LSPosed / native 逆向与模块开发的**侦察 + 篡改**工具链。
> ⚠️ 仅限**已获授权**的安全研究 / CTF / 逆向学习 / 防御性研究；分析对象须为你自有或明确授权的设备与应用。

---

## 0. 一句话架构

**手机侧只做原子能力（拉包 / 读文件 / native hook / Java hook），所有智能在 PC 侧（你 + MCP 工具）。**
手机上跑两样东西：① KernelSU 模块里的 **C++ 守护进程**（HTTP 静态接口 + 动态 hook 分发 + 事件推流）；② 一个**通用 LSPosed 模块 ReconBridge Tracer**（数据驱动的 Java trace/篡改执行器）。你在 PC 用 MCP 工具下发指令、收结果。

```
你(Agent) ──MCP工具──> reconbridge MCP(python) ──adb/HTTP──> 手机守护进程(root)
                                                          ├─ 静态接口(拉包/读文件/shell)
                                                          ├─ /hook 配置分发 ──@reconbridge_inject socket──┐
                                                          └─ SSE/WS 事件回传 <───────────────────────────┤
                                          Zygisk native 执行器(M3/M4) ──┤ (ShadowHook, .so 符号)
                                          LSPosed Tracer 模块(M5) ──────┘ (XposedBridge, Java 方法)
```

---

## 1. 设备要求（与你的具体机型无关）

- Android **arm64-v8a**，已 root：**KernelSU**（其它 root 方案未测试）。
- **ZygiskNext**（M3/M4 native 动态 hook 需要）。
- **LSPosed**（M5 Java trace/篡改需要）。
- 已刷本仓库的 KernelSU 模块（守护进程 + sepolicy），装了 M5 的话另需安装 `m5/ReconBridge-Tracer.apk`。

> 已验证环境（仅供参考，不是硬性要求）：Xiaomi SM8750 / Android 16 / HyperOS / KernelSU + ZygiskNext + LSPosed。

**连接**：默认走 **adb**（`RECONBRIDGE_TRANSPORT=adb`），MCP 自动 `adb forward` 到本地端口并自动从设备读 token（真实 base_url 见 `device_status`）。守护进程设备端口默认 **8787** 且**默认关闭**，需在 KernelSU WebUI 开关或 `rbctl enable` 打开。也支持 `wifi` 模式（局域网直连，需 `RECONBRIDGE_URL` + `RECONBRIDGE_TOKEN`）。
**多设备**：MCP 会**自动挑唯一在线设备**并忽略 `offline`/`unauthorized` 残留链路（如残留的 tls-connect 链路），无需手动 `adb disconnect`。仅当**多台都在线**时才会报清单让你设 `RECONBRIDGE_SERIAL=<序列号>` 指定其一。

**手机 AI 本地直连**：在 AI 软件中添加 MCP 配置时选择 `Streamable HTTP`，URL 填 `http://127.0.0.1:8790/mcp`。必须在「自定义请求头 / Custom Headers」中新增请求头：名称填 `X-Token`，值填 KernelSU WebUI 中显示的完整 token；不要把 token 填进 URL、MCP 名称或请求体。手机本地 MCP 需先在 WebUI 开启，且客户端须允许明文 localhost HTTP 和访问 `127.0.0.1`。

---

## 2. 新会话怎么让工具可用

- `install.ps1` / `install.sh` 会把 reconbridge **注册到用户级**（`~/.claude.json` 的 `/mcpServers`，绝对路径指向你克隆仓库里的 venv 与 `pc/`），**任意文件夹的新会话都会自动加载**。新会话 = 重启 MCP server = 自动加载最新 `pc/reconbridge_mcp` 代码（含最新工具/修复）。
- **前提**：① 别移动/删除仓库目录（用户级配置写死了它的 venv + `pc/` 绝对路径；仓库挪了就改 `~/.claude.json` 里对应两处路径）；② 手机已刷模块、端口已开、adb 连得上。
- **第一步永远先** `device_status` 确认连得上（返回 `/health` 即 OK）。
- 已知目标包名后，**默认第二步是 `open_target(package_name)`**，第三步优先直接 `investigate(session_id, goal=...)`。只有需要手工控制调查阶段时再拆成 `search_target / rank_candidates / verify_candidates / explain_evidence`。
- 这些 MCP 工具在会话里可能是**延迟加载**的：优先加载 `device_status,open_target,investigate,trace_target,investigation_status,close_investigation`，特殊需求再拿原子工具 schema。

---

## 3. MCP 工具：默认高层入口 + 原子能力

### 3.0 默认高层任务模式（优先）
| 工具 | 用途 |
|---|---|
| `open_target(package_name, auto_pull=True, note="")` | 创建持久化分析会话；自动绑定本地 APK/JADX/so，本地没 APK 时默认尝试从设备拉取 |
| `investigate(session_id, goal, verify_runtime=True, top_n=5, seconds=15, ...)` | **默认首选**：自然语言目标自动执行关键词规划、索引、多词候选排序、批量运行时验证，并自动展开主候选 callers/callees + JADX 源码上下文；运行时失败仍保留静态与源码结果 |
| `inspect_method(session_id, class_name, method, descriptor="", ...)` | 已知具体方法时查看一层 callers/callees、关联字符串、同类字段和 JADX 方法体；可自动准备源码 |
| `inspect_call_graph(session_id, class_name, method, upstream_depth=2, downstream_depth=2, ...)` | 递归展开调用图；默认标准库/Android/Kotlin 节点只显示不继续扩，返回代表业务路径并标记 runtime 覆盖 |
| `verify_call_path(session_id, class_name, method, path_index=0, seconds=15, ...)` | 对代表路径统一挂 before Hook；一次行为触发后返回真实时间线、节点/边覆盖率、同线程完整路径和相邻入口 delta_ms |
| `capture_call_graph_scenario(session_id, name, class_name, method, ...)` | 围绕目标方法对整张局部调用图挂同一组 before Hook，采集一个可做 A/B 比较的命名场景 |
| `list_call_graph_scenarios(session_id)` | 列出当前 Investigation 会话保存的调用图场景 |
| `diff_call_graph_scenarios(session_id, a, b)` | 校验两次采集使用相同静态图+Hook 集合后，输出公共前缀、首次分叉、仅 A/仅 B 方法/边和共享边耗时差 |
| `analyze_scenario_divergence(session_id, a, b, ...)` | 自动取公共前缀最后一个方法，回到 JADX 源码定位 if/else、switch、when、三元条件，关联类字段/条件方法并生成 trace 探针计划 |
| `capture_divergence_probe(session_id, a, b, capture_for, ...)` | 自动执行一个安全条件探针；字段在分支点 before 读取，条件方法在 after 抓返回值，压缩保存到对应 A/B 场景 |
| `compare_divergence_probes(session_id, a, b, ...)` | 比较 A/B 同一条件探针的稳定值，并检查布尔值是否与源码 true/false 分支方向一致 |
| `search_target(session_id, query, kind="auto", limit=20)` | 手工模式：统一搜源码/字符串/类/方法/字段；优先复用 JADX，否则直接查 DEX SQLite 持久索引；首次索引自动构建 |
| `prepare_index(session_id, force=False)` | 主动预热/重建 DEX SQLite 索引；连续大量搜索前可先做一次 |
| `prepare_target(session_id, force=False)` | 仅在需要完整源码时运行 JADX；已有产物直接复用 |
| `rank_candidates(session_id, query, limit=10, pool_limit=80)` | 综合字符串 xref、方法名/类名、历史 Evidence Graph 生成带 score/reasons 的候选排序 |
| `verify_candidates(session_id, query, top_n=5, seconds=15, ...)` | 一次性给前 N 个候选装观测 Hook，共享采集窗口；一次目标行为即可验证真实命中 |
| `trace_target(session_id, class_name, method, ...)` | 已知具体方法后的精细 Java trace；自动包名/游标/唯一 Hook，默认命中即返回并清理临时 Hook；结果自动写证据图 |
| `evidence_graph(session_id, focus="", depth=2, limit=100)` | 查看证据关系图；可围绕关键词/类/方法/字段展开附近节点 |
| `explain_evidence(session_id, focus, depth=3, limit=80)` | 汇总关联字符串、方法、字段和运行时确认情况，解释当前证据链 |
| `investigation_status(session_id)` | 查看当前会话资产、发现记录、索引状态、证据图规模、游标与临时 Hook |
| `close_investigation(session_id, cleanup_hooks=True)` | 结束会话并默认清理目标 Hook |

> **Agent 决策规则**：能用高层工具完成，就不要拆成多个原子调用。原子工具用于 native、高级 patch、协议调试和高层入口尚未覆盖的特殊场景。

### 3.1 设备原子能力（M1，7 个）
| 工具 | 签名 | 用途 |
|---|---|---|
| `device_status` | `()` | 探活 + 看传输/base_url；排查连不上 |
| `list_packages` | `(name_filter="", only_third_party=False)` | 列已装应用（包名/versionCode/路径/是否系统） |
| `pull_apk` | `(package_name)` | 拉**全部** apk（base + 所有 split）到 PC，字节等价 adb pull |
| `pull_libs` | `(package_name)` | 拉落地的 native `.so`（`extractNativeLibs=false` 时改用 pull_apk 解包 `lib/arm64-v8a/`） |
| `read_remote_file` | `(path, save_as="", max_inline_kb=64)` | root 流式读任意文件，小文本内联预览 |
| `proc_info` | `(pid, what="status")` | 读 `/proc/<pid>/<status\|maps\|cmdline>` |
| `remote_shell` | `(argv=[...], cmd="")` | root 执行**白名单**命令（见下），优先 `argv` |

`remote_shell` 白名单：`id whoami getprop uname ls cat stat du df md5sum sha1sum sha256sum pm cmd dumpsys ps getenforce settings wc head tail ip netstat pgrep mount readlink basename dirname find date`。白名单外 403；**没有 `am`/`logcat`/`grep`**（要 logcat/force-stop 用外部 `adb`）。

### 3.2 PC 反编译工具链（M2，5 个）
| 工具 | 签名 | 用途 |
|---|---|---|
| `decompile_apk` | `(apk_path, output_dir="")` | jadx 反编译到 Java 源码目录 |
| `dexkit_search` | `(apk_path, query)` | 在 dex 里链式查类/方法/字段。**后端是 androguard**（DexKit 无 Win/py 包）。query 例：`{"find":"method","using_strings":["sign","md5"]}` |
| `ghidra_analyze` | `(so_path, options={})` | Ghidra headless 分析 `.so`：导出/导入/字符串/函数/可疑函数；`options={"decompile":["sym",0x1234]}` 给伪代码 |
| `hermes_decompile` | `(bundle_path, output_dir="")` | 反编译 RN Hermes 字节码（`assets/index.android.bundle`） |
| `toolchain_status` | `()` | 自检 jadx/DexKit/Ghidra/Hermes 是否就绪及路径 |

> **重型工具路径坑**：Ghidra 需 JDK21 且**必须装在 ASCII 路径**（安装路径含非 ASCII 字符会让 Ghidra 的 log4j 初始化崩溃）。若仓库本身在非 ASCII 路径下，把 Ghidra/JDK 放到 ASCII 目录并用 `RECONBRIDGE_NATIVE_TOOLS` 指定（Windows 默认回退到 `<盘符>:/ReconBridgeTools`）。

### 3.3 动态 hook / 内存 dump / 产出物（M3 native + M4，8 个）
| 工具 | 签名 | 用途 |
|---|---|---|
| `post_hook` | `(config)` | 下发原始 hook 配置（native 或 java，见协议）。**通用入口** |
| `list_hooks` | `()` | 列当前已下发配置 |
| `unhook` | `(package, hook_id="")` | 删该包全部 / 某个 hook 配置 |
| `collect_events` | `(seconds=10, max_events=200, until_first_hit=False, until_n_events=0, fold_stack=True, include_recent=False, since_seq=0)` | 连 SSE 收命中事件。**`until_first_hit=True` 命中即返回**；**`include_recent=True` 事后补捞**环形缓冲历史命中（命中发生在采集开始前也能拿到）；`fold_stack` 折叠栈顶 hook 框架帧 |
| `recent_events` | `(limit=50, since_seq=0)` | **事后采集**：直接取守护进程环形缓冲里最近的命中，无需正连着 SSE。返回 `latest_seq` 可作游标只取增量 |
| `dump_dex` | `(package, symbol="", offset="", base_arg=0, size_arg=1, lib="libart.so", restart=True)` | hook dex 加载入口，把内存中已解密 dex 回传落盘（脱壳） |
| `list_dumps` | `()` | 列已落盘 dump（用 `read_remote_file` 取回） |
| `list_artifacts` | `(package_name="")` | 列 PC 已产出物：已拉 apk / native so / jadx 目录 / Hermes 目录，免翻找是否拉过/反编译过 |

### 3.4 Java trace / 实时篡改（M5，2 个）★ 面向 LSPosed 开发
| 工具 | 签名 | 用途 |
|---|---|---|
| `trace_java` | `(package, class_name, method, params=None, args_render="tostring", capture_args=None, fields=None, paths=None, this="class", ret=True, when="after", stack=False, hook_id="", debug=False, restart=True, seconds=12, max_events=200, until_first_hit=False, until_n_events=0, fold_stack=True, include_recent=False, since_seq=0, hot=False)` | **一步 hook 一个 Java 方法并采集**：看 this/参数/返回值/私有字段/调用顺序。`paths` 取嵌套值、`render:"deep"` 深序列化、`until_first_hit=True` 命中即返回、**`hot=True` 免重启热加**（往运行中进程增量追加，不 force-stop） |
| `patch_java` | `(package, class_name, method, params=None, replace_args=None, replace_return=None, skip_original=False, trace=True, capture_args=None, this="class", when="after", hook_id="", debug=False, restart=True, seconds=0, max_events=100)` | **实时篡改**：改参数 / 改返回值 / 跳过原方法。篡改持久生效直到 `unhook` |

### 3.5 场景捕获 + 差分（P2，3 个）★ 回答"A 与 B 行为为何不同"
| 工具 | 签名 | 用途 |
|---|---|---|
| `capture_scenario` | `(name, seconds=20, quiet_ms=1500, max_events=500, fold_stack=True)` | 先 arm 一组宽 hook，调用后**在窗口内做一次操作**，抓完这一波（静默 quiet_ms 即停）存盘为命名场景 |
| `diff_scenarios` | `(a, b)` | 比对两场景：**只在A/只在B命中的方法**、两者都命中但**参数值不同**的方法 |
| `list_scenarios` | `()` | 列已捕获场景 |

---

## 4. M5 Tracer（LSPosed）—— 用前必读

**是什么**：一个通用的、由 PC 数据驱动的 LSPosed 模块（`m5/tracer/`，包名 `com.reconbridge.tracer`，预编译 `m5/ReconBridge-Tracer.apk`）。它跑在目标 App 进程里，读守护进程下发的 `kind:"java"` 目标，用 `XposedBridge` 装 trace/篡改回调，走**和 M3 相同**的 socket→SSE→`collect_events` 链路。**daemon 不用改。**

**启用步骤（一次性，人工）**：
1. `adb install -r m5/ReconBridge-Tracer.apk`
2. **LSPosed 管理器 → 启用「ReconBridge Tracer」→ 把目标 App 勾进作用域**（这步只能人工点）。
3. 之后 PC 用 `trace_java` / `patch_java` 下发即可。

**协议要点**（全文 `m5/JAVA_HOOK_PROTOCOL.md`）：
- 配置 = `{package, restart, debug?, targets:[{kind:"java", class, method, params?, capture{...}, action?}]}`。
- `params` 省略 = hook 所有同名重载；`method:"<init>"` = 构造函数。
- `capture`：`this`(class/tostring/none)、`when`(before/after/both/**none**=只篡改不出事件)、`args`/`all_args`、`ret`、`fields`(反射读私有字段)、`stack`。
- `render`：`tostring`(数值/布尔原样，其余 toString 截断) / `class`(类名) / `json`(原样字符串交 PC 解析，适合参数本身是 JSON) / `deep`(反射深度序列化对象图，带深度/环/节点预算防爆)。
- `paths`(嵌套字段路径捕获)：`[{"path":"args[1].payload.load_url","render":"tostring"}]`——直接拿深埋在 payload 对象里的值，不靠整对象 toString 撞运气。路径 `args[N]`/`this`/`ret` 起头，`.name` 逐层(反射字段→getter→Map key)，`[n]` 索引数组/List；裸字段名=`this.<name>`；解析不到标 `unresolved:true`。
- `action`(篡改与 Action 流水线)：支持快捷覆盖入参 `replace_args:[{index,value,type}]`、覆盖返回值 `replace_return:{value,type}`、`skip_original`；同时支持高级动作链 `before_actions` / `after_actions`，包含 `call_method`(调用Java方法)、`set_field`(读写字段)、`construct`(构造对象)、`eval_js`(Rhino JS片段执行)、`eval_dex`(DEX动态执行)、`exec_shell`(执行Shell命令)。命中事件带 `tampered:true`。
- `debug:true` 才逐命中打 logcat（默认安静）。

---

## 5. 典型工作流（示例包名/类名请替换成你的目标）

**A. 摸清一个 App 的结构（推荐）**
```
device_status
→ open_target("com.target.app")                 # 返回 session_id
→ investigate(session_id, goal="找到会员状态判断方法", top_n=5)
# ↑ 自动：关键词规划 → SQLite v2 索引 → 多词候选合并 → 批量 Hook → callers/callees → JADX 方法体
#    → 上下游递归调用图 → 入口/目标/下游代表路径 → runtime 覆盖 → 证据汇总
→ verify_call_path(session_id, "com.target.PayManager", "checkVip", path_index=0)
# ↑ 在采集窗口里触发一次目标行为；结果按 before 入口时间还原真实 A→B→C→D 和每段 delta_ms
# 如果此轮需要 runtime 验证，在采集窗口里触发一次目标行为即可
→ prepare_target(session_id)                    # 只有需要完整源码上下文时再做
→ trace_target(session_id, "com.target.PayManager", "checkVip")  # 已明确方法后精细抓参数/字段
```
同一个 APK 的索引只需构建一次；DEX 索引 v2 持久化方法调用边，所以多层调用图也只查 SQLite。investigate 只回传少量代表路径；需要完整 nodes/edges 再调用 inspect_call_graph。verify_call_path 使用 before 事件而非 after，避免嵌套调用逆序；相邻静态边要求同一 tid 按序出现，减少多线程误判。返回 node_coverage、edge_coverage、full_path_observed、primary_tid、timeline 和每条相邻边的 delta_ms，结果会写回 Evidence Graph 的 runtime_sequence 关系。

**B. 定位并观测一个 Java 方法（推荐）**
```
# 先确保 Tracer 模块已启用且目标 App 在 LSPosed 作用域内
trace_target(session_id,
             class_name="com.target.Foo", method="doWork",
             paths=[{"path":"args[1].payload","render":"deep"}],
             seconds=30)
# 默认命中即返回，并自动卸载这次临时 Hook
```
复杂持续 Hook、篡改或原始协议调试再使用 `trace_java` / `patch_java` / `post_hook`。

**C. 实时篡改验证（不写模块就试想法）**
```
# 替换某方法的参数：
patch_java("com.target.app", "com.target.Foo", "doWork",
           replace_args=[{"index":1,"value":"...","type":"string"}], when="both", seconds=30)
# 让某校验方法恒返回 true、且不执行原方法：
patch_java("com.target.app", "com.target.Security", "verify",
           replace_return={"value":true,"type":"boolean"}, skip_original=True)
# 用完恢复：
unhook(package="com.target.app")   # + 用外部 adb: adb shell am force-stop <pkg> 清掉运行进程里的活 hook
```

> **推荐套路：先验证，再固化。** 定位到候选方法后，别急着写模块 + 编译 + 安装 + 测试整轮。
> 先用 `patch_java` **现场验证想法**——"skip 掉这个方法真能拦住跳转吗？""把返回值改成 true 有效吗？"
> ——`skip_original` / `replace_return` / `replace_args` 秒级见效。验证通过后再把逻辑固化进 APK 模块，
> 能省掉早期若干轮"改代码→编译→装→测"。

**D. native 层 hook（M3，非 Java）** —— 见 `m3/HOOK_PROTOCOL.md`，用 `post_hook` 下发 `lib+symbol`/`offset` 目标，`collect_events` 收命中。

**E. "A 与 B 行为为何不同"（调用图场景差分，推荐）** —— 例如会员/非会员、打开/查看、成功/失败两个行为为什么走不同分支。
```
# 先用 investigate 找到共同的关键目标方法，例如 PayManager.checkVip
capture_call_graph_scenario(
    session_id, "非会员",
    class_name="com.target.PayManager", method="checkVip"
)
# ↑ 在采集窗口里执行一次“非会员”操作

capture_call_graph_scenario(
    session_id, "会员",
    class_name="com.target.PayManager", method="checkVip"
)
# ↑ 用完全相同的静态调用图和 Hook 范围执行一次“会员”操作

diff_call_graph_scenarios(session_id, "非会员", "会员")
# → common_prefix: Entry.onClick → PayManager.checkVip
# → a_next: Paywall.showPaywall
# → b_next: Feature.enterFeature
# → only_in_a / only_in_b / only_edges_a / only_edges_b
# → shared_edge_timing: 两边共同边的入口耗时差

analyze_scenario_divergence(session_id, "非会员", "会员")
# → branch_point: PayManager.checkVip
# → top_condition: premiumStatus
# → branch_orientation: a_false_b_true
# → probe_plan: 观测 premiumStatus 字段或 isPremiumUser() 条件方法

capture_divergence_probe(
    session_id, "非会员", "会员",
    capture_for="非会员"
)
# ↑ 触发一次非会员行为；例如捕获 premiumStatus=false

capture_divergence_probe(
    session_id, "非会员", "会员",
    capture_for="会员"
)
# ↑ 触发一次会员行为；第二侧完成后会自动附带 comparison

compare_divergence_probes(session_id, "非会员", "会员")
# → status: branch_orientation_confirmed
# → 非会员: false
# → 会员: true
# → 动态观测与 a_false_b_true 源码方向一致
```
两次采集会同时保存 `graph_fingerprint` 与 `hook_fingerprint`；任一不一致就拒绝给出“业务分叉”结论，避免第二次 Hook 少挂了方法导致假差异。场景事件经过压缩后独立保存在当前 Investigation 会话目录，不会持续膨胀主 session JSON。

原来的 `capture_scenario / diff_scenarios` 仍保留，适合已经手工 arm 好一批任意 Hook、需要比较参数值差异的低层场景；新流程优先用于 Java 业务调用链分叉。

---

## 6. 高频坑（务必记住）

1. **adb + Git Bash（Windows）**：所有 adb 命令前 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`，否则 `/data/...` 被改写成 Windows 路径。
2. **首个 hook 要 `restart:true`，之后可 `hot`**：模块/native 层在**进程启动时**读一次配置。第一个 hook 需 `restart`（`am force-stop` 触发重注入）让目标带配置起来；此后目标进程活着时，**Java trace 可用 `trace_java(hot=True)` 免重启热加**（`restart:false`+`mode:append`，往运行中进程增量追加，daemon 下发 reload 帧）——迭代加 hook 不再反复强退/重唤醒。`hot_injected` 为 0 说明目标没在跑（或非 tracer 作用域/旧版 APK/native 目标），退回 `restart`。native 目标目前仍需 `restart`。
3. **稀疏事件的采集时序**：**优先 `until_first_hit=True`**（命中即返回，不必和窗口掐点）。守护进程带**最近 ~400 条环形缓冲**，故命中即便发生在采集开始前也能捞回——用 `collect_events(include_recent=True)` 或直接 `recent_events()`（推荐流程：post_hook 后 `recent_events(limit=0)` 记游标 → 触发 → 事后 `recent_events(since_seq=游标)` 补捞）。`seconds` 只当兜底。
4. **控制台中文可能显示成乱码**：多为终端编码问题（如 Windows Git Bash），数据本身是 UTF-8。验证时写 UTF-8 文件再用 Read 看，或设 `PYTHONUTF8=1 PYTHONIOENCODING=utf-8`。
5. **改了 `pc/reconbridge_mcp/*.py` 要重启 MCP server** 才生效（新会话天然是新 server，不受影响）。
6. **LSPosed 模块必须人工启用 + 勾作用域**；悬浮窗/自绘/Compose 类 UI 不一定走 `Activity.onResume`，验证挑必然会走的业务方法。
7. **多设备/多链路** → MCP 自动挑唯一在线设备、忽略离线残链；仅**多台都在线**时才需设 `RECONBRIDGE_SERIAL`。
8. **篡改用完要恢复**：`unhook` + `adb shell am force-stop <pkg>`，否则活 hook 留在运行进程里。
9. **模块日志**：`XposedBridge.log` 不一定进 logcat；模块另有 `android.util.Log`（tag `ReconTracer`），`adb logcat -s ReconTracer` 可看装 hook/错误（逐命中日志需配置 `debug:true`）。

---

## 7. 里程碑与目录

| 里程碑 | 内容 | 关键文件 / 文档 |
|---|---|---|
| **M1** | 静态传输层：KernelSU 模块 + C++ 守护进程 + WebUI + 静态接口 | `src/daemon.cpp`、`module/`、`README.md` |
| **M2** | PC MCP Server + 反编译链（jadx/androguard/Ghidra/Hermes） | `pc/reconbridge_mcp/`、`pc/README.md` |
| **M3** | 通用 native 动态 hook 执行器：Zygisk+ShadowHook + SSE/WS | `src/dynamic.cpp`、`m3/zygisk/module.cpp`、`m3/HOOK_PROTOCOL.md` |
| **M4** | 加固/反调试增强：内存 dex dump + 反检测模板 | `m4/README.md`、`m4/templates/` |
| **M5** | 通用 Java trace + 实时篡改（LSPosed 模块） | `m5/tracer/`、`m5/README.md`、`m5/JAVA_HOOK_PROTOCOL.md`、`m5/ReconBridge-Tracer.apk` |

**构建**：`./build.ps1`（NDK clang++ 编守护进程 + zygisk，无需 cmake）→ `./pack.ps1`（打 `dist/ReconBridge-*.zip`）。
M5 模块单独编：`cd m5/tracer && ./gradlew.bat :app:assembleDebug`（若仓库在非 ASCII 路径，`gradle.properties` 已加 `android.overridePathCheck=true`）。

**运行时文件（设备）**：`/data/adb/reconbridge/`：`config.conf`(enabled/port/bind/token)、`daemon.log`、`hooks/<pkg>.json`(下发的配置)、`dumps/`(dump 落盘)、`agent/`。模块根 `/data/adb/modules/reconbridge/`（`rbctl`、`bin/reconbridge_daemon`、`sepolicy.rule`）。

**配置环境变量**（在 `~/.claude.json` 的 mcp `env` 或 shell 里设）：`RECONBRIDGE_TRANSPORT`(adb/wifi)、`RECONBRIDGE_SERIAL`、`RECONBRIDGE_PORT`(默认 8787)、`RECONBRIDGE_URL`/`RECONBRIDGE_TOKEN`(wifi 模式)、`RECONBRIDGE_WORKDIR`、`RECONBRIDGE_NATIVE_TOOLS`(Ghidra/JDK 的 ASCII 路径)、`RECONBRIDGE_ADB`(adb 可执行文件路径)。

---

## 8. 起手式（新会话照抄）

1. `device_status` → 确认 `/health` ok（否则：查 `adb devices`、端口是否开、多设备）。
2. 明确目标 App 包名（必要时 `list_packages`），然后立即 `open_target(package)`。
3. 默认直接 `investigate(session_id, goal=...)`；先读 `call_graph.representative_paths`，再用 `verify_call_path` 确认真实链路。若比较两个行为，走 `capture_call_graph_scenario A/B → diff_call_graph_scenarios → analyze_scenario_divergence → capture_divergence_probe A/B → compare_divergence_probes`，从方法分叉一路验证到具体运行时条件值。要完整静态图用 `inspect_call_graph`；确认条件后再 `trace_target` 追状态来源。
4. 只有需要人工控制候选排序/验证，或 native、复杂 patch、高层入口覆盖不了时，才退回拆分工具/原子工具。
5. 结束时 `close_investigation`，默认清理目标 Hook。
