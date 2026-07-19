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

---

## 2. 新会话怎么让工具可用

- `install.ps1` / `install.sh` 会把 reconbridge **注册到用户级**（`~/.claude.json` 的 `/mcpServers`，绝对路径指向你克隆仓库里的 venv 与 `pc/`），**任意文件夹的新会话都会自动加载**。新会话 = 重启 MCP server = 自动加载最新 `pc/reconbridge_mcp` 代码（含最新工具/修复）。
- **前提**：① 别移动/删除仓库目录（用户级配置写死了它的 venv + `pc/` 绝对路径；仓库挪了就改 `~/.claude.json` 里对应两处路径）；② 手机已刷模块、端口已开、adb 连得上。
- **第一步永远先** `device_status` 确认连得上（返回 `/health` 即 OK）。
- 这些 MCP 工具在会话里可能是**延迟加载**的：先 `ToolSearch("select:mcp__reconbridge__device_status,...")` 拿到 schema 再调。

---

## 3. 全部 MCP 工具（21 个）

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

### 3.3 动态 hook / 内存 dump / 产出物（M3 native + M4，7 个）
| 工具 | 签名 | 用途 |
|---|---|---|
| `post_hook` | `(config)` | 下发原始 hook 配置（native 或 java，见协议）。**通用入口** |
| `list_hooks` | `()` | 列当前已下发配置 |
| `unhook` | `(package, hook_id="")` | 删该包全部 / 某个 hook 配置 |
| `collect_events` | `(seconds=10, max_events=200, until_first_hit=False, until_n_events=0, fold_stack=True)` | 连 SSE 收命中事件。**`until_first_hit=True` 命中即返回**，不空等满窗口；`fold_stack` 折叠栈顶 hook 框架帧 |
| `dump_dex` | `(package, symbol="", offset="", base_arg=0, size_arg=1, lib="libart.so", restart=True)` | hook dex 加载入口，把内存中已解密 dex 回传落盘（脱壳） |
| `list_dumps` | `()` | 列已落盘 dump（用 `read_remote_file` 取回） |
| `list_artifacts` | `(package_name="")` | 列 PC 已产出物：已拉 apk / native so / jadx 目录 / Hermes 目录，免翻找是否拉过/反编译过 |

### 3.4 Java trace / 实时篡改（M5，2 个）★ 面向 LSPosed 开发
| 工具 | 签名 | 用途 |
|---|---|---|
| `trace_java` | `(package, class_name, method, params=None, args_render="tostring", capture_args=None, fields=None, paths=None, this="class", ret=True, when="after", stack=False, hook_id="", debug=False, restart=True, seconds=12, max_events=200, until_first_hit=False, until_n_events=0, fold_stack=True)` | **一步 hook 一个 Java 方法并采集**：看 this/参数/返回值/私有字段/调用顺序。`paths` 按路径取嵌套值、`render:"deep"` 深序列化、`until_first_hit=True` 命中即返回 |
| `patch_java` | `(package, class_name, method, params=None, replace_args=None, replace_return=None, skip_original=False, trace=True, capture_args=None, this="class", when="after", hook_id="", debug=False, restart=True, seconds=0, max_events=100)` | **实时篡改**：改参数 / 改返回值 / 跳过原方法。篡改持久生效直到 `unhook` |

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
- `action`(v2 篡改)：`replace_args:[{index,value,type}]`、`replace_return:{value,type}`、`skip_original`。`type ∈ string|int|long|boolean|double|float|short|byte|char`，**类型要与 Java 签名匹配**。命中事件带 `tampered:true`。
- `debug:true` 才逐命中打 logcat（默认安静）。

---

## 5. 典型工作流（示例包名/类名请替换成你的目标）

**A. 摸清一个 App 的结构（侦察）**
```
device_status → list_packages(name_filter="关键字") → pull_apk("com.target.app")
→ decompile_apk(base.apk) / dexkit_search(base.apk, {"find":"method","using_strings":[...]})
→ (加壳/动态 dex) dump_dex(...) 或 pull_libs + ghidra_analyze
```

**B. 定位并观测一个 Java 方法（LSPosed 开发前的侦察）**
```
# 先确保 Tracer 模块已启用且目标 App 在 LSPosed 作用域内
trace_java(package="com.target.app",
           class_name="com.target.Foo", method="doWork",
           capture_args=[{"index":1,"render":"json","max":2000}],
           fields=[{"target":"this","name":"mState","render":"tostring"}],
           restart=True, seconds=30)
# 手机上触发目标行为 → 秒级拿到参数/返回值/字段/调用顺序，无需建 APK
```

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

---

## 6. 高频坑（务必记住）

1. **adb + Git Bash（Windows）**：所有 adb 命令前 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`，否则 `/data/...` 被改写成 Windows 路径。
2. **已运行的目标要 `restart:true`**：模块/native 层在**进程启动时**读一次配置；改配置后目标不重启不生效（`restart` 会 `am force-stop` 触发重注入）。
3. **稀疏事件的采集时序**：广播器**不回放历史**，命中必须在采集期间发生。**优先用 `until_first_hit=True`**（命中即返回，不必和窗口掐点）；把 `seconds` 设大些当兜底即可，触发晚也没关系。仅当就是要固定窗口批量收集时才用纯 `seconds`。
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
2. 明确目标 App 包名（`list_packages`）。
3. 侦察走 §5.A；要看/改 Java 行为走 §5.B/C（**先确认 Tracer 模块已在 LSPosed 启用并勾了该 App**）。
4. 记住 §6 的坑，尤其 `restart:true`、采集时序、篡改后 `unhook`。
