# 项目：通用逆向分析 KernelSU 模块（ReconBridge）

## 一句话定位
在 Android 设备（KernelSU root）上运行一个**通用逆向能力后端**，通过局域网 HTTP/WebSocket 暴露原子能力；PC 端 Claude Code 通过 MCP server 调用它，把手机当作一个可编程的逆向工作台。模块本身**不内置任何针对特定 App 的逻辑**——所有智能（定位函数、生成 hook、分析结果）都在 PC 侧完成。

## 目标设备 / 环境（硬性约束）
- 设备：Xiaomi 15 Ultra，SoC 骁龙 8 Elite（SM8750），arm64-v8a
- 系统：Android 16（API 36），HyperOS
- Root：KernelSU（非 Magisk），支持 Zygisk（通过 ZygiskNext / KernelSU 的 Zygisk 实现）
- Native hook 库：**ShadowHook**（bytedance/android-inline-hook），项目统一用它，不要引入 Frida 到模块本体
- PC 端：Windows，Claude Code 作为主要开发/调用工具
- 交叉编译：Android NDK，目标 minSdk 26+，arm64-v8a 优先（可选加 armeabi-v7a）

## 核心设计原则（务必遵守）
1. **手机侧只做原子能力，长期不动**：模块提供 pull apk / 读文件 / 注入 hook / dump dex 等原子操作，不为任何具体 App 写死逻辑。
2. **动态 hook 走"数据驱动"，不走"重新编译"**：PC 端下发的是 hook 配置（JSON：目标 so、符号或偏移、抓哪几个参数、抓不抓调用栈），模块侧有一个**通用 ShadowHook 执行器**解释这个配置并注入。这样 Claude Code 改 hook 无需重新编译刷入模块，天然实现热更新。
3. **智能在 PC 侧**：函数定位、控制流分析、hook 配置生成、结果解读，都由 Claude Code 配合 jadx / DexKit / Ghidra headless 完成。
4. **安全默认关闭**：模块装上并重启后，网络端口**默认关闭**，由用户在 KernelSU WebUI 手动开启，用完手动关闭。
5. **鉴权必备**：所有接口需要 token 校验；端口绑定到具体 Wi-Fi 网段而非 0.0.0.0；不做无鉴权裸 HTTP。

## 架构分层

```
PC (Claude Code + MCP server)
   │  HTTP / WebSocket (局域网, token 鉴权)
   ▼
手机 KernelSU 模块
   ├─ C++ 守护进程 (常驻, cpp-httplib 或裸 socket)
   │    ├─ 静态接口 (纯 root, 不注入)
   │    └─ 动态接口 (转发给注入层)
   ├─ Zygisk 注入层 (按需注入目标进程)
   │    └─ 通用 ShadowHook 执行器
   └─ KernelSU WebUI (端口开关 + token 显示 + 状态)
```

## 分阶段交付（里程碑）

### M1 — 静态传输层（先做这个，做到能独立验收再往下）
KernelSU 模块骨架 + C++ HTTP 守护进程 + WebUI 端口开关 + 静态接口。

**需要产出的文件：**
- `module.prop`、`customize.sh`、`service.sh`（late_start service 阶段拉起守护进程）
- C++ 守护进程源码（建议 cpp-httplib 单头库 + nlohmann/json，静态链接，产物尽量小）
- `CMakeLists.txt` 或 `Android.mk`（NDK 交叉编译到 arm64-v8a）
- KernelSU WebUI（`webroot/` 下的 index.html + JS，KernelSU WebUI 标准形式）

**静态接口清单：**
- `GET  /health` — 存活探测
- `GET  /packages` — 列出已安装应用（包名 / 版本 / 安装路径 / 是否系统应用）
- `GET  /apk?pkg=<pkg>` — 返回该应用的全部 apk 路径（base.apk + 所有 split_config.*.apk），支持按需下载单个文件，大文件流式传输不要一次性读进内存
- `GET  /file?path=<path>` — root 读任意文件（流式）
- `GET  /libs?pkg=<pkg>` — 列出并可下载该应用 lib 目录下的 native .so
- `GET  /proc?pid=<pid>&what=maps|status|cmdline` — 转发 procfs
- `POST /shell` — 执行 root 命令（**先实现白名单机制**，白名单外拒绝）

**WebUI 需要的功能：**
- 显示当前端口开关状态、监听地址、端口号
- 一键开启 / 关闭端口（写配置文件，守护进程 inotify 监听该文件即时生效；不要让 WebUI 直接控制 native 进程）
- 显示当前 token（随机生成，启动时写入配置）
- 显示守护进程运行状态

**M1 验收标准：** PC 上用 curl 带 token，能把手机上任意一个 App 的完整 APK（含所有 split）和 native so 拉到本地，效果等价于 adb pull 但不依赖 adb 授权。

### M2 — PC 端 MCP Server
把 M1 的静态接口封装成 Claude Code 可调用的 MCP 工具，并在 PC 本地集成反编译工具链。

**MCP 工具设计：**
- `list_packages()` → 调 /packages
- `pull_apk(package_name)` → 调 /apk，自动落盘到工作目录，返回本地路径列表
- `pull_libs(package_name)` → 调 /libs，拉 so 到本地
- `read_remote_file(path)` → 调 /file
- `proc_info(pid, what)` → 调 /proc
- `remote_shell(cmd)` → 调 /shell（白名单）
- `decompile_apk(apk_path)` → 本地跑 jadx-cli，返回反编译目录
- `dexkit_search(apk_path, query)` → 本地 DexKit 链式查询（类/方法/字段）
- `ghidra_analyze(so_path, options)` → Ghidra headless 分析 .so，返回导出表 / 字符串 / 可疑函数
- （React Native / Hermes 目标）`hermes_decompile(bundle_path)` → hbctool / hermes-dec 反编译 .hbc

**M2 验收标准：** 在 Claude Code 里一句话（例如"分析 <pkg> 的某功能实现"）能自动完成：拉包 → 反编译 → 定位相关类/方法/so，全程不用手动切到手机操作。

### M3 — 通用动态 hook 执行器
Zygisk 注入 + 数据驱动的 ShadowHook 执行器 + WebSocket 结果回传。

**核心：hook 配置协议（PC 下发的 JSON schema，需要你设计并文档化）**
至少支持描述：
- 目标进程（包名）
- 目标 so 名 + 符号名 或 相对基址偏移
- 抓取哪些参数（寄存器 / 栈位置，arm64 调用约定）、参数类型（int / ptr / string / bytes+len）
- 是否抓返回值、是否抓调用栈（unwind）
- hook 类型：仅观测（读参数返回值）/ 篡改返回值 / 篡改参数

**动态接口：**
- `POST /hook` — 下发 hook 配置，执行器解析并用 ShadowHook 注入到目标进程
- `POST /unhook` — 移除指定 hook
- `GET  /hooks` — 列出当前生效的 hook
- `WS   /events` — hook 命中事件实时推流（参数值 / 返回值 / 调用栈 / 时间戳）

**M3 验收标准：** Claude Code 下发一个 hook 配置，能在 WS 流里看到某个 native 函数每次被调用时的实时参数和返回值。

### M4 — 加固 / 反调试增强（最后做，用真实目标验证）
- `POST /dump_dex` — 通用内存 dex dump：hook dex 加载入口（如 `OpenMemory` / `DefineClass` 相关），把内存中已解密的 dex dump 回传。用于应对整体加固壳。
- **反检测 hook 配置库**：把常见反调试 / 反 hook / root 检测点做成可复用的 hook 配置模板（由 PC 端生成下发，模块侧仍然只是通用执行器）。
- 说明：动态分析对抗（如网易易盾这类安全 SDK 的 Frida/Xposed/root 检测）通过"下发绕过检测点的 hook 配置"解决，模块本体不需要知道任何具体安全 SDK 的存在。

## 技术注意点（避免踩坑）
- **split apk 必须全拉**：现代 App 普遍拆分 `split_config.arm64_v8a.apk` / `split_config.<lang>.apk`，DexKit 分析有时需要它们齐全，`/apk` 接口不能只返回 base.apk。
- **React Native / Hermes 目标**：很多业务逻辑在 Hermes bytecode（.hbc，通常在 assets/ 里）而非 dex 或传统 so，工具链要保留 hbc 反编译支路。
- **Zygisk 注入时机**：Zygisk 在 zygote fork 时注入，早于目标 App 大部分运行时检测，隐蔽性优于运行时 attach。
- **ShadowHook 与目标冲突**：部分 App 自身也用 shadowhook/xhook，注意 hook 点可能被目标做完整性校验；执行器要能处理 hook 失败的情况并回报。
- **arm64 调用约定**：参数抓取按 AAPCS64（x0-x7 传参，超出走栈），配置协议和执行器都要正确处理。
- **守护进程资源占用**：手机侧只做搬运和注入，重型工具（jadx/DexKit/Ghidra/IDA）全部放 PC，不要在手机上跑 JVM 级工具。
- **端口开关状态落盘**：WebUI 的开关状态写配置文件，重启后保持"默认关闭"语义（除非用户显式设置为开机自启，且默认不开机自启）。

## 编码约定
- C++：C++17，守护进程单一职责，接口与业务解耦，方便后续加接口。
- 注释和文档用中文，代码标识符用英文。
- 每个里程碑产出对应的 README 段落，说明如何编译、刷入、验收。
- 优先保证 M1 能独立编译刷入并通过验收，再进入 M2/M3/M4，不要一次性铺开全部代码。

## 明确不要做的事
- 不要在模块本体内写死任何特定 App（网易云、微信等）的逻辑。
- 不要把 Frida 塞进模块本体（PC 端调试可另行选择，但模块统一用 ShadowHook）。
- 不要做无鉴权的开放端口。
- 不要在手机侧运行 jadx / Ghidra / DexKit 等重型分析工具。
- 不要为了 libxposed API 102 热重载而增加复杂度——本项目通过"数据驱动 hook 配置"实现热更新，不依赖 Xposed 热重载机制。
