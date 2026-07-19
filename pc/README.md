# ReconBridge MCP Server（M2）

把 M1 的手机静态接口 + PC 本地反编译工具链，封装成 Claude Code 可直接调用的 MCP 工具。

## 能力总览（共 25 个工具）

> 下表列 M2 的 12 个原子 / 反编译能力；另有 M3/M5 的动态 hook、Java trace、场景捕获、落盘等，完整清单见仓库根 [`AGENTS_QUICKSTART.md`](../AGENTS_QUICKSTART.md)。

**设备原子能力（封装 M1 HTTP 接口）**
| 工具 | 作用 |
|------|------|
| `device_status` | 探测守护进程 /health 与连接方式 |
| `list_packages` | 列应用（支持 name_filter / only_third_party） |
| `pull_apk` | 拉全部 apk（base+split）到工作目录，校验字节数 |
| `pull_libs` | 拉 native .so 到工作目录 |
| `read_remote_file` | root 读任意文件（小文本内联） |
| `proc_info` | /proc/<pid>/{maps,status,cmdline} |
| `remote_shell` | 白名单 root 命令 |

**PC 本地反编译工具链**
| 工具 | 后端 | 作用 |
|------|------|------|
| `decompile_apk` | jadx | apk → Java 源码 |
| `dexkit_search` | androguard | dex 里定位 类/方法/字段/字符串（见下方 query 语法） |
| `ghidra_analyze` | Ghidra headless | .so 导出/导入表、字符串、函数、可疑函数、可选反编译 |
| `hermes_decompile` | hbctool（best-effort） | RN Hermes .hbc 反编译 |
| `toolchain_status` | — | 检查工具链就绪情况 |

> 关于 DexKit：官方无 Windows/Python 预编译包（PyPI 已下架），故 `dexkit_search` 用 **androguard** 作为等价的 dex 搜索后端，功能覆盖“定位类/方法/字段/字符串”。

## 连接方式（传输）

- **adb（默认，推荐）**：经 USB。自动读取设备 token、把守护进程绑到设备 `127.0.0.1`、开启端口、建立 `adb forward`，请求打到本机 `127.0.0.1:8787`。**localhost-only，不暴露到局域网**，免手工配 token。
- **wifi**：设 `RECONBRIDGE_TRANSPORT=wifi` + `RECONBRIDGE_URL` + `RECONBRIDGE_TOKEN`，直连局域网内设备。

## 环境准备

```powershell
cd pc
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

外部工具（`toolchain_status` 会显示探测结果）：
- **jadx**：解压到 `pc/tools/jadx`（已内置）。
- **androguard**：`pip install androguard`（在 requirements 里）。
- **Ghidra + JDK21**：Ghidra 12 需要 JDK21，且**安装路径必须是 ASCII**（本项目目录含中文，Ghidra 的 log4j 会崩）。
  默认放在同盘 `<盘符>:\ReconBridgeTools\`（如 `E:\ReconBridgeTools\ghidra_12.1.2_PUBLIC` 与 `jdk-21.x`）。
  可用 `RECONBRIDGE_NATIVE_TOOLS` 覆盖。

## 注册到 Claude Code

**推荐：一行在线安装（打包 exe，无需 clone / venv）**
```powershell
irm https://github.com/lm060719/reconbridge/releases/latest/download/install.ps1 | iex
```
下载打包好的 MCP exe 到 `%LOCALAPPDATA%\ReconBridge\` 并自注册。构建该 exe：仓库根 `./build_exe.ps1`（PyInstaller onedir → `dist/reconbridge-mcp-win64.zip`）；exe 也能自注册：`reconbridge-mcp.exe --register [--transport adb|wifi]`。

**本地 Web 控制台**：`reconbridge-mcp --serve`（源码：`python -m reconbridge_mcp --serve`）起一个只绑 `127.0.0.1:9000` 的图形控制台——选 adb/wifi、一键连接、看 daemon 状态与只读监控（活动 hook / 事件流 / dumps）。`--port N` / `--host H` / `--no-open` 可调。

**源码方式**：项目根已有 `.mcp.json`（项目级配置）。在该目录启动 Claude Code 会提示批准 `reconbridge` MCP server，批准后即可用。

手动方式：
```powershell
claude mcp add reconbridge --env PYTHONPATH=<pc路径> --env RECONBRIDGE_TRANSPORT=adb -- <venv>\Scripts\python.exe -m reconbridge_mcp
```

## `dexkit_search` 的 query 语法

```jsonc
{"find":"method", "method_name":"onReceive"}          // 按方法名（普通名=子串匹配）
{"find":"method", "using_strings":["sms_code","sign"]} // 引用了这些字符串的方法（定位利器）
{"find":"class",  "class_name":"smscode"}              // 按类名
{"find":"field",  "class_name":"Config","field_name":"token"}
{"find":"string", "string":"http"}                     // dex 里的字符串常量
// 普通名字按子串匹配；含正则元字符则当正则；可加 "max_results": N
```

## 自测

```powershell
.venv\Scripts\python test_mcp_e2e.py   # 走真正的 MCP stdio 协议自测
```

## M2 验收

在 Claude Code 里一句话即可完成 **拉包 → 反编译 → 定位类/方法/so**，全程不用手动操作手机。
例如：「拉 `com.xxx` 的包，反编译，找出做签名/加密的方法和相关 .so」。

## 工作目录

默认 `pc/work/<包名>/`：`apk/`（拉下来的 apk）、`libs/`（.so）、`*-jadx/`（反编译源码）。
可用 `RECONBRIDGE_WORKDIR` 覆盖。
