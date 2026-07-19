# ReconBridge —— 通用逆向分析 KernelSU 模块

在 Android（KernelSU root）设备上运行的**通用逆向能力后端**。手机侧只做原子能力（拉包 / 读文件 / 列 so / 注入 hook），所有智能（定位函数、生成 hook、分析结果）都在 PC 侧（Claude Code + MCP）完成。

> 📌 **给 AI agent / 新会话的一页纸速查：[`AGENTS_QUICKSTART.md`](AGENTS_QUICKSTART.md)** —— 全部 MCP 工具签名、M5 用法、典型工作流、高频坑，读一篇即可上手。

> 进度：**M1 / M2 / M3 / M4 / M5 均已完成并真机验证**（Xiaomi SM8750 / Android 16 / KernelSU + ZygiskNext + LSPosed）。
> - **M5**：通用 Java trace + 实时篡改（LSPosed 模块，`trace_java` / `patch_java`）—— 见 [`m5/README.md`](m5/README.md)、[`m5/JAVA_HOOK_PROTOCOL.md`](m5/JAVA_HOOK_PROTOCOL.md)。

---

> ## ⚠️ 免责声明 / Disclaimer
>
> 本项目**仅供已获授权的安全研究、CTF、逆向学习与防御性研究使用**。使用者须对自己所分析的设备与应用**拥有合法授权**（自有设备、明确授权的渗透测试、公开的教学样本等）。
>
> **禁止**将本项目用于未经授权的破解、绕过版权/许可保护、窃取数据、攻击第三方系统或任何违反当地法律的行为。作者不对任何滥用或由此产生的后果负责。继续使用即表示你已理解并接受以上条款。
>
> *For authorized security research and educational use only. You are responsible for having proper authorization for any device/app you analyze.*

---

## 快速开始

### PC 端（一键装 MCP 工具）

支持两种 AI 客户端：**Claude Code**（写 `~/.claude.json`）与 **ChatGPT Codex**（写 `~/.codex/config.toml`）。默认 `both`＝**自动探测**：只注册进「已安装」的客户端（Claude 看 `~/.claude.json`/`~/.claude/`，Codex 看 `~/.codex/`），没装的那个自动跳过、不建目录；**两个都没检测到就只装工具本体、不写任何配置**（等你装好客户端再重跑注册，或用 `--target` 强制写入）。另需 `adb`（Android platform-tools，连真机用）。

**推荐：一行在线安装（Windows，无需 clone 仓库、无需 Python）**

```powershell
irm https://github.com/lm060719/reconbridge/releases/latest/download/install.ps1 | iex
```

自动下载打包好的 MCP exe、解压到 `%LOCALAPPDATA%\ReconBridge\`、注册进客户端用户级配置，并铺一个 `reconbridge` skill（逆向类任务时新会话自动加载工作流）：
- **Claude Code** → `~/.claude.json` 的 `mcpServers.reconbridge` + skill 到 `~/.claude/skills/`
- **ChatGPT Codex** → `~/.codex/config.toml` 的 `[mcp_servers.reconbridge]` + skill 到 `~/.codex/skills/`

装完**重启对应客户端**即用。
> exe 内含 MCP server 与核心依赖（含 androguard）；jadx / Ghidra 仍为可选反编译工具，解压到 `%LOCALAPPDATA%\ReconBridge\tools\` 即被自动探测（`toolchain_status` 查看）。
> **强制只装一个**（跳过探测）：先设 `$env:RB_TARGET="codex"`（或 `"claude"`）再执行——此时即使目录不存在也会创建。**wifi 传输**：先设 `$env:RB_TRANSPORT="wifi"`。

**更新**：重跑上面那条安装命令即可——它会原地覆盖 exe 并重新注册，保留 `work\`（拉包/dump 数据）与 `tools\`。

**卸载**：
```powershell
irm https://github.com/lm060719/reconbridge/releases/latest/download/uninstall.ps1 | iex
```
从两个客户端注销 reconbridge 并删除安装目录（默认保留 `work\`/`tools\` 数据；连数据一起删设 `$env:RB_PURGE="1"`；只卸某一个设 `$env:RB_TARGET="codex"`）。等价地，exe 也能自注销：`reconbridge-mcp.exe --unregister [--target codex]`。

**本地控制台（可选，图形化选连接方式 / 看状态）**

```powershell
reconbridge-mcp --serve            # 一键安装会把它加进 PATH——装完「新开一个终端」即可用；浏览器自动打开 127.0.0.1:9000
# 若提示找不到命令（PATH 未生效或未加），用全路径：
#   %LOCALAPPDATA%\ReconBridge\reconbridge-mcp\reconbridge-mcp.exe --serve
# 源码装法：python -m reconbridge_mcp --serve
```

网页里选 adb / wifi、一键连接、看 daemon 状态与只读监控（活动 hook / 近期事件流 / 落盘 dumps），省去命令行设环境变量、手抄 token。仅绑 `127.0.0.1`（本机）。`--port N` 改端口、`--no-open` 不自动开浏览器。

**adb 还是 wifi？监听地址的坑**

- **adb（USB，默认）**：自动读 token、建 USB 隧道，免配置、最安全（daemon 只绑本机回环）。代价：连接时会把设备端监听地址**钉成 `127.0.0.1`**（配合隧道），且要给 adb shell root。
- **wifi（局域网直连）**：需要设备端 daemon 绑到**局域网 IP**。在**手机 WebUI「网络设置」→「监听地址」**填 `auto`（自动绑 `wlan0` 局域网 IP）保存，或设备上 `rbctl setbind auto`；然后用 `http://<手机IP>:<端口>` + token 连（IP / 端口 / token 都在手机 WebUI 显示）。
- ⚠️ **用过 adb 模式后想切 wifi**：`bind` 已被钉成 `127.0.0.1`，电脑连不上——把「监听地址」改回 `auto` 即可。想固定走 wifi，就别再用 adb 模式（每次会重新钉回 `127.0.0.1`）。

**从源码运行（开发者 / Linux / macOS，需 Python 3.10+）**

```powershell
# Windows
git clone https://github.com/lm060719/reconbridge.git
cd reconbridge
./install.ps1              # 建 venv → 装依赖 → 注册 reconbridge + 铺 skill（默认 Claude + Codex）
./install.ps1 -Target codex   # 只装 Codex（另可 -Transport wifi）
```

```bash
# Linux / macOS
git clone https://github.com/lm060719/reconbridge.git
cd reconbridge
./install.sh                  # 默认 both；只装 Codex：./install.sh adb codex
```

装完**重启对应客户端**：Claude Code 里 `claude mcp list` / `/mcp` 能看到 `reconbridge`（25 个工具），Codex 的 `~/.codex/config.toml` 里有 `[mcp_servers.reconbridge]`；两端都会随装一个 `reconbridge` skill（`~/.claude/skills/` 或 `~/.codex/skills/`，逆向类任务时新会话自动加载工作流与踩坑清单）。
> 脚本直接写 `~/.claude.json` / `~/.codex/config.toml`（用户级作用域），比客户端自带的 `add` 命令更稳（后者在 Windows / 非 ASCII 路径下对引号/编码处理有坑）；写 TOML 时只增删 `reconbridge` 表块，用户其它配置与注释原样保留。如只想在本仓库目录内启用 Claude，见 [`.mcp.json.example`](.mcp.json.example)。自己构建 exe：`./build_exe.ps1`（产出 `dist/reconbridge-mcp-win64.zip`）。

### 设备端（刷入 KernelSU 模块）

设备需已 root（KernelSU），装 ZygiskNext（M3/M4 动态 hook 需要）。

```powershell
./build.ps1               # 用 NDK 编译 arm64-v8a（需 Android NDK，见下）
./pack.ps1                # 打包 dist/ReconBridge-M1.zip
```

在 KernelSU Manager → 模块 → 从本地安装 `dist/ReconBridge-M1.zip` → 重启。
> 仓库已内置预编译产物（`module/bin`、`module/zygisk`、`module/system/lib64`），若不想自己编译，直接 `./pack.ps1` 打包即可，或用 [Releases](../../releases) 里的 zip。

装好后对 Claude Code 说一句「连一下手机看状态」即可开始。详见下方各里程碑文档。

## 里程碑总览

| 里程碑 | 内容 | 文档 |
|--------|------|------|
| **M1** | 静态传输层：KernelSU 模块 + C++ HTTP 守护进程 + WebUI + 静态接口 | 本文（下方） |
| **M2** | PC 端 MCP Server：M1 接口 + 本地反编译链（jadx / DexKit→androguard / Ghidra / Hermes）封装为 Claude Code 工具 | [`pc/README.md`](pc/README.md) |
| **M3** | 通用动态 hook 执行器：Zygisk 注入 + 数据驱动 ShadowHook + SSE/WS 命中推流 | [`m3/README.md`](m3/README.md) · 协议 [`m3/HOOK_PROTOCOL.md`](m3/HOOK_PROTOCOL.md) |
| **M4** | 加固/反调试增强：通用内存 dex dump（`/dump_dex`）+ 反检测 hook 配置模板 | [`m4/README.md`](m4/README.md) |

构建全部产物：`./build.ps1` → `./pack.ps1`（生成 `dist/ReconBridge-M1.zip`）。
> 设备端注意：Windows 经 adb 传 `/data/...` 路径需 `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'`（Git Bash 否则会改写 Unix 路径）。

---

## M1 —— 静态传输层

KernelSU 模块骨架 + C++ HTTP 守护进程 + WebUI 端口开关 + 静态接口。

### 目录结构

```
逆向模块/
├─ src/
│  ├─ daemon.cpp              # C++17 守护进程源码
│  └─ third_party/
│     ├─ httplib.h            # cpp-httplib 0.18.3（单头）
│     └─ json.hpp             # nlohmann/json 3.11.3（单头）
├─ module/                    # 刷入 zip 的内容（zip 根 = 此目录）
│  ├─ module.prop
│  ├─ customize.sh            # 安装脚本（架构检查 / 权限）
│  ├─ service.sh              # late_start 拉起守护进程
│  ├─ rbctl                   # 控制脚本（enable/disable/info…）
│  ├─ bin/reconbridge_daemon  # 编译产物（arm64-v8a）
│  └─ webroot/index.html      # KernelSU WebUI
├─ CMakeLists.txt             # cmake 构建（可选）
├─ build.ps1                  # 直接用 NDK clang++ 构建（推荐，无需 cmake）
├─ pack.ps1                   # 打包成刷入 zip
└─ README.md
```

### 一、编译

需要 Android NDK（本项目用 r27c）。已在 `%LOCALAPPDATA%\Android\Sdk\ndk\` 下自动探测。

```powershell
# 方式 A（推荐，无需 cmake）：直接调用 NDK clang++
./build.ps1

# 方式 B：cmake + ninja
cmake -B build -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE=$env:ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake `
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build
```

产物：`module/bin/reconbridge_daemon`（AArch64 PIE ELF，~900 KB，静态链接 libc++）。

### 二、打包刷入 zip

```powershell
./pack.ps1
# 生成 dist/ReconBridge-M1.zip
```

### 三、刷入

- KernelSU Manager → 模块 → 从本地安装 → 选 `ReconBridge-M1.zip` → **重启**。
- 或 `adb`：
  ```
  adb push dist/ReconBridge-M1.zip /data/local/tmp/
  adb shell su -c "ksud module install /data/local/tmp/ReconBridge-M1.zip"
  adb reboot
  ```

### 四、开启端口

重启后端口**默认关闭**。在 KernelSU Manager → 模块 → ReconBridge 打开 WebUI：

1. 打开「端口开关」。
2. 记下页面显示的 **访问 URL**（如 `http://192.168.x.x:8787`）与 **token**。
3. 用完记得关闭开关。

> WebUI 只写 `config.conf`，守护进程通过 inotify 感知变更即时生效，不直接控制 native 进程。

### 五、验收（PC 侧，同一 Wi-Fi）

设 `IP`/`TOKEN`/`PKG` 为实际值：

```bash
# 1) 存活
curl -H "X-Token: TOKEN" http://IP:8787/health

# 2) 列应用
curl -H "X-Token: TOKEN" "http://IP:8787/packages"

# 3) 查某应用全部 apk 路径（含所有 split）
curl -H "X-Token: TOKEN" "http://IP:8787/apk?pkg=PKG"

# 4) 拉某个 apk（流式，等价 adb pull，不依赖 adb 授权）
#    从上一步取到具体 path 后：
curl -H "X-Token: TOKEN" "http://IP:8787/apk?pkg=PKG&path=/data/app/.../base.apk" -o base.apk

# 5) 拉 native so
curl -H "X-Token: TOKEN" "http://IP:8787/libs?pkg=PKG"
curl -H "X-Token: TOKEN" "http://IP:8787/libs?pkg=PKG&path=/data/app/.../lib/arm64/libfoo.so" -o libfoo.so

# 6) 读任意文件
curl -H "X-Token: TOKEN" "http://IP:8787/file?path=/system/build.prop"

# 7) procfs
curl -H "X-Token: TOKEN" "http://IP:8787/proc?pid=1&what=status"

# 8) 白名单 shell
curl -H "X-Token: TOKEN" -X POST "http://IP:8787/shell" \
     -d '{"argv":["getprop","ro.product.model"]}'
```

**M1 验收标准**：PC 上用 curl 带 token，能把手机上任意一个 App 的完整 APK（含所有 split）和 native so 拉到本地，效果等价于 `adb pull` 但不依赖 adb 授权。

---

## 静态接口清单

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/health` | 存活探测（name/version/pid/uptime） |
| GET  | `/packages` | 列出已安装应用（包名 / versionCode / 路径 / 是否系统应用） |
| GET  | `/apk?pkg=` | 列出该应用全部 apk 路径（base + split）；加 `&path=` 流式下载单个 |
| GET  | `/file?path=` | root 流式读任意文件（绝对路径） |
| GET  | `/libs?pkg=` | 列出该应用 lib 目录下 native `.so`；加 `&path=` 下载单个 |
| GET  | `/proc?pid=&what=maps\|status\|cmdline` | 转发 procfs |
| POST | `/shell` | 白名单命令执行，body：`{"argv":[...]}` 或 `{"cmd":"..."}` |

鉴权：三选一 —— 请求头 `X-Token: <token>`、`Authorization: Bearer <token>`、或查询参数 `?token=<token>`。

`/shell` 白名单：`id whoami getprop uname ls cat stat du df md5sum sha1sum sha256sum pm cmd dumpsys ps getenforce settings wc head tail ip netstat pgrep mount readlink basename dirname find date`。不走 `sh -c`，直接 `execvp`，白名单外拒绝。

---

## 安全说明

- 端口**默认关闭**，仅用户在 WebUI 手动开启，用完手动关闭；重启后回到关闭。
- 全部接口 token 鉴权；token 启动时随机生成（16 字节 hex）。
- 默认绑定 `wlan0` 的局域网 IP（`bind=auto`），非 `0.0.0.0`；未探测到时回退 `0.0.0.0` 并告警。监听地址可在 **WebUI「网络设置」→「监听地址」**修改（`auto` / `0.0.0.0` / 具体 IP / `127.0.0.1`）。注意 adb 模式连接会自动把它设为 `127.0.0.1`。
- 手机侧只做搬运，不含任何特定 App 逻辑（符合 `ndde.md` 设计原则）。

## 运行时文件

`/data/adb/reconbridge/`：
- `config.conf` —— `enabled` / `port` / `bind` / `token`
- `daemon.log` —— 守护进程日志

## 已知限制（M1）

- `/packages` 的「版本」取 `versionCode`（`pm` 一次调用即可，快）；`versionName` 需 `dumpsys`，M1 未纳入。
- `/libs` 只列**落地**的 `.so`；若应用 `extractNativeLibs=false`，so 在 apk 内 `lib/arm64-v8a/`，请用 `/apk` 拉包后本地解包（接口会在 `note` 提示）。
- `/shell` 的 `cmd` 字符串按空白朴素切分，不支持引号；复杂命令用 `argv` 数组形式。
