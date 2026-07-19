**中文** | [English](README_en.md)

# ReconBridge M4 —— 加固 / 反调试增强

在 M3 通用执行器之上，用**数据驱动 hook 配置**应对整体加固与动态分析对抗。
**模块本体不含任何具体加固/安全 SDK 的逻辑**——所有对抗都通过 PC 下发 hook 配置解决。

## 一、通用内存 dex dump（应对整体加固壳）

加固壳在运行时把解密后的 dex 交给 ART 加载。hook dex 加载入口，拿到内存里 dex 的基址+长度，
把这段内存回传落盘，即得到脱壳后的 dex。

**执行器新增 `dump` 能力**：hook 命中时读 `[x_base_arg, +x_size_arg)` 内存，经注入 socket
回传守护进程，落盘到 `/data/adb/reconbridge/dumps/`。命中事件里带 `"dump":{"saved":..,"bytes":..}`。

### 接口
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/dump_dex` | 便捷下发 dump 配置：`{package, lib, symbol\|offset, base_arg, size_arg, max?, ext?, restart?}` |
| GET  | `/dumps`    | 列出已落盘的 dump（用 `/file?path=` 取回） |

也可直接用 `/hook` 下发带 `capture.dump` 的 target（见 `templates/dump_dex_art.json`）。

### 用法
```bash
# 1) 用 M2 分析 libart.so 找 dex 加载入口及其 base/size 参数位置
#    ghidra_analyze /system/lib64/libart.so  → 找 OpenMemory / DexFile 相关导出
# 2) 下发 dump（symbol 按实际 libart 符号；base_arg/size_arg 按参数布局）
curl -H "X-Token: $T" -X POST http://IP:8787/dump_dex -d '{
  "package":"com.target.app","lib":"libart.so",
  "symbol":"_ZN3art7DexFile10OpenMemoryEPKhm...","base_arg":0,"size_arg":1,"restart":true}'
# 3) 启动目标触发加载 → 列出并取回 dump
curl -H "X-Token: $T" http://IP:8787/dumps
curl -H "X-Token: $T" "http://IP:8787/file?path=/data/adb/reconbridge/dumps/xxx.dex" -o xxx.dex
# 4) 本地用 M2 的 dexkit_search / decompile 分析脱壳 dex
```

> 不同 Android/ART 版本的 dex 加载符号与参数布局不同，故模块只提供**通用 dump 机制**，
> 具体入口由 PC 侧用 M2 定位后下发——符合“智能在 PC 侧、手机侧只做原子能力”。

## 二、反检测 hook 配置模板库（`templates/`）

常见反调试 / 反 hook / root 检测点的可复用配置。分两类用法：

- **observe（定位）**：先挂 libc 的 `access/fopen/openat/strstr` 等，抓路径/字符串参数+调用栈，
  看目标在检查什么、从哪里发起 → 用 M2 反编译定位到 App **自身的检测函数**。
- **replace_ret（精准绕过）**：对定位到的检测函数下 `replace_ret`，返回“未检测到”。

| 模板 | 用途 |
|------|------|
| `anti_debug_ptrace.json`   | ptrace 反调试绕过（replace_ret 0） |
| `root_detection_locate.json` | 定位 root 检测（observe access/fopen + 调用栈） |
| `frida_xposed_locate.json` | 定位 Frida/Xposed 检测（observe openat/strstr） |
| `dump_dex_art.json`        | 内存 dex dump（ART 入口示例，符号需按版本调整） |

用法：把模板里的 `<TARGET_PKG>` 换成目标包名，`/hook` 下发即可。

### 重要限制
执行器的 `replace_ret` / `replace_arg` 是**无条件**的（每次调用都改），不做参数值匹配。
因此**不建议**对 `access/open` 这类高频通用 libc 函数直接 replace（会影响全局逻辑）；
正确姿势是：observe 定位 → 找到 App/壳 里那个**具体的**检测函数 → 只对它 replace_ret。
需要“仅当参数=某 root 路径时才改返回值”的条件绕过，属于 App 特定逻辑，交由 PC 侧决策下发到
精准的检测函数上，模块侧保持通用。

## 与其它里程碑的关系
- 定位（找检测函数 / dex 入口符号）：M2（jadx / dexkit / ghidra）。
- 注入与执行：M3 通用 ShadowHook 执行器。
- 取回产物（dump 的 dex / so）：M1 静态 `/file`、M2 `pull_*`。
