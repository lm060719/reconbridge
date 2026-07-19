**中文** | [English](README_en.md)

# ReconBridge M3 —— 通用动态 Hook 执行器

Zygisk 注入 + 数据驱动 ShadowHook 执行器 + 命中事件实时推流（SSE / WS）。
模块侧只是**通用执行器**，不含任何特定 App 逻辑；hook 点由 PC 侧下发的 JSON 配置描述，改 hook 无需重编刷入。

> hook 配置协议见 `HOOK_PROTOCOL.md`。

## 组成

```
m3/
├─ HOOK_PROTOCOL.md            # hook 配置 JSON 协议 + 事件格式（PC 下发用）
├─ zygisk/
│  ├─ module.cpp               # Zygisk 模块（注入层）+ 数据驱动 ShadowHook 执行器
│  └─ third_party/             # zygisk.hpp / shadowhook.h / json.hpp
└─ prebuilt/                   # libshadowhook.so + libshadowhook_nothing.so（bytedance 2.0.1）

（守护进程侧 M3 代码在 src/dynamic.cpp：/hook /unhook /hooks + SSE/WS + 注入 IPC socket）
```

刷入 zip 里 M3 相关文件：
- `zygisk/arm64-v8a.so` —— 注入层（ZygiskNext 加载）
- `system/lib64/libshadowhook.so` + `libshadowhook_nothing.so` —— 挂到 /system/lib64
- `sepolicy.rule` —— 放行 app 域连接守护进程注入 socket

## 前置：设备需有 Zygisk 实现
KernelSU 本身不带 Zygisk，需要 **ZygiskNext（zygisksu）** 或 ReZygisk。安装脚本会检测并提示。

## 运行架构

```
POST /hook ─► 守护进程写 /data/adb/reconbridge/hooks/<pkg>.json（可选 am force-stop 触发重注入）
目标 App 启动 ─► ZygiskNext 注入 zygisk/arm64-v8a.so
   注入层(app 域) ──connect──► 守护进程抽象 socket @reconbridge_inject（ksu 域，sepolicy 放行）
        取本包 hook 配置；从 /system/lib64 按名 dlopen libshadowhook.so，shadowhook_init
        按配置注入 hook（shadowhook_hook_sym_name / _sym_addr）
   命中 ─► 代理抓 x0-x7 参数 + 返回值(+可选调用栈) ─► 事件 JSON 经 socket 回传守护进程
守护进程广播 ─► GET /events(SSE) 与 ws://host:port+1/events(WS) 实时推流
```

**关键点：为什么 shadowhook 库放 /system/lib64。** 注入层处于 app SELinux 域，读不到 /data/adb；
若用 memfd 加载 shadowhook，shadowhook 的 linker init 会 `dlopen("libshadowhook_nothing.so")`
来验证 linker hook，而 memfd 加载的库处于各自匿名 linker 命名空间，shadowhook 找不到 nothing.so →
`shadowhook_init` 返回 12（INIT_LINKER）。把两个 .so 通过模块 `system/lib64/` 挂到 /system/lib64
（默认命名空间，nothing.so 同级），并 `chcon` 成 `system_lib_file`（否则默认 system_file 不允许
app 执行），注入层按名 `dlopen("libshadowhook.so")` 即可，与普通 App 用法一致，init 成功。

## 动态接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/hook`   | 下发 hook 配置（写 hooks/<pkg>.json，可选 force-stop） |
| POST | `/unhook` | 移除某包全部或指定 id 的 hook |
| GET  | `/hooks`  | 列出当前下发的 hook 配置 |
| GET  | `/events` | SSE 事件流（curl 友好） |
| WS   | `/events` | `ws://host:(port+1)/events?token=…` |

## 验收（已在真机通过）

设备：Xiaomi SM8750 / Android 16 / KernelSU + ZygiskNext。

```bash
# 1) 下发 hook：抓 libc __system_property_get 的参数(属性名)与返回值
curl -H "X-Token: $T" -X POST http://IP:8787/hook -d '{
  "package":"com.salt.music","restart":true,
  "targets":[{"id":"propget","lib":"libc.so","symbol":"__system_property_get",
    "capture":{"args":[{"index":0,"type":"string","max":128}],"ret":{"capture":true,"type":"int"}},
    "action":{"type":"observe"}}]}'

# 2) 订阅事件流
curl -N -H "X-Token: $T" http://IP:8787/events
```

实测 SSE/WS 均实时收到命中事件，例如：
```json
{"ts":1784366050786,"package":"com.salt.music","hook_id":"propget","pid":10295,"tid":22095,
 "lib":"libc.so","symbol":"__system_property_get","action":"observe",
 "args":[{"index":0,"type":"string","value":"ro.build.version.sdk"}],"ret":{"type":"int","value":2}}
```
即：每次该 native 函数被调用，实时看到参数（属性名字符串）与返回值（长度）。**M3 验收通过。**

## 能力与限制

- 参数/返回值走 AAPCS64 整型/指针寄存器 x0–x7 / x0；**不抓浮点(d0–d7)**。
- 支持 `observe` / `replace_ret`（篡改返回值）/ `replace_arg`（篡改入参）。
- 参数类型：int / ptr / string(C 串) / bytes(指针+长度，hex)；可选调用栈（原始 PC 列表）。
- 定位方式：符号名（`shadowhook_hook_sym_name`，lib 未加载时自动 pending）或相对偏移
  （`shadowhook_hook_sym_addr`，lib 未加载时注册 dlopen 回调延迟补挂）。
- 注入在 zygote fork 时；对已运行进程需重启 App（`restart:true` 让守护进程 force-stop）。
- 单进程 hook 点上限 64（编译期常量）。
- 内存读取用 `process_vm_readv` 做保护，坏指针返回失败而非崩溃。
