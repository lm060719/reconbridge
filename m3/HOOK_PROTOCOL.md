# ReconBridge 动态 Hook 配置协议（M3）

> 新增 `kind:"jni"` 注册观察器，以及事件 `seq/stream_id`、缓冲丢失统计和 `/jni/bindings`。
> 接口与覆盖边界见 [诊断、事件完整性与 JNI 映射](../pc/OBSERVABILITY.md)。

PC 侧下发**数据驱动**的 hook 配置，手机侧通用执行器解析并用 ShadowHook 注入。改 hook 无需重新编译刷入。

## 约束与说明
- 目标：arm64-v8a / x86_64，最多 8 个标量参数。整数/指针与 float/double 分别使用对应 ABI 寄存器或栈位置。
- 浮点函数必须声明完整 `signature`；签名、替换与特殊值编码见 [Native 浮点支持](../pc/NATIVE_FLOAT.md)。
- 首次注入发生于目标进程启动；在线 Native 连接支持 H(kind=native) / R / S 实时新增、替换和透传停用。签名变更需重启。
- M5 Java Tracer 使用 HookRegistry 执行实时新增、替换与物理 unhook。Native 停用保留机器码跳板，边界见 [Native 实时配置](../pc/NATIVE_LIVE.md)。
- 执行器 hook 点上限 64（够用；可编译期调整）。

## 下发：`POST /hook`

```jsonc
{
  "package": "com.target.app",   // 必填，目标进程包名
  "restart": true,               // 可选，下发后 force-stop 该包以触发重新注入（默认 false）
  "mode": "append",              // 可选 replace(默认)|append：append 按 target.id 合并进现有配置
  "targets": [                   // 一个或多个 hook 点
    {
      "id": "enc1",              // 该 hook 点标识（回传事件里带上；缺省服务端生成）
      "lib": "libfoo.so",        // 目标 so 名（ShadowHook 按 lib+符号 定位；offset 模式也需要）
      "symbol": "encrypt",       // 符号名；与 offset 二选一
      "offset": "0x12f40",       // 相对 so 加载基址的偏移（hex 字符串或整数）；与 symbol 二选一
      "capture": {
        "args": [                // 要抓的逻辑参数（从 0 开始）
          {"index": 0, "type": "int"},
          {"index": 1, "type": "string", "max": 256},        // char*，读到 NUL，最长 max
          {"index": 2, "type": "bytes", "len_from": 3},      // 指针+长度，长度取自第 3 个参数
          {"index": 2, "type": "bytes", "len": 16},          // 指针+固定长度
          {"index": 4, "type": "ptr"}                        // 原始指针值（hex）
        ],
        "ret": {"capture": true, "type": "int"},             // 抓返回值 + 类型（另支持 float|double）
        "backtrace": false                                    // 是否抓调用栈（返回原始 PC 列表）
      },
      "action": {
        "type": "observe",       // observe（只读） | replace_ret（篡改返回值） | replace_arg（篡改参数）
        "ret_value": 0,          // type=replace_ret：新的返回值（浮点需 signature）
        "arg_overrides": [       // type=replace_arg：进入原函数前覆盖这些逻辑参数
          {"index": 0, "value": 1}
        ]
      }
    }
  ]
}
```

**采集类型取值**：`float`、`double`（需匹配完整 signature），`int`（有符号 64 位）、`ptr`（指针，hex 输出）、`string`（C 字符串）、`bytes`（原始字节，hex 输出，需 `len` 或 `len_from`）。

**响应**：`{"ok":true,"package":"...","installed":[{"id":"enc1"}],"note":"..."}`
（note 会提示“配置已写入，注入在目标下次启动时生效”或“已 force-stop 触发重启”。）

## 移除：`POST /unhook`
```jsonc
{"package": "com.target.app"}          // 移除该包全部期望 hook
{"package": "com.target.app", "id": "enc1"}   // 只移除某个 hook 点
```
对 **M5 Java Tracer**，daemon 会同步剩余完整配置（或 `targets:[]`），HookRegistry 立即执行 live unhook；对支持实时配置的 **M3 native**，后续调用透传原函数，在途调用保留旧配置；未物理撤钩。

## 查询：`GET /hooks` / `GET /runtime_status`
`GET /hooks` 返回磁盘上的**期望 hook 配置**（读 `/data/adb/reconbridge/hooks/*.json`）：
```jsonc
{"count":1,"hooks":[{"package":"com.target.app","targets":[...],"active_processes":[12300]}]}
```

M5 Java Tracer 的真实进程状态改用 `GET /runtime_status?package=com.target.app`（MCP: `runtime_hook_status`），可看到每个连接进程的 pid、实际 installed id/member、`live_unhook` 和 `replace_supported`。

## 事件流：`GET /events`（SSE）与 `WS /events`
hook 命中实时推流。每条事件：
```jsonc
{
  "ts": 1731000000123,          // epoch 毫秒
  "package": "com.target.app",
  "hook_id": "enc1",
  "pid": 12300, "tid": 12345,
  "lib": "libfoo.so", "symbol": "encrypt",
  "args": [
    {"index":0,"type":"int","value":42},
    {"index":1,"type":"string","value":"hello"},
    {"index":2,"type":"bytes","value":"00112233aabb"}
  ],
  "ret": {"type":"int","value":0},        // 若 capture.ret.capture
  "backtrace": ["0x7ab1230000","0x7ab1231111"],  // 若 capture.backtrace
  "action": "observe"                      // 实际执行的动作
}
```
- **SSE**：`GET /events`（`Accept: text/event-stream`），每条事件一行 `data: {json}\n\n`。curl 友好。
- **WS**：`ws://host:port+1/events?token=...`（独立端口，见下）。二者内容一致。
- **事后采集**：`GET /recent?limit=N&since_seq=S` 返回环形缓冲里最近事件 `{latest_seq,count,events}`。
  SSE/WS 不回放历史，命中若发生在连流之前就漏了；`/recent` 补上——保留最近 ~400 条，命中即便在
  采集开始前也能捞回（PC 侧 `recent_events` / `collect_events(include_recent=True)`）。`latest_seq` 作游标取增量。

> 说明：M1 守护进程用 cpp-httplib（仅 HTTP）。SSE 走同一 HTTP 端口；WebSocket 用**独立端口 = HTTP 端口+1** 的极简 WS 服务实现，二选一即可，PC 侧推荐 SSE（更简单）。

## 内部数据流（实现细节）

> 当前版本的 native 层直接连接 daemon 的注入 IPC，接收配置和回传事件。
> 支持 H(kind=native) / R 完整配置 / S 状态的版本可运行中新增、停用和替换；
> 停用保留透传跳板，物理撤钩仍未实现。用法和限制见 [Native 实时配置](../pc/NATIVE_LIVE.md)。
> 下图为早期 companion 方案，保留作历史背景，不代表当前部署链路。
```
POST /hook ─► 守护进程写 /data/adb/reconbridge/hooks/<pkg>.json
                                    │ (可选 am force-stop <pkg>)
目标 App 启动 ─► Zygisk 注入我们的 zygisk so
   injected(app 域) ─connectCompanion─► companion(root 域)
        companion 读 hooks/<pkg>.json + libshadowhook.so 字节 ─► 回传 injected
        injected: memfd 加载 shadowhook，按配置注入 hook
   命中 ─► injected 把事件行经 companion ─► companion 追加到 events.log
守护进程 inotify 监听 events.log ─► 推给 SSE/WS 客户端
```
（injected 处于 app SELinux 域，不能直接读 /data/adb 或连守护进程，故一切经 root 域的 companion 中转。）
