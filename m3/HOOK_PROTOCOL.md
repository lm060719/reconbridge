# ReconBridge 动态 Hook 配置协议（M3）

PC 侧下发**数据驱动**的 hook 配置，手机侧通用执行器解析并用 ShadowHook 注入。改 hook 无需重新编译刷入。

## 约束与说明
- 目标：arm64-v8a，AAPCS64 调用约定（整型/指针参数走 x0–x7，返回值 x0）。
- **参数/返回值只支持整型与指针寄存器（x0–x7 / x0）**；浮点参数（d0–d7）M3 不抓。
- 注入时机：Zygisk 在 zygote fork 目标进程时注入。**配置在进程启动时读取**，对已运行的进程需重启该 App 才生效（可用 `restart:true` 让守护进程 `am force-stop` 触发重启）。
- **免重启热加（P0-2，仅 M5 Java tracer）**：注入 socket 是双向的——tracer 握手后发 `'H'` 帧声明可热加并注册进连接表。`POST /hook` 若 `restart:false` 且目标进程在跑，守护进程向其下发 `'R'`(reload) 控制帧（payload=合并后的新配置），tracer 按 id 去重增量装新 target（只加不删）。响应含 `hot_injected`=热注入到的进程数。**native 层不发 `'H'`，不响应 `'R'`，故 native 目标仍需 `restart`。**配合 `mode:"append"` 可迭代追加 hook 而全程不 force-stop。
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
        "args": [                // 要抓的参数（arm64 x0..x7）
          {"index": 0, "type": "int"},
          {"index": 1, "type": "string", "max": 256},        // char*，读到 NUL，最长 max
          {"index": 2, "type": "bytes", "len_from": 3},      // 指针+长度，长度取自第 3 个参数
          {"index": 2, "type": "bytes", "len": 16},          // 指针+固定长度
          {"index": 4, "type": "ptr"}                        // 原始指针值（hex）
        ],
        "ret": {"capture": true, "type": "int"},             // 抓返回值 + 类型（int|ptr|string|bytes）
        "backtrace": false                                    // 是否抓调用栈（返回原始 PC 列表）
      },
      "action": {
        "type": "observe",       // observe（只读） | replace_ret（篡改返回值） | replace_arg（篡改参数）
        "ret_value": 0,          // type=replace_ret：新的返回值（整型/指针）
        "arg_overrides": [       // type=replace_arg：进入原函数前覆盖这些寄存器
          {"index": 0, "value": 1}
        ]
      }
    }
  ]
}
```

**类型取值**：`int`（有符号 64 位）、`ptr`（指针，hex 输出）、`string`（C 字符串）、`bytes`（原始字节，hex 输出，需 `len` 或 `len_from`）。

**响应**：`{"ok":true,"package":"...","installed":[{"id":"enc1"}],"note":"..."}`
（note 会提示“配置已写入，注入在目标下次启动时生效”或“已 force-stop 触发重启”。）

## 移除：`POST /unhook`
```jsonc
{"package": "com.target.app"}          // 移除该包全部 hook（删除配置文件）
{"package": "com.target.app", "id": "enc1"}   // 只移除某个 hook 点
```

## 查询：`GET /hooks`
返回当前已下发的 hook 配置（读 `/data/adb/reconbridge/hooks/*.json`）：
```jsonc
{"count":1,"hooks":[{"package":"com.target.app","targets":[...],"active_processes":[12300]}]}
```

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
