# ReconBridge M5 —— Java 动态 trace 协议

把 M3 的「PC 数据驱动 hook + 实时回传」从 native 扩展到 **Java 方法**。执行器是一个通用
LSPosed 模块 **ReconBridge Tracer**（`m5/tracer/`，包名 `com.reconbridge.tracer`），它跑在目标
App 进程里，通过抽象 socket `@reconbridge_inject` 直连守护进程 —— **与 M3 native 执行器共用同一条
链路和事件流**（`/hook` 写配置、SSE `/events`、WS、PC `collect_events` 全部不变）。

## 前置条件

1. 设备已刷 ReconBridge 模块（M1–M4，含守护进程 + sepolicy）。
2. 安装 `ReconBridge Tracer` APK（`m5/tracer/app/build/outputs/apk/debug/app-debug.apk`）。
3. 在 **LSPosed 管理器**里启用该模块，并把要侦察的目标 App 勾进**作用域**。
4. 目标进程启动时读配置，故对**已运行**的目标需 `restart:true`（守护进程 `am force-stop` 触发重载）。

## 下发：`POST /hook`（复用 M3 端点，target 加 `kind:"java"`）

```jsonc
{
  "package": "com.miui.voiceassist",
  "restart": true,
  "debug": false,                     // 可选：true 时模块逐命中打 logcat（HIT/sendEvent）；默认安静
  "targets": [
    {
      "kind": "java",                 // 关键：走 M5 Java 执行器（缺省 native 走 M3）
      "id": "sendStream",             // 事件里带上；缺省服务端补
      "class": "r70.a",               // 目标类全名（含混淆名；或留空/正则）
      "method": "sendStreamData",     // 方法名；"<init>" 表示构造函数
      "using_strings": ["sendStream"],// 新增：按字符串特征自动搜索 DEX 定位混淆类与方法（可配合 class_name_match / method_name_match 过滤）
      "params": ["java.lang.String","java.lang.String"],  // 可选：精确重载；省略=hook 所有同名重载
      "capture": {
        "this": "class",              // this 渲染：class（类名）| tostring | none
        "when": "after",              // before | after | both | none（none=只篡改不出事件）
        "args": [                     // 逐参数抓取；省略且 all_args=true 时抓全部参数
          {"index": 0, "render": "tostring", "max": 256},
          {"index": 1, "render": "tostring", "max": 2000}
        ],
        "all_args": false,            // true=按 tostring 抓全部参数（懒人模式）
        "ret": {"capture": true, "render": "tostring", "max": 1024},
        "fields": [                   // 反射读（私有）字段：复刻手写 Xposed 里 getDeclaredField 的做法
          {"target": "this", "name": "Z3", "render": "tostring"}
        ],
        "paths": [                    // 嵌套字段路径捕获（直接拿深埋在 payload 里的值）
          {"path": "args[1].payload.load_url", "render": "tostring", "max": 2000}
        ],
        "stack": false                // 抓 Java 调用栈（前 24 帧）
      },
      "action": {                     // 可选：实时篡改与动作流水线（Action Pipeline）
        "condition": {                // 缺口 2：条件执行 (Conditional Execution)
          "path": "ret.body.type", "op": "eq", "value": "revokemsg"   // 或 "script": "$ret != null"
        },
        "mutate_return": [            // 缺口 1 & 3：返回值字段级篡改与 Path 访问 (Return Value Mutation)
          { "path": "body.type", "value": "normal" },
          { "path": "headers['x-status']", "value": "ok" }
        ],
        "replace_args": [             // 进入原方法前覆盖参数（标量快捷语法）
          {"index": 1, "value": "被换掉的内容 ${args[0]}", "type": "string"} // 缺口 5：模板变量 ${...}
        ],
        "replace_return": {"value": 0, "type": "int"},  // 覆盖整个返回值
        "skip_original": false,       // true=不执行原方法，直接返回 replace_return（没给则 null）
        
        // --- 扩展：缺口 4 副作用调用 (Side Effect Actions) 与自定义 Callback 流水线 ---
        "before_actions": [           // 进入原方法前按顺序执行动作列表
          { "action": "set_field", "target": "this", "field": "debugMode", "value": true },
          { "action": "call_method", "target": "this", "method": "setToken", "args": [{"value": "new_tok"}] },
          { "action": "construct", "class": "com.foo.UserConfig", "args": [{"value": "admin"}], "save_to": "$v1" },
          { "action": "eval_js", "script": "var t = $args[0]; $thisObject.update(t); t + '_js';", "save_to": "$v2" },
          { "action": "exec_shell", "cmd": "id", "as_root": false, "save_to": "$sh" },
          { "action": "eval_dex", "dex_b64": "<base64_dex>", "class": "com.foo.Plugin", "method": "run", "save_to": "$res" }
        ],
        "after_actions": [            // 原方法完成后执行动作列表（缺口 3：可读写 ret 路径）
          { "condition": { "path": "ret.code", "op": "neq", "value": 200 },
            "action": "call_method", "target": "class:com.foo.Logger", "method": "log", "args": [{"value": "Status: ${ret.code}, user: ${args[0]}"}] }
        ]
      }
    }
  ]
}
```

**篡改与 Action 流水线扩展（Action Pipeline）**：
- **缺口 1：返回值字段级篡改（Return Value Mutation）**：通过 `mutate_return` / `mutate_fields` 或 step `"action": "mutate"`，按路径（如 `ret.body.type` 或 `ret['key']` 或 `args[0].name`）修改返回值对象内部的某个字段/Map key/List 索引，而不是整体替换。
- **缺口 2：条件执行（Conditional Execution）**：Action 或 Step 级可包含 `condition` 检查。支持 `op`：`eq`, `neq`, `contains`, `matches` (正则), `gt`, `gte`, `lt`, `lte`, `is_null`, `not_null`，或通过 Rhino JS 执行 `"script": "$ret != null && $ret.code == 200"`。条件不满足时自动跳过当前 action / step。
- **缺口 3：After 阶段访问返回值路径（Path-based Return Access）**：在 after 阶段，`ret` / `result` 以及嵌套路径表达式（`ret.body.type` / `ret['key']`）作为完整上下文开放给 `condition`、`mutate`、`call_method` 与模板变量，并跨 before/after 共享寄存器 `$v1`。
- **缺口 4：副作用调用（Side Effect Actions）**：
  - **`call_method` / `invoke`**：调用任意 Java 静态方法或实例方法。`target` 可为 `"this"`、`"args[N]"`、`"ret.xxx"`、`"class:包名.类名"` 或寄存器 `"$v1"`。`save_to` 保存返回值。
  - **`set_field`**：修改 `this`、参数或静态类的私有/公有字段。
  - **`construct` / `new_instance`**：实例化 Java 复杂对象，保存至寄存器。
  - **`exec_shell`**：在目标 App 进程空间内执行 Shell 命令（支持 `as_root: true`），保存输出。
  - **`eval_js`**：嵌入 Rhino JS 引擎执行 JavaScript 代码。自动注入环境变量 `$this`, `$args`, `$ret`, `$ctx`, `$regs`。
  - **`eval_dex`**：动态加载 Base64/本地 DEX 文件并执行指定类的方法。
- **缺口 5：模板化参数引用（Template Variables）**：在 action 参数或 value 中使用 `${args[0]}`、`${ret.body.type}`、`${$v1}` 等模板语法，运行时自动解析并填入对应数据。单一 `${expr}` 保持原始 Java 对象类型，复合文本 `"user_${args[0]}"` 自动插值。

**render 取值**：`tostring`（数值/布尔原样，其余 `String.valueOf` 截断到 `max`）、`class`（对象类名）、
`json`（原样字符串，交 PC 侧解析——适合参数本身就是 JSON 文本的场景，如 `sendStreamData` 的 content）、
`deep`（反射把对象图**深度序列化**成 JSON，带深度=5 / 环检测 / 节点预算=2000 三重防爆；
容器 Map/Collection/数组展开，`java./android./kotlin.` 等系统类只 `toString` 不下钻，普通对象枚举含私有字段）。

**`paths`（嵌套字段路径捕获）**：不靠整对象 `toString()` 撞运气，直接按路径把深埋在 payload 对象里的值取出来。
每条 `{path, render?, max?}`，路径语法：
- 起头：`args[N]`（第 N 个参数）/ `this` / `ret`（仅 after 阶段有值）/ 裸字段名（=`this.<name>`）。
- 逐段 `.name`：依次尝试 **反射字段**（含私有、跨父类）→ **getter**（`getName`/`name`/`isName`）→ **Map key**。
- `[n]`：索引数组 / `List`。
- 例：`args[1].payload.load_url`、`this.mState.items[0].title`、`ret.body`。
- 解析不到的段：该条返回 `{"path":…, "value":null, "unresolved":true}`（与“字段本就是 null”区分）。
每条 `path` 的值再按其 `render`（可为 `deep`）渲染。事件里以 `"paths":[{path,render,value,...}]` 回传。

`params` 里的类型名：Java 全名（`java.lang.String`、`android.os.Bundle`），基本类型用 `int/long/boolean/…`。

## 事件流：`GET /events`(SSE) / WS（复用 M3）

每次命中一条 JSON（沿用 M3 事件形态 + java 扩展字段）：

```jsonc
{
  "ts": 1731000000123,
  "package": "com.miui.voiceassist",
  "hook_id": "sendStream",
  "kind": "java",
  "pid": 12300, "tid": 12345,
  "phase": "after",                    // 本条是 before 还是 after
  "class": "r70.a", "method": "sendStreamData",
  "this": "r70.a",                     // 按 capture.this 渲染
  "args": [
    {"index": 0, "render": "tostring", "value": "instruction"},
    {"index": 1, "render": "tostring", "value": "{\"header\":{\"name\":\"ToastStream\"}...}"}
  ],
  "ret": "…",                          // 若 capture.ret.capture
  "fields": [{"target": "this", "name": "Z3", "value": "true"}],
  "paths": [{"path": "args[1].payload.load_url", "render": "tostring", "value": "https://…"}],
  "stack": ["…"]                       // 若 capture.stack
}
```

## PC 便捷工具：`trace_java`（MCP）

```
trace_java(package, class_name, method,
           params=None, capture_args=None, fields=None, paths=None,
           this="class", ret=True, when="after", stack=False,
           args_render="tostring", restart=True, seconds=12, max_events=200,
           until_first_hit=False, until_n_events=0, fold_stack=True,
           include_recent=False, since_seq=0, hot=False)
```
`hot=True`：免重启热加——目标进程在跑时直接增量追加这个 hook（不 force-stop）。
一步：拼 java target → `POST /hook` → `collect_sse` 采集并返回命中。等价于「hook 一个 Java 方法看它跑」。
底层就是上面的 `/hook` + `/events`，也可以直接用 `post_hook` + `collect_events` 手工组合。

**实时篡改：`patch_java`（M5 v2）**
```
patch_java(package, class_name, method,
           replace_args=[{"index":1,"value":"...","type":"string"}],
           replace_return={"value":true,"type":"boolean"}, skip_original=False,
           trace=True, params=None, when="after", debug=False, restart=True, seconds=0)
```
下发一条带 `action` 的 java target（篡改**持久生效**直到 `unhook`）。`seconds>0` 时顺便采集命中。
常见用法：换某 String 参数、让校验方法恒返回 true（`replace_return` + `skip_original`）、拦掉某调用。

## 实时配置同步 / 移除

M5 Tracer 现在使用进程内 `HookRegistry` 保存每个 target id 对应的 LSPosed `Unhook` handle。
daemon 下发的配置被视为“完整期望状态”，运行中收到新配置后会执行 reconcile：

- 新 id → live install；
- 同 id 且配置未变 → 保持；
- 同 id 但配置改变 → **先装新 Hook，成功后再卸载旧 Hook**，避免 replace 失败导致已有能力消失；
- 配置中消失的 id → 立即调用 `Unhook.unhook()`；
- `targets:[]` → 清空当前进程全部 M5 Java Hook。

因此 `POST /unhook` 对运行中的 M5 Tracer 已经是 **live unhook**：

```json
{"package":"com.miui.voiceassist"}
{"package":"com.miui.voiceassist","id":"sendStream"}
```

无需再 force-stop 才能恢复。若目标进程未运行，则只更新磁盘期望配置，下次启动自然不会再安装。

> **Phase 6 之后的边界**：普通 `POST /unhook` / MCP `unhook` 只管理手工 Hook。已启用 Runtime Program 的物化 targets 会自动重新加入最终期望配置；要停 Program 必须调用 `runtime_program_disable`。直接尝试 unhook `rp:<program>:<target>` 会返回冲突提示。

查询分两层：

- `GET /hooks` / MCP `list_hooks`：磁盘上的**期望配置**；
- `GET /runtime_status?package=...` / MCP `runtime_hook_status`：运行中 Tracer 的**完整 M5 Runtime 状态**，包含 HookRegistry / ClassLoader、Runtime State / Event Bus，以及 Context / Lifecycle Runtime。

## 远程 Runtime Command（Runtime Phase 5）

Phase 5 复用现有 `@reconbridge_inject` 双向 socket，不再通过“临时 Hook”间接操作 Runtime：

```text
Tracer -> K                 # 声明支持 Runtime Command
daemon -> C + JSON          # 下发命令，带 request_id
Tracer -> A + JSON          # Ack，带同一个 request_id
```

daemon 暴露 `POST /runtime_command`，PC / 手机 MCP 提供对应高层工具：

- `runtime_state_get`
- `runtime_state_set`
- `runtime_state_remove`
- `runtime_state_increment`
- `runtime_state_append`
- `runtime_state_clear`
- `runtime_event_emit`
- `runtime_context_status`
- `runtime_activity_action`

示例：

```text
runtime_state_set("com.target.app", key="debug", value=true)
runtime_state_increment("com.target.app", key="hits", delta=1)
runtime_state_append("com.target.app", key="history", value={"page":"vip"})
runtime_state_remove("com.target.app", key="debug")

runtime_event_emit(
    "com.target.app",
    name="debug.toggle",
    payload={"enabled": true}
)

runtime_context_status("com.target.app")

runtime_activity_action(
    "com.target.app",
    actions=[
        {"action":"call_method","target":"activity","method":"finish"}
    ]
)
```

State 的远程 scope 支持 `process/package/hook`。远程命令**不支持 thread scope**：socket command 线程的 ThreadLocal 不能代表真实 Hook 业务线程。hook scope 必须传 `hook_id`。

多进程 App 未指定 `process` 时，daemon 会把命令并行发给该包所有在线且声明 `K` 能力的 Tracer，并返回 `results[]`；需要只操作主进程或 `:service` 时显式传完整 process name。

`activity_action` 直接复用现有 Action Pipeline；若当前有真实 Android Activity，会把动作调度到主线程并等待 Ack。没有当前 Activity 时明确失败，不会偷偷回退 application context。HTTP `timeout_ms` 会被限制在 200–10000ms。

Runtime Command 不修改 `hooks/<pkg>.json`，也不创建临时 Hook，因此适合交互式调试、状态开关、远程触发 Event Bus 和当前 Activity 操作。Tracer 每次命令后会重新发布 runtime status，便于 `runtime_hook_status` 看到最新 State/Event/Context 状态。

## Runtime Program / Module Manifest（Runtime Phase 6）

Phase 6 把一组 Java/Runtime targets、State 初始化和模块元数据打包成一个**命名 Runtime Program**。Program 持久化在设备端 daemon：

```text
/data/adb/reconbridge/runtime_programs/<package>/<program_id>.json
```

manifest 示例：

```jsonc
{
  "id": "vip_debug",
  "name": "VIP 调试模块",
  "version": "1.0.0",
  "description": "把会员状态和页面行为组合成一个可启停 Runtime Program",

  "targets": [
    {
      "id": "vip_source",
      "kind": "java",
      "class": "com.target.UserRepo",
      "method": "refreshVip",
      "capture": {"when": "none"},
      "action": {
        "after_actions": [
          {
            "action": "emit_event",
            "name": "vip.changed",
            "payload": {"vip": "${ret}"}
          }
        ]
      }
    },
    {
      "id": "vip_listener",
      "kind": "runtime",
      "on_event": {
        "name": "vip.changed",
        "actions": [
          {
            "action": "set_state",
            "scope": "process",
            "key": "last_vip",
            "value": "${event.vip}"
          }
        ]
      }
    }
  ],

  "state_init": [
    {
      "scope": "process",
      "key": "vip_program_enabled",
      "value": true
    }
  ],

  "state_cleanup": [
    {
      "scope": "process",
      "key": "vip_program_enabled"
    }
  ]
}
```

对应 MCP：

```text
runtime_program_install(package, manifest)
runtime_program_replace(package, manifest, expected_revision=...)
runtime_program_enable(package, program_id)
runtime_program_disable(package, program_id)
runtime_program_rollback(package, program_id)
runtime_program_status(package, program_id="")
```

### Target 命名空间

manifest 内的 target id 是 Program 局部 id。daemon 物化到 HookRegistry 时自动改成：

```text
rp:<program_id>:<local_target_id>
```

例如：

```text
vip_source
→ rp:vip_debug:vip_source
```

因此不同 Program 都可以拥有 `id:"listener"`，不会互相覆盖。物化 target 还带 `__reconbridge_program / __reconbridge_local_id / __reconbridge_program_revision` 元数据，便于状态与排错。

普通 `post_hook/unhook` 只管理手工 Hook；已启用 Program targets 会在最终期望配置中自动重新加入。直接对 `rp:<program>:<target>` 调 `unhook` 会被拒绝，应该使用 `runtime_program_disable` 或 `runtime_program_replace`。

### state_init / state_cleanup

Phase 6 的 Program State 声明目前支持 `process/package` scope。

`state_init` 有两层保证：

1. Program install/enable/replace/rollback 后，如果目标 Runtime 在线，daemon 立即通过 Phase 5 Runtime Command 执行 `state_set`；
2. daemon 还会自动生成一个 Program 私有 bootstrap target，在未来进程启动时监听 `lifecycle.application_attached` 再执行同一批初始化。

因此 `state_init` 不会只在安装当下有效。对应 bootstrap id：

```text
rp:<program_id>:__bootstrap
```

`state_cleanup` 在 disable/replace/rollback 时对在线 Runtime 执行 `state_remove`。进程未在线时不会报 Program 安装失败；持久化 manifest 和未来启动 bootstrap 仍然有效。

### revision / replace / rollback

每个 Program 有单调递增的 `revision`。同 id 更新使用 `runtime_program_replace`，旧 manifest 会进入最多 **5 层**历史。

```text
revision 1   install v1
revision 2   replace v2
revision 3   replace v3
revision 4   rollback → 恢复 v2 manifest
```

rollback 会消费最近一层历史，但 revision 继续递增，不会倒退。这样 PC/手机两端可以用 `expected_revision` 做乐观并发检查，避免覆盖另一端刚写入的 Program。

`runtime_program_status` 会返回：
- 当前 revision / enabled；
- name / version / description；
- target/state_init/state_cleanup 数量；
- history_depth；
- effective_target_ids；
- 原始 manifest。

Program disable 只移除该 Program 的物化 targets，并保留 manifest/history，所以之后可以无重装再次 enable。

## Runtime State + Event Bus（Runtime Phase 3）

Phase 3 让不同 Hook 不再彼此独立。每个目标 App **进程**拥有一份 `RuntimeStateStore` 和 `RuntimeEventBus`，Java Hook、动态 ClassLoader 后补装 Hook、以及纯事件 target 都共享它们。

### Runtime State

State 支持四种作用域：

| scope | 生命周期 / 语义 |
|---|---|
| `process` | 当前 Android 进程长期共享；所有 Hook 可读写 |
| `package` | 当前实现同样是**进程内**包级状态；多进程 App 不会自动跨进程同步 |
| `hook` | 按 target `id` 隔离；真正 remove/unhook 时自动清理；同 ID live replace 会保留 |
| `thread` | `ThreadLocal`；只在当前线程可见，不在 runtime status 中枚举具体线程值 |

Action Pipeline 新增：

```jsonc
{
  "before_actions": [
    {
      "action": "set_state",
      "scope": "process",
      "key": "current_user",
      "value": "${args[0]}"
    },
    {
      "action": "get_state",
      "scope": "process",
      "key": "current_user",
      "save_to": "$user"
    },
    {
      "action": "increment_state",
      "scope": "hook",
      "key": "hits",
      "delta": 1,
      "save_to": "$count"
    },
    {
      "action": "append_state",
      "scope": "package",
      "key": "recent_users",
      "value": "${args[0]}"
    },
    {
      "action": "remove_state",
      "scope": "process",
      "key": "old_key"
    },
    {
      "action": "clear_state",
      "scope": "thread"
    }
  ]
}
```

`increment_state` 和 `append_state` 在单个 scope map 内原子执行；多个 Hook 线程同时命中不会因为简单的 get→set 竞争而丢计数。

默认容量保护：

- 每个长期 scope 最多 **256 keys**，按 LRU 淘汰；
- 最多 **128 个 hook scope**；
- `append_state` 每个列表最多 **128 项**，超出从最旧元素开始移除；
- State 可以保存真实 Java 对象引用，因此对象会一直存活到被覆盖、删除、LRU 淘汰或进程结束。需要长期保存大对象时应主动控制数量。

现有统一表达式系统直接支持：

```text
state.process.current_user
state.package.vip_enabled
state.hook.hits
state.thread.request_id
```

所以可以用于：

```jsonc
{
  "condition": {
    "path": "state.process.vip_enabled",
    "op": "eq",
    "value": true
  }
}
```

以及模板：

```jsonc
{
  "action": "call_method",
  "target": "class:com.foo.Logger",
  "method": "log",
  "args": [
    {"value": "user=${state.process.current_user}, hits=${state.hook.hits}"}
  ]
}
```

`mutate/set_path` 也可直接写 `state.*` 路径。

Rhino JS 中额外注入：

```javascript
$state.process
$state.package
$state.hook
$state.thread
$stateStore
$event
```

其中 `$state` 是当前 Hook 的状态视图；`$stateStore` 是底层 Store 对象。

### Event Bus：Hook → Event → Action

Java Hook 可以在 before/after Action Pipeline 中发事件：

```jsonc
{
  "action": "emit_event",
  "name": "vip_changed",
  "payload": {
    "vip": "${ret}",
    "user": "${state.process.current_user}"
  },
  "save_to": "$listener_count"
}
```

payload 会递归解析模板、path/value 对象和数组，不是只做字符串替换。

事件监听有两种配置方式。

**1. 纯 Runtime target** —— 不依赖某个 Java 方法，只负责监听事件：

```jsonc
{
  "kind": "runtime",
  "id": "vip_state_listener",
  "on_event": [
    {
      "name": "vip_changed",
      "condition": {
        "path": "event.vip",
        "op": "eq",
        "value": true
      },
      "actions": [
        {
          "action": "set_state",
          "scope": "process",
          "key": "vip_enabled",
          "value": "${event.vip}"
        },
        {
          "action": "increment_state",
          "scope": "process",
          "key": "vip_change_count"
        }
      ]
    }
  ]
}
```

**2. Java target 自带监听器**：

```jsonc
{
  "kind": "java",
  "id": "user_runtime",
  "class": "com.foo.UserManager",
  "method": "refresh",
  "action": {
    "after_actions": [
      {
        "action": "emit_event",
        "name": "user_refreshed",
        "payload": {"user": "${args[0]}"}
      }
    ]
  },
  "on_event": {
    "name": "vip_changed",
    "actions": [
      {
        "action": "call_method",
        "target": "class:com.foo.Logger",
        "method": "log",
        "args": [{"value": "vip=${event.vip}"}]
      }
    ]
  }
}
```

`on_event` / `event_handlers` 可为单个对象或数组。

事件上下文支持：

```text
event.name
event.source_hook
event.ts
event.tid
event.payload.vip
event.vip
```

payload 字段同时平铺到 `event` 根节点，因此 `event.vip` 是 `event.payload.vip` 的快捷形式；内置元数据键不会被 payload 覆盖。

Event Bus 当前为**同步分发**：

```text
Hook A emit_event
    ↓ 同一线程
listener condition
    ↓
listener actions / state mutation
    ↓
返回 Hook A
```

因此 listener 对 Runtime State 的修改可以立刻影响当前线程后续逻辑。为了防止 `emit_event → listener → emit_event` 无限递归：

- 最大事件递归深度默认 **16**；
- 最大订阅 handler 数默认 **256**；
- 超过递归深度的事件会被丢弃并计入 `dropped_depth`；
- 单个 listener 异常只计入 `handler_errors`，不会阻断其它 listener。

事件订阅本身也是 `LiveHookHandle`，和 Java Hook 一样由 HookRegistry 管理。因此：

- 同 ID replace：新 listener 安装成功后再卸载旧 listener；
- `unhook(package, id)`：立即卸载 listener；
- 删除 target 后不会留下“幽灵监听器”；
- hook-scope State 在真正 remove 时同步清理；replace 同 ID 时保留。

纯事件 handler 的 ActionContext 没有方法调用上下文，因此 `this / args / ret` 不可用；应主要使用 `event.*`、`state.*`、静态 `class:...` 调用或自行 construct/eval_js/eval_dex。

## Lifecycle + Context Runtime（Runtime Phase 4）

Phase 4 把 Android 进程里的 `Application / Context / 当前 Activity / Activity 生命周期` 接入现有 ActionContext 和 Event Bus。

实现策略不是给每个 Activity 子类逐个挂 `onResume()` Hook，而是：

```text
Application.attach(Context)
        ↓
ContextRegistry 记录 Application / applicationContext
        ↓
Application.registerActivityLifecycleCallbacks(...)
        ↓
Activity created/started/resumed/paused/stopped/destroyed
        ↓
ContextRegistry 更新当前 Activity
        ↓
RuntimeEventBus.emit("lifecycle....")
```

当前 Activity 只通过 **WeakReference** 保存；Runtime 不会为了提供 `${activity}` 而阻止页面被回收。

### Action / 模板中的 Context 根对象

现有 path / template / condition / `call_method.target` 现在都可直接使用：

| 根路径 | 含义 |
|---|---|
| `application` / `${application}` | 当前进程 Application 对象 |
| `context` / `${context}` | 优先当前 Activity；没有 Activity 时退回 applicationContext / Application |
| `activity` / `${activity}` | 当前 Activity 弱引用；页面不存在时解析为 missing |
| `lifecycle.activity_class` | 当前 Activity 完整类名 |
| `lifecycle.activity_state` | created/started/resumed/paused/stopped/destroyed 等当前状态 |
| `lifecycle.has_activity` | 当前 Activity 是否仍可取到 |
| `lifecycle.last_event` | 最近一次 lifecycle 事件 |
| `lifecycle.last_event_at` | 最近事件时间戳 |
| `lifecycle.package / process` | 当前包名 / 进程名 |

例如：

```jsonc
{
  "condition": {
    "path": "lifecycle.activity_state",
    "op": "eq",
    "value": "resumed"
  },
  "before_actions": [
    {
      "action": "call_method",
      "target": "activity",
      "method": "getIntent",
      "save_to": "$intent"
    },
    {
      "action": "set_state",
      "scope": "process",
      "key": "screen",
      "value": "${lifecycle.activity_class}"
    }
  ]
}
```

Rhino JS 同步注入：

```text
$application
$context
$activity
$lifecycle
```

因此 JS、模板、condition 和 Action target 使用的是同一套 Runtime 对象。

### 标准 Lifecycle Event

LifecycleManager 会向现有 RuntimeEventBus 发出：

```text
lifecycle.application_attached
lifecycle.activity_created
lifecycle.activity_started
lifecycle.activity_resumed
lifecycle.activity_paused
lifecycle.activity_stopped
lifecycle.activity_save_instance_state
lifecycle.activity_destroyed
```

Activity 事件 payload 至少包含：

```text
event.activity
event.activity_class
event.context
event.application
event.state
event.package
```

因此也可以直接使用普通 `on_event`：

```jsonc
{
  "kind": "runtime",
  "id": "screen_listener",
  "on_event": {
    "name": "lifecycle.activity_resumed",
    "condition": {
      "path": "event.activity_class",
      "op": "contains",
      "value": "VipActivity"
    },
    "actions": [
      {
        "action": "set_state",
        "scope": "process",
        "key": "vip_page_visible",
        "value": true
      }
    ]
  }
}
```

### `on_lifecycle` 简写

Phase 4 额外提供 `on_lifecycle`，避免手写完整事件名：

```jsonc
{
  "kind": "runtime",
  "id": "vip_page_runtime",
  "on_lifecycle": [
    {
      "stage": "resumed",
      "activity": "VipActivity",
      "actions": [
        {
          "action": "set_state",
          "scope": "process",
          "key": "vip_page_visible",
          "value": true
        }
      ]
    },
    {
      "stage": "paused",
      "activity_match": ".*VipActivity$",
      "actions": [
        {
          "action": "set_state",
          "scope": "process",
          "key": "vip_page_visible",
          "value": false
        }
      ]
    }
  ]
}
```

`stage:"resumed"` 会标准化为 `lifecycle.activity_resumed`。也接受 `activity_resumed`、完整的 `lifecycle.activity_resumed` 或 `application_attached`。

Activity 过滤：
- `activity:"com.foo.VipActivity"`：完整类名；
- `activity:"VipActivity"`：简单类名；
- `activity_match:".*VipActivity$"`：正则。

`on_lifecycle` 最终仍然注册成 EventBus 的 LiveHookHandle，因此 target live remove / replace 时生命周期 listener 会和普通 `on_event` 一样立即卸载。

### Runtime Status

`runtime_hook_status(package)` 的每个进程状态现在除 HookRegistry / ClassLoader 信息外，还包含：

```jsonc
{
  "runtime_state": {
    "enabled": true,
    "max_keys_per_scope": 256,
    "max_hook_scopes": 128,
    "max_append_items": 128,
    "process": {"count": 2, "values": {"vip_enabled": true}},
    "package_scope": {"count": 0, "values": {}},
    "hooks": {
      "vip_hook": {
        "count": 1,
        "values": {"hits": 14}
      }
    },
    "thread_scope": {
      "thread_local": true,
      "enumerable": false
    },
    "operations": {
      "reads": 20,
      "writes": 18,
      "removes": 0,
      "clears": 0
    }
  },
  "event_bus": {
    "enabled": true,
    "synchronous": true,
    "handler_count": 1,
    "max_handlers": 256,
    "max_depth": 16,
    "emitted": 8,
    "delivered": 8,
    "dropped_depth": 0,
    "handler_errors": 0,
    "handlers": [
      {
        "owner_hook_id": "vip_state_listener",
        "event": "vip_changed"
      }
    ],
    "recent_events": ["vip_changed"]
  }
}
```

另外还会包含：

```jsonc
{
  "context_runtime": {
    "enabled": true,
    "application_available": true,
    "context_available": true,
    "activity_available": true,
    "activity_class": "com.foo.VipActivity",
    "activity_state": "resumed",
    "last_event": "activity_resumed",
    "activity_weak_reference": true
  },
  "lifecycle_runtime": {
    "enabled": true,
    "attach_hook_count": 1,
    "callbacks_registered": true,
    "registered_application_alive": true,
    "application_attach_events": 1,
    "lifecycle_events": 12,
    "event_prefix": "lifecycle."
  }
}
```

Lifecycle 变化后 Tracer 会主动重新发送 runtime status，因此 `runtime_hook_status(package)` 不需要等下一次 Hook 配置同步才能看到当前 Activity 状态。

runtime status 对任意非标量 Java 对象只返回有限摘要，不应把它当成对象 dump 接口；需要对象细节仍使用 `capture.fields / capture.paths / render:"deep"`。

Lifecycle 变化后的 runtime status 采用后台合并刷新（约 120ms 去抖），不会在 Activity 主线程同步写整份状态快照。Lifecycle Runtime 是**进程内**的；多进程 App 每个已连接进程各有自己的 Application/Activity 状态。Compose/Fragment/自绘视图不是独立 Activity 生命周期，若要判断其内部状态仍应 Hook 对应业务方法或自行 emit 自定义事件。

## Runtime Command Dispatcher（Runtime Phase 5）

Phase 5 在现有 `@reconbridge_inject` 双向 socket 上增加交互式 Runtime Command，不再需要为了“读一个 state / 发一个 event / 调当前 Activity”临时创建 Hook。

新增帧：

```text
Tracer → daemon  K  声明支持 Runtime Command
daemon → Tracer  C  Runtime Command JSON
Tracer → daemon  A  Command Ack JSON
```

`C/A` 使用 request_id 对应请求和响应；期间 `R` 热重载、`S` runtime status、`E` Hook 事件仍可正常穿插。daemon 对每个目标进程维护独立 waiter，超时或进程断线都会唤醒请求，不会永久挂起。

PC / 手机 MCP 提供：

```text
runtime_state_get
runtime_state_set
runtime_state_clear
runtime_event_emit
runtime_context_status
runtime_activity_action
```

### 直接操作 Runtime State

```text
runtime_state_set(
    package="com.foo",
    scope="process",
    key="debug_enabled",
    value=true
)

runtime_state_get(
    package="com.foo",
    scope="process",
    key="debug_enabled"
)

runtime_state_clear(
    package="com.foo",
    scope="hook",
    hook_id="vip_hook"
)
```

远程命令支持 `process / package / hook` scope。**不支持远程 thread scope**：ThreadLocal 属于命令 socket 的处理线程，读取它不能代表任意 Hook 实际运行的业务线程，因此 Runtime 会明确拒绝，而不是返回误导值。

`runtime_state_set.value` 支持 JSON 标量、对象、数组和 null；对象/数组进入 Runtime 后会变成普通 Map/List，可继续被现有模板和 path 系统读取。

### 从 PC 主动发 Event

```text
runtime_event_emit(
    package="com.foo",
    name="debug.toggle",
    payload={"enabled": true}
)
```

这个事件进入的就是 Phase 3 同一个 `RuntimeEventBus`，现有：

```jsonc
{
  "kind": "runtime",
  "id": "debug_listener",
  "on_event": {
    "name": "debug.toggle",
    "actions": [
      {
        "action": "set_state",
        "scope": "process",
        "key": "debug_enabled",
        "value": "${event.enabled}"
      }
    ]
  }
}
```

会在目标进程中同步响应。

### 直接读取 Context / Activity

```text
runtime_context_status(package="com.foo")
```

返回当前进程 ContextRegistry / Lifecycle 视图。它不会 dump Activity 对象本身，只返回有限状态摘要。

`runtime_activity_action` 可直接把现有 Action Pipeline 运行在当前 Activity：

```text
runtime_activity_action(
    package="com.foo",
    actions=[
      {
        "action": "call_method",
        "target": "activity",
        "method": "finish"
      }
    ]
)
```

也可以在 actions 中使用 `set_state / emit_event / call_method / set_field / eval_js` 等现有动作。没有当前 Activity 时会返回明确错误，不会静默退回 Application。真实 Android Activity 的 Action Pipeline 会自动切到主线程同步执行；主线程调度使用同一条 Runtime Command 的 `timeout_ms` 预算，避免 socket 线程直接操作 View/Activity。

### 多进程语义

所有 Runtime Command 都接受可选 `process`。不传时，daemon 会并行下发到该包所有**在线且声明 Runtime Command 能力**的 Tracer 进程，并返回：

```jsonc
{
  "targeted": 2,
  "succeeded": 2,
  "results": [
    {"process": "com.foo", "...": "..."},
    {"process": "com.foo:service", "...": "..."}
  ]
}
```

因此多进程 App 不会被偷偷折叠成一个状态。要只操作主进程或某个 `:service`，请明确传 `process`。

`runtime_hook_status` 的进程行也新增 `runtime_command:true/false`；旧版 Tracer 只会声明 live reconcile，不会被 daemon 误判成支持 Runtime Command。

## 动态 ClassLoader / Pending Hook（Runtime Phase 2）

显式指定 `"class":"com.foo.PluginEntry"` 的 Java target 在同步时会依次尝试当前已知 ClassLoader。若所有已知 loader 都抛出 `ClassNotFoundException / NoClassDefFoundError`，它不会计为安装失败，而是进入：

```text
state = pending_class
```

进程内现在有两层 ClassLoader 发现机制：

1. **BaseDexClassLoader 构造监听**：常驻但低频，用来发现常见的 `PathClassLoader` / `DexClassLoader` / `InMemoryDexClassLoader`。新 loader 一出现就立刻拿它重试所有 pending target，不需要等目标类被业务代码主动调用。
2. **ClassLoader.loadClass 监听**：仅当 `pending_count > 0` 时临时启用，并只对 pending 的精确类名触发安装回调。pending 清空后立即卸载 watcher，减少长期类加载开销。

Watcher 与 HookRegistry 都有线程递归保护；Registry 自己为了安装 target 调用 `loader.loadClass()` 时不会再次进入 pending 安装回调。

pending 与 live replace 可以组合：如果同一个 Hook ID 的旧版本已经 installed，而新版本把目标改成了尚未加载的插件类，则旧 Hook **继续保持生效**，新 spec 以 `replacing_installed:true` 等待；只有新类在某个 loader 上成功安装后，Registry 才卸载旧 Hook 并完成 replace。

`unhook(package, id)` / 全量 reconcile 删除 ID 时会同时删除对应 pending；不会出现“已经取消，但以后插件类出现又突然装回来”的情况。

ClassLoaderRegistry 对 loader 实例使用**弱引用**。运行时状态保存 loader id / 实现类 / first_seen / last_seen / last_loaded_class 等轻量元数据，但不会仅因为监控就永久阻止可卸载插件 ClassLoader 被 GC。

典型 `runtime_hook_status(package)` 片段：

```jsonc
{
  "installed_count": 1,
  "pending_count": 1,
  "pending_hook_supported": true,
  "dynamic_classloader_supported": true,
  "hooks": [
    {
      "id": "main_check",
      "state": "installed",
      "class_loader_id": "cl1",
      "class_loader_class": "dalvik.system.PathClassLoader"
    }
  ],
  "pending_hooks": [
    {
      "id": "plugin_check",
      "class": "com.foo.plugin.Checker",
      "state": "pending_class",
      "attempts": 2,
      "last_error": "java.lang.ClassNotFoundException: ...",
      "replacing_installed": false
    }
  ],
  "class_loader_count": 2,
  "class_loaders": [
    {
      "id": "cl1",
      "class": "dalvik.system.PathClassLoader",
      "source": "lpparam.classLoader",
      "alive": true
    }
  ],
  "class_loader_watch": {
    "base_dex_constructor_watch": true,
    "load_class_watch": true
  }
}
```

注意：
- 自动 pending 最可靠的是**显式 `class` target**。只有 `using_strings`、没有确定类名的搜索型 target 仍依赖当前能扫描到的 DEX，不能保证在未来插件 DEX 出现后自动重新做字符串搜索。
- 极少数完全绕过标准 `BaseDexClassLoader` / `ClassLoader.loadClass` 语义的自定义 native loader 仍可能观察不到。
- 首次让 Tracer 进入目标进程的限制仍然存在：如果目标进程启动时完全没有 M5 配置，Tracer 不会建立长期控制通道。第一次下发到一个已运行且从未连接过的进程，仍建议 `restart:true`。

## 语义与限制

- **trace（观测）+ 实时篡改（action）** 均支持。篡改在 Xposed before（改参数/skip）/after（改返回值）阶段生效。
- 类解析不再只限主 loader：HookRegistry 会先尝试所有已知 loader；找不到的显式类进入 pending，并由 BaseDexClassLoader / loadClass watcher 后续自动补装。
- 首个 hook 仍需目标进程先加载 Tracer；最稳妥的起手式仍是 `restart:true`。
- 进程已连接后，`restart:false` 会走实时 reconcile：daemon 用 `'R'` 下发**完整期望配置**，
  HookRegistry 自动 add/remove/replace。PC 侧 `trace_java(hot=True)` 继续可免重启追加；
  同 ID target 发生变化时会 live replace，`unhook` 会 live remove。
- tracer 通过 `'S'` 帧持续回报完整 M5 Runtime 状态；`runtime_hook_status` 可核对 installed/pending/ClassLoader、Runtime State/Event Bus，以及当前 Application/Context/Activity/Lifecycle。
- native M3 目标不发送 `'H'/'S'`，因此这些 live reconcile 能力目前只保证 M5 Java Hook。
- 复杂对象默认只 `toString()` + 类名；要看内部状态用 `fields`（点名反射某字段）、`paths`（按路径取深埋值）
  或 `render:"deep"`（整棵对象图序列化，有深度/环/节点预算防爆）。
- 篡改值类型要与目标 Java 签名匹配（显式 `type`）；类型不符会在命中时抛异常并打日志（不影响原方法）。
- 日志默认安静（只在装 hook / 出错时打）；配置 `debug:true` 才逐命中打 logcat。
- 需要 LSPosed；模块作用域需手动勾选目标 App（这正是给 LSPosed 模块开发者用的工具，环境本就具备）。
