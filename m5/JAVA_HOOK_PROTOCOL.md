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
      "class": "r70.a",               // 目标类全名（含混淆名）
      "method": "sendStreamData",     // 方法名；"<init>" 表示构造函数
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
      "action": {                     // 可选（M5 v2）：实时篡改。不给=纯观测
        "replace_args": [             // 进入原方法前覆盖参数
          {"index": 1, "value": "被换掉的内容", "type": "string"}
        ],
        "replace_return": {"value": 0, "type": "int"},  // 覆盖返回值
        "skip_original": false        // true=不执行原方法，直接返回 replace_return（没给则 null）
      }
    }
  ]
}
```

**篡改（action）取值**：`replace_args`/`replace_return` 的 `type` ∈ `string|int|long|boolean|double|float|short|byte|char`；
省略 `type` 则按 JSON 原生类型（务必与目标参数/返回的 Java 类型匹配，如 `long` 参数别只传 JSON 整数，要显式 `type:"long"`）。
命中事件里会多一个 `"tampered": true` 标记。想**静默篡改**（不产生事件）设 `capture.when = "none"`。

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

## 移除：`POST /unhook`（复用 M3）
`{"package":"com.miui.voiceassist"}` 删整包配置；带 `"id"` 只删某目标。模块下次进程启动即不再挂。

## 语义与限制

- **trace（观测）+ 实时篡改（action）** 均支持。篡改在 Xposed before（改参数/skip）/after（改返回值）阶段生效。
- 类解析用目标进程主 classloader（`lpparam.classLoader`）；动态加载进独立 classloader 的类暂不覆盖。
- 模块进程启动时读配置装 hook。**首个 hook 需 `restart:true`**（force-stop 让目标带配置起来）；
  此后目标进程活着时支持**免重启热加**（`restart:false` + `mode:"append"`）：daemon 向运行中的 tracer
  下发 `'R'`(reload) 控制帧，tracer 按 id 去重**增量装新 target（只加不删）**——迭代加 hook 不再反复 force-stop。
  PC 侧 `trace_java(hot=True)` 即走此路；`hot_injected` 返回热注入到的进程数（0=目标没在跑，退回 restart）。
  （注入 socket 因此变双向：tracer 握手后发 `'H'` 声明可热加；native 层不发 `'H'`，故 native 目标仍需 restart。）
- 复杂对象默认只 `toString()` + 类名；要看内部状态用 `fields`（点名反射某字段）、`paths`（按路径取深埋值）
  或 `render:"deep"`（整棵对象图序列化，有深度/环/节点预算防爆）。
- 篡改值类型要与目标 Java 签名匹配（显式 `type`）；类型不符会在命中时抛异常并打日志（不影响原方法）。
- 日志默认安静（只在装 hook / 出错时打）；配置 `debug:true` 才逐命中打 logcat。
- 需要 LSPosed；模块作用域需手动勾选目标 App（这正是给 LSPosed 模块开发者用的工具，环境本就具备）。
