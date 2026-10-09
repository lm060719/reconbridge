# 诊断、事件完整性与 JNI 映射

PC 新增 `diagnose_target`、`event_stream_status`、`capture_event_window`、
`configure_jni_capture`、`inspect_jni_bindings`。手机 MCP 提供其中的事件状态和两个 JNI 工具；
诊断汇总与调查会话落盘由 PC 提供。完整工具清单见 [TOOL_CATALOG.md](TOOL_CATALOG.md)。

## 统一诊断

```python
diagnose_target("com.example.app")
```

检查本地工具、daemon 连通性/版本/能力、目标与 Tracer 的安装信息、期望 Hook、
各进程实际 Java Hook/pending 类、native Hook 安装/JNI observer 状态及事件缓冲能力。
某项失败仍返回已取得的检查结果，不安装 Hook、不重启 App；连接使用现有 adb/wifi 初始化流程。
`ok` 只有在所有检查项均正常时才为 true；`warning/unknown` 应查看具体检查项。

没有在线 Runtime **不能直接证明 LSPosed 作用域没勾选**：进程未启动、还没有 Hook 配置、
Tracer 未启用也可能造成同样现象。安装版本与进程里正在运行的 Tracer 版本分别报告；
旧 Tracer 未报告 `tracer_version` 时返回 null。

### Native Hook 安装状态

`runtime_hook_status(package)` 的 native `runtime` 回报 `native_status_version: 1`，
包含 `engine`、`configuration`、`hooks`、`jni_observers` 与递增 `revision`。
每条 Hook 记录配置中的 `config_index`、`id`、库名及符号/偏移。

| 状态 | 含义 |
|---|---|
| `pending` | 等待库/符号可解析；有 ShadowHook 任务句柄不代表已经安装 |
| `installing` | 引擎安装调用正在执行 |
| `installed` | 引擎已确认安装成功 |
| `failed` | 安装或延迟回调注册失败，`detail` 提供错误码和原因 |
| `timeout` | x86_64 轮询 200 次仍未找到库/符号；重试间隔 150ms |
| `rejected` | 无效配置或超出 64 个 native slot；包括不支持的采集类型 |

arm64 符号使用 ShadowHook 完成回调更新状态，offset 使用库加载回调；旧引擎若缺少符号完成回调，
延迟安装只能保持 pending，并标记 `completion_callback: false`。arm64 不设与 x86_64 相同的轮询期限。
引擎加载/初始化失败也通过 IPC 保留报告，进程退出后连接记录随之移除。

`diagnose_target` 对比期望 native ID 与成功安装 ID，报告缺失、等待、失败和引擎错误。
旧模块缺少状态协议时不推断为健康。`installed` 仅表示本次进程中的安装结果；
尚未跟踪库卸载，也未实现 native 实时增删替换。修改配置仍需重启目标进程。

## 事件完整性

更新 daemon 后，每条 SSE/WS/recent 事件具有 daemon 分配的 `seq` 和 `stream_id`。
序号在同一 daemon 内递增，重启会改变 stream_id。业务内容相同的两次命中不会再因内容相同而被去重。
`/recent` 在同一锁内取得事件与游标，避免游标越过尚未返回的事件。

```python
start = event_stream_status()
# 触发一次目标行为
recent_events(limit=400, since_seq=start["latest_seq"], stream_id=start["stream_id"])
event_stream_status(since_seq=start["latest_seq"], stream_id=start["stream_id"])
```

| 字段 | 含义 |
|---|---|
| `earliest_seq/latest_seq` | 当前保留范围与最新游标 |
| `overwritten_total` | daemon 启动后被环形缓冲覆盖的累计条数 |
| `lost_before_cursor` | 请求游标之后、当前缓冲之前已经丢失的条数 |
| `limit_truncated` | 本次请求 limit 太小，较早的可用事件未返回 |
| `cursor_reset` | stream_id 不同或游标超前，不能继续原区间 |
| `subscriber_dropped_total` | SSE/WS 订阅队列满时的累计丢弃次数；断开订阅后保留计数 |
| `subscribers` | 当前订阅者队列长度、容量与各自丢弃数 |
| `truncated` | 此查询存在重启、缓冲丢失或返回条数截断 |

`limit=0` 只读游标，不因不返回事件而设置 limit_truncated；丢失/重启仍会报告。
没有起始游标（since_seq=0）时，丢失统计从本次 daemon 启动计算，不是“刚刚丢失”。
订阅丢弃按投递次数统计：两个订阅者漏了同一事件会计两次。

完整性范围是 **daemon 已收到的事件**，不包含 Hook 到 daemon 之前的丢失，
因此 `upstream_loss` 始终为 `unknown`，不能将它解读为业务执行路径完全覆盖。
旧 daemon 返回 `integrity.supported=false`、`complete=null`；不会伪装成完整数据。

### 调查会话落盘

```python
capture_event_window(session_id, seconds=15, max_events=10000)
```

使用 `/recent` 轮询，将目标包和其子进程的事件写入 `.investigations/<session_id>.events/` 下的
JSONL，旁边的 JSON 保存起止游标、完整性和错误。全局游标在包过滤前推进。
最长 60 秒，最多 100000 条；遇到缓冲丢失、重启、连接异常或条数截断会停止并保留已收集数据。
没有主动安装 Hook或触发操作。高频场景仍可能超过缓冲吞吐，必须检查结果的 `complete/issues`。

动作示范采集也会保存 stream_id 并检查完整性。来自旧 daemon 的完整性无法确认，或区间发生丢失/重启，
示范会标为 truncated，不能用于可执行计划；取消采集仍可正常清理。

## JNI 注册映射

```python
configure_jni_capture("com.example.app")
# 重启并打开目标 App，触发 native 库加载
inspect_jni_bindings("com.example.app", class_filter="Native", limit=500)
# 结束：移除期望配置，然后退出/重启目标进程
configure_jni_capture("com.example.app", enable=False)
```

必须更新 **daemon 和 Zygisk 模块**。配置按 `__rb_jni` 这个固定 id 追加，不覆盖已有 Hook。
默认不重启；启用时传 `restart=True` 会 force-stop 目标，之后需要重新打开 App。
native observer 不支持 live unhook；关闭只移除下次启动的配置，当前进程里的 observer 持续到进程退出。
`configured=true` 不代表安装成功，应查看查询结果的 `runtime_status.processes[].runtime.jni_observers`。

每条记录包含 Java 类名、方法名、JNI 签名、函数地址、模块路径、模块基址、相对偏移、PID/TID、
进程实例与时间。原 RegisterNatives 先执行，仅成功返回且无待处理异常时记录，不修改注册参数或结果。
Java 与 runtime targets 会被 native 执行器跳过，不再占 native Hook 槽位。

覆盖边界：

- 只观察安装之后、当前 JNI 函数表所指实现收到的 `RegisterNatives`；不补回之前的注册，也不枚举静态 `Java_*` 绑定。
- 查询结果是**注册历史**，不是当前 VM 的完整绑定表。没有跟踪 UnregisterNatives、类卸载或库卸载；地址可能失效。
- 同名类可能来自不同 ClassLoader，不能仅用类名+签名推断它们是同一绑定。
- 独立缓存保留最近 4096 条注册记录，不受普通 Hook 事件挤占。缓存统计为全局；查询另报告本次过滤后的截断。
- 单次注册最多采集 1024 个方法，超出时 `registration_truncated=true`；上游未观测的丢失仍未知。

本功能需真机验证与目标 Android/Hook 引擎的运行时兼容性；编译成功不等于所有 ROM 上均能安装 observer。

## 开发验证

```powershell
cd pc
.\.venv\Scripts\python.exe -m pytest -q --ignore=test_mobile_mcp_e2e.py
```

`tests/event_stream_test.cpp` 验证实际 C++ 缓冲实现的并发、丢弃、截断和重启语义，CI 中用 g++ 执行。
`build.ps1` 编译 arm64/x86_64 daemon 与 Zygisk。Tracer 版本回报由 `:app:testDebugUnitTest :app:assembleDebug` 验证构建。
