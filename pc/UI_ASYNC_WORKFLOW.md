# UI、异步关联与离线报告

新增 8 个 PC MCP 工具，PC 总数 103，手机 MCP 仍为 49。UI 和 Perfetto 经 PC 的 adb
访问设备；即使 daemon 使用 Wi-Fi HTTP，仍需 adb 连接和正确的 serial。
报告导出与本地 APK 分析不需要设备。异步 Hook 需要目标进程实际加载 **Tracer 1.2.0**。

## UI 采集与回放

先用 `open_target(package_name="com.example.app", auto_pull=False)` 取得 `session_id`，打开目标页面后调用：

```python
capture_ui(session_id="<会话ID>", screenshot=True)
```

保存 XML、解析后的 JSON 和可选 PNG，返回证据目录、文件长度和 SHA-256。
JSON 中密码字段文本被遮蔽；原始 XML 和截图可能包含页面原始内容。
层级与截图分别采集，`atomic_snapshot=false`；目标包不在可见层级时记录失败。

```python
steps = [
    {"action": "tap", "selector": {"resource-id": "com.example.app:id/details"}},
    {"action": "assert", "selector": {"resource-id": "com.example.app:id/details_title"}}
]
replay_ui_steps(session_id="<会话ID>", steps=steps)  # 本地校验，不连接设备
replay_ui_steps(session_id="<会话ID>", steps=steps, execute=True)
```

`execute=True` 立即执行。每步重新采集层级，选择器必须在目标包内唯一匹配，tap 要求节点
可点击且启用。任一步失败立即停止，不自动重试；保存每步前后层级和回执。
可设置 `expected_hierarchy_sha256`，页面变化时不发送该步输入。检查与输入存在时间差，
不能保证期间窗口不变化。`assert` 只检查节点存在，不代表服务端业务成功。

支持 `tap`、`assert`、`text`、`key`（BACK/ENTER），最多 50 步。选择器为
`resource-id`、`text`、`content-desc`、`class` 的精确匹配。文本输入要求字段已经聚焦，
限 1–200 个可打印 ASCII 字符且不含 `%`，不自动清空原内容。回执区分
`input_attempted`、`input_sent`、`effect_unknown`，输入超时不会自动重试。

默认 `capture_events=True`：保存每步 daemon 游标及目标包事件窗口，最多 2000 条，
保留重启/覆盖/截断信息。daemon 不可用会记录错误，不阻止 UI 步骤。
窗口只说明事件发生在采集期间，不能证明点击造成调用；上游丢失未知，晚到的异步事件可能不在窗口内。
当前不包含任意手势录制、自动学习用户触摸、swipe、WebView DOM 或跨应用导航。
Java 业务动作学习见 [ACTION_LEARNING.md](ACTION_LEARNING.md)。

## 按任务对象关联异步调用

选择实际入队与执行方法，二者必须观察到**同一个对象实例**：

```python
configure_async_trace(
    package="com.example.app",
    enqueue={"class": "com.example.app.JobQueue", "method": "submit",
             "params": ["com.example.app.Job"], "task": "arg:0"},
    execute={"class": "com.example.app.Job", "method": "run",
             "params": [], "task": "this"},
    namespace="jobs")
```

示例类名须换成已定位的具体实现。省略 params 遵循现有 Java Hook 重载匹配规则。
工具 append 两个 Hook，不自动重启；用 `runtime_hook_status` 确认安装结果与运行时版本。
相同 namespace 使用固定 Hook ID，会更新这两个目标。完成后用 `unhook` 移除返回的 ID。

启用关联的调用附带进程 UUID、span ID、线程嵌套 parent 和 async 元数据。
入队使用弱引用记录身份，不包装任务、不改变调度。缓存最多 2048 项，保留 60 秒。
同对象同时重复提交标记歧义；返回 false 或抛异常会撤销未消费记录。
这些是 Hook 观察到的参数与最终返回值；与参数/返回值篡改 Hook 并用时需单独核实。

通过 `capture_event_window` 或 UI 步骤记录取得事件，将保存的事件数组交给：

```python
correlate_async_events(session_id="<会话ID>", events=[...])
```

只有同进程实例、ticket/namespace 一致且有成功入队 after 证据时才建立任务边，
before/after 到达顺序不影响匹配。缺失、歧义和失败证据进入 `unresolved`，分析落盘并纳入报告。
没有仅凭时间邻近推断的边，`complete=null`。包装任务、重新分配对象、缓存淘汰或超过 TTL
可能无法匹配；不覆盖自动 coroutine、Binder 或跨进程传播。
线程嵌套只在显式开启 correlation 的 Hook 之间记录。

## Android 工具入口

```python
android_tool_status()                          # 仅本机检查
android_tool_status(probe_device=True)         # 检查设备命令
analyze_apk_metadata(apk_path="/path/app.apk", section="summary")
capture_perfetto(session_id="<会话ID>", seconds=10, buffer_mb=8)
```

- apkanalyzer 支持 summary/manifest/permissions/files，优先查找 `RECONBRIDGE_APKANALYZER`，
  然后 PATH 和 Android SDK cmdline-tools；缺失返回安装提示。跨平台启动与资源限制沿用现有实现，
  返回输出尾部，可能截断。
- UI Automator 调用设备内置 `uiautomator dump --compressed`，自绘或未暴露无障碍节点的控件可能不可见。
- Perfetto 调用设备 CLI 采集 sched/freq/view/input，时长 1–60 秒、buffer 1–32 MiB。
  保存原始 trace，不解析指标。这是**系统级**采集，不限目标包；版本/权限/数据源限制可能导致失败
  或内容不足。只清理由本次调用创建的远端临时文件，不上传 trace。

参考：[SDK apkanalyzer](https://developer.android.com/tools/apkanalyzer)、
[UI Automator dump 源码](https://android.googlesource.com/platform/frameworks/uiautomator/+/dec12c69b4e09679f691050d8fdcab0a5e474258/cmds/uiautomator/src/com/android/commands/uiautomator/DumpCommand.java)、
[Perfetto Android](https://perfetto.dev/docs/learning-more/android)、
[Perfetto CLI](https://perfetto.dev/docs/reference/perfetto-cli)。

## 报告与故障包

`export_investigation_report(session_id="<会话ID>")` 离线生成 report.json、可直接打开的
report.html、manifest.json 和 support-bundle.zip，包含会话证据图、工具状态、工作流记录与事件。
HTML 转义内容，ZIP 清单记录 SHA-256 并在返回前核对。清单证明导出包内部一致性，
不证明历史源文件未经修改，也不证明采集完整。

附件最多 100 个、单文件 2 MiB、合计 16 MiB，每个证据根目录最多扫描 500 条。
跳过符号链接、XML、PNG、Perfetto trace、APK，报告列出原因。遮蔽结构化密码/token、
参数/返回值及 UI 文本；自由文本仍可能含识别信息。所有输出留在本机，不自动发送或上传。

## 验证范围

Python 覆盖二进制输出/超时/限额、shell 转义、选择器歧义、页面变化、不确定输入不重试、
事件窗口、跨进程隔离、报告转义/脱敏/清单及三平台启动脚本。Kotlin 覆盖跨线程对象身份、
重复任务、TTL/淘汰/取消和 span 清理。Linux CI 使用实际构建的 Tracer APK 执行四种 apkanalyzer 操作。
按用户安排，本轮不部署或连接真机；UI、Perfetto、Xposed 回调设备联调留待后续。
