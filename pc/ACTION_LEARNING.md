# 从手动操作到可验证的动作模块

UI 层级采集、选择器回放与异步任务关联见 [UI_ASYNC_WORKFLOW.md](UI_ASYNC_WORKFLOW.md)。
本文描述 Java 业务动作学习，两种执行路径分别保存证据，不将 UI 输入回执当作业务执行成功。

这组能力由 **PC MCP** 提供，设备端需要 ReconBridge Tracer **1.1.0**、LSPosed 作用域和在线 Runtime。手机本地 MCP 的静态分析工具不会因此自动获得这组高层接口。

流程：**采集一次操作 → 多次示范对比 → 绑定动态参数 → 预览 → 单次执行及结果验证 → 安装模块**。所有采集、计划和执行记录保存在分析会话旁的 `<session_id>.actions/`，记录可能包含业务参数，应按本地分析数据管理。

## 采集操作

先用 `open_target` 绑定目标及其全部 APK。新装的 Tracer 若尚未进入目标进程，先按常规 Java trace 工作流初始化连接；`runtime_hook_status` 应能看到在线进程。开始采集不会自动重启应用。

```python
method = {"class": "com.example.demo.Controller", "method": "submit",
          "params": ["long", "boolean"]}
begin_action_capture(session_id, label="提交第一项", methods=[method])
# 工具返回 recording 后，在手机上做一次操作。
finish_action_capture(session_id, capture_id)
```

再采集另一项内容，得到第二个 `capture_id`。可以先不传 `methods`：传统 View 点击会记录控件 ID、文本、描述、监听器类和栈；`next_capture_methods` 会给出监听器方法，供下一次采集验证。Compose、WebView、自定义触摸处理和覆盖框架方法的控件可能需要额外探针。

开始前确认 Hook 已安装；结束时只清理本次 Hook。`finish_action_capture(..., cancel=True)` 取消采集。`list_action_captures` 列出记录。环形缓冲丢失事件、版本变化、重复命中或未成功清理的示范不能用于生成可执行计划。

采集现在同时检查 daemon 的 `stream_id` 和事件区间完整性。旧 daemon 无法证明区间完整，
会标记 truncated；请更新模块后重新采集。字段含义见 [OBSERVABILITY.md](OBSERVABILITY.md)。

点击与方法之间的同线程时间关联比单纯时间相邻更有参考价值，两者均不等于因果证明。跨线程调用需要调用图或业务 ID 等进一步证据。

## 对比及生成草稿

```python
compare_action_demonstrations(session_id, [capture_a, capture_b], method)
create_action_plan(
    session_id, plan_id="demo_submit", capture_ids=[capture_a, capture_b],
    method=method, receiver="activity",
    bindings={"0": {"input": "item_id"}},
    checks=[{"source": "state", "key": "result", "path": "value.done",
             "op": "eq", "value": True},
            {"source": "state", "key": "result", "path": "value.item_id",
             "op": "eq", "value": "{{input.item_id}}"}],
    limits={"max_runs": 10, "min_interval_ms": 1000,
            "timeout_ms": 5000, "verification_ms": 3000},
)
```

`plan_id` 使用 ASCII 字母、数字、下划线或连字符。同一 ID 的计划不可覆盖，以保留执行历史。精确 `params` 必须使用 Java 类型；省略签名的示范可用于发现方法，不能直接生成可执行模块。

参数会分类为 `observed_constant`、`dynamic` 或 `missing`。样本中一致的值只证明这些样本里一致。动态参数需要绑定：`{"input":"item_id"}` 由调用时传入，`{"path":"activity.currentItem"}` 从实时对象取值，`{"value":true}` 明确指定字面值。对象的 `toString()`/deep 序列化结果不能冒充活的 Java 对象。

`receiver` 从当前 `activity`、`context`、`application`、`class:...` 或前置步骤寄存器重新获取。`setup_actions` 支持 `call_method/get_state`，可先通过 `findViewById` 或业务 getter 获取对象，再用 `$receiver` 调用。实例方法不能用类名代替实例。

成功条件由分析者依据业务证据指定。示例中的 `result` 是目标 Hook 已写入 Runtime State 的业务结果，不是工具自动创造的成功标记。支持 `state`、`context` 和临时方法探针捕获的 `events`；调用返回 Ack 不算业务成功。

异步回调检查示例：

```python
checks = [{"source": "events",
           "method": {"class": "com.example.demo.Callback", "method": "completed",
                      "params": ["long"]},
           "path": "ret", "op": "eq", "value": True,
           "correlation": {"args[0]": "item_id"}}]
```

存在动态输入时，回调检查必须关联当前输入，状态/页面检查必须有绑定当前输入的身份条件（`value="{{input.item_id}}"` 会按实际类型替换）。其他进程、其他内容和抛异常的方法返回不能作为成功证据。原本已经满足全部成功条件的操作会在提交前停止。

## 预览、验证、安装

```python
execute_action_plan(session_id, "demo_submit", {"item_id": 42}, "item:42")
# 默认 dry_run=True：预览实际参数、成功条件、限制和兼容性，不提交操作。
execute_action_plan(session_id, "demo_submit", {"item_id": 42}, "item:42", dry_run=False)
inspect_action_plan(session_id, "demo_submit")
export_action_plan(session_id, "demo_submit")
install_action_plan(session_id, "demo_submit")
# 当前精确计划验证通过后，可以走已安装模块的事件入口：
execute_action_plan(session_id, "demo_submit", {"item_id": 43}, "item:43",
                    dry_run=False, use_installed=True)
```

`dedup_key` 必须标识业务对象，而非每次生成随机值。次数限制包括验证提交。RPC 超时、结果未确认、失败或清理失败会留下记录并停止后续提交，不自动重试；调查后可创建新的计划 ID。已有外部效果不能由工具回滚。

PC 端会检查安装版本以及全部本地/设备 APK 的 SHA-256；设备模块会再次检查版本。升级、同版本换包、缺少 split APK 都需要重新拉包、采集和验证。`check_action_compatibility` 可单独检查。

安装需要最近一次对**同一份计划**的执行验证成功，继续遵守既有 Runtime Program 权限策略。导出文件包含计划和 manifest，是可审查的草稿文件；签名发布继续使用 `runtime_program_export`。独立 LSPosed APK 仍需另外开发。

安装后的模块通过 `action.execute.<plan_id>` 接收输入、run_id 和 dedup_key。`execute_action_plan(use_installed=True)` 会负责探针、验证和 completion。仅手工发事件不会自动完成外部结果验证：模块在 `awaiting_verification` 状态阻止下一次提交，必须以相同 run_id 完成验证。

## 执行保护的边界

设备端 `run_guarded` 会在业务动作前持久化预留，维护次数、间隔、业务键和执行状态；Android 真机使用应用私有 SharedPreferences，重启应用不会清空记录。`complete_guarded` 仅接受当前等待验证的 run_id。Guard 中的步骤抛错后立即停止后续步骤。

超时按步骤检查，不能强行取消已经进入的 Java 方法。超时结果属于不确定状态；不会声称动作已撤销。程序卸载、disable 或 rollback 也不会清掉这些业务记录。

这些能力用于分析和构建经授权的动作模块。能否跳过某个界面流程、是否真正发生点赞或获得奖励，仍由目标应用及服务端的实现决定。
