# ReconBridge 优化建议

> 来源：一次真实的 LSPosed 模块开发（`xiaoai-plug`，目标 App = 超级小爱 `com.miui.voiceassist`）。
> 本次共约 **22 次** `mcp__reconbridge__*` 调用（`device_status`×2、`pull_apk`×1、`post_hook`×6、
> `collect_events`×8、`unhook`×5），外加复用其 jadx 反编译产物。
> 下列每一条都对应本次实际踩到的摩擦点，按"能省多少时间"排序，不含泛泛建议。

---

## 优先级总览

| 优先级 | 优化点 | 核心收益 |
|---|---|---|
| P0 | `collect_events` 早返回 + 保留最近事件（不再固定窗口/不回放） | 一轮验证从 ~75s 降到命中即返回；消除"掐点说话" |
| P0 | 免重启热加 hook（`post_hook` 不强制 force-stop） | 消除每轮"强退→重新唤醒→重说"的循环 |
| P0 | 嵌套字段捕获 / `render:"json"` 深序列化 | 直接拿嵌套 payload 值，不再靠 `toString()` 撞运气 |
| P1 | 多设备/离线链路自动处理 | 免手动 `adb disconnect` |
| P1 | stack 自动折叠 hook 框架帧 | 一眼看到真正的调用方 |
| P1 | 已产出物索引 `list_artifacts(package)` | 免翻找 apk/jadx/libs 是否已存在 |
| P2（新能力）| 场景捕获 + 差分 `diff_scenarios(A,B)` | 直接命中"A 与 B 行为为何不同"这类逆向任务 |
| — （文档）| 推荐"先 `patch_java` 现场验证，再固化进 APK"套路 | 少走几轮编译-安装-测试 |

---

## P0-1. `collect_events`：固定窗口 + 不回放 → 逼人"掐点说话"

**现象/证据**
- 每轮都要人工"现在说！"，然后阻塞干等整个窗口。第 1 轮因为用户没赶上窗口 **0 命中白跑**；实际命中 5 秒就来了，却还要空等 70 秒。
- 文档里"广播器不回放历史"是当前最反直觉、最容易踩坑的约束。

**建议**
1. **早返回**：新增 `until_first_hit=true` / `until_n_events=N`，命中即返回，不跑满窗口。
2. **保留最近 N 条的环形缓冲**：允许"事后采集"，不必在命中那一刻正好连着 SSE。
3. **arm-and-notify**：下发后立即返回，命中时推送或允许轮询，而不是长阻塞。

**收益**：把"和用户掐点同步"这个最大的人工摩擦彻底去掉；单轮耗时数量级下降。

---

## P0-2. `post_hook` 每次 restart → 反复"强退+重唤醒+重说"

**现象/证据**
- 本次做了 6 轮 recon = 6 次 `force-stop`。目标是语音助手，用户每次都要重新长按电源键唤醒、把同一句话再说一遍。
- 根因：M5 tracer 只在**进程启动时**读一次配置。

**建议**
- **热加 hook**：支持往已运行进程**增量追加** target 而不重启（例如给 tracer 一个信号让它重读 `hooks/<pkg>.json`，或提供 `post_hook(..., restart=false, mode="append")`）。
- 至少对"只加不删、纯观测"的 target 支持免重启注入。

**收益**：迭代式逆向时省掉一大半"重来一遍"，人机同步成本骤降。

---

## P0-3. 只能整对象 `tostring` → 嵌套字段全靠运气

**现象/证据**
- 需要 `Template.FrontendPage.loadUrl`（云端下发、源码无常量），最终是靠 `Instruction.toString()` **恰好**吐出 JSON 才拿到。
- 直接 hook `setLoadUrl` 那轮扑空（客户端不走 setter），说明"靠某个 setter 拿值"不可靠。

**建议**
1. **嵌套字段路径捕获**：`capture: {"path": "args[1].payload.load_url"}`。
2. **`render:"json"` / `"deep"`**：反射把对象图序列化成 JSON 返回。
- 对"关键值都埋在嵌套 payload 对象里"的场景，这比 stack 还高频。

**收益**：把"能不能拿到这个值"从撞运气变成确定能拿到。

---

## P1-4. 多设备 / 离线链路自动处理

**现象**：首个 `device_status` 直接报 `more than one device`——一条 offline 的 `adb-...tls-connect` 残留链路所致，需手动 `adb disconnect`。
**建议**：自动忽略 `offline`/重复 transport，或在多在线设备时给出清单让选，而不是直接失败。

## P1-5. stack 自动折叠 hook 框架帧

**现象**：每条 stack 顶部固定是 `TraceCallback.emit / XC_MethodHook.callBeforeHookedMethod / r.intercept / k.proceed / CrasaistFrind` 等 hook 框架噪声，真正有价值的是下面几帧。
**建议**：默认折叠/标注这些框架帧（可 `raw_stack=true` 关闭），让调用方一眼看到真实 caller。

## P1-6. 已产出物索引

**现象**：jadx 反编译目录是 `find` 撞见的；`list_dumps` 有了，但缺 apk/jadx/libs 的清单。
**建议**：`list_artifacts(package)` —— 返回该包已 pull 的 apk、已反编译的 jadx 目录、已拉的 libs 及路径，免"到底反编译过没有"的翻找。

---

## P2（新能力）场景捕获 + 差分

**动机**：本次两个关键突破本质都是"A 与 B 为何不同"：
1. 「查看X」vs「打开X」——为什么一个跳转一个不跳；
2. App 对话 vs 电源键悬浮窗——为什么一个渲染答案卡一个不渲染（最终定位到 App 走 `flowableresult.d`、悬浮窗走 `widget.d`）。

这两次都是**人肉比对两次 trace 的命中集**看出来的。

**建议**
> `capture_scenario(name)`：arm 一组 hook → 用户操作一次 → 自动记录有序命中时间线（带 stack）。
> `diff_scenarios(A, B)`：直接给出"只在 A 命中 / 只在 B 命中 / 参数不同"的方法差异。

**收益**：把"行为差异逆向"这一标准动作做成一等公民，直接命中最常见的一类需求。

---

## 文档层面：推荐"先验证再固化"套路

`patch_java`（`skip_original` / 改返回值）本可用来**先现场验证**想法——例如"skip 掉 `startActivitySafely` 到底能不能拦住跳转"——确认后再写进模块。本次是直接写模块 + 编译 + 安装 + 测试的整轮。

**建议**：在 `AGENTS_QUICKSTART.md` 明确点出推荐工作流：
> 定位到候选方法后，**先用 `patch_java` 现场验证行为**（拦得住吗？改返回值有效吗？），验证通过再固化进 APK 模块。

可省掉早期若干轮"改代码→编译→装→测"。

---

## 一句话结论

ReconBridge 的动态 instrumentation 能力本身已经很到位（stack + all_args 是本次多个决定性突破的直接来源）。**当前最值得投入的两块是"采集时序（P0-1）"和"免重启迭代（P0-2）"**——它们不是功能缺失，而是直接决定"一轮验证要 10 秒还是 2 分钟"、决定要不要反复打扰用户。把这两块磨顺，配合 P0-3 的嵌套字段捕获，逆向迭代体验会有质变。
