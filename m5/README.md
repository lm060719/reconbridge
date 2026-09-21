**中文** | [English](README_en.md)

# ReconBridge M5 —— 通用 Java trace 执行器（LSPosed）

给 **LSPosed 模块开发者**用的实时侦察器：PC 端下发「hook 某个 Java 类的方法」，秒级看到每次调用的
`this`/参数/返回值/私有字段/调用顺序/线程 —— **不用建 APK、不用重编译迭代**，把「加 `Log.i` → gradle
build → 装 → 重启 → 看 logcat」的分钟级循环压成 PC 一条命令。

## 为什么是 LSPosed 模块而不是 Zygisk+LSPlant
目标用户本就在 LSPosed 里；LSPosed 内部就是成熟的 ART hook 引擎（LSPlant）。M5 直接**架在它之上**做
一个「数据驱动的通用 Xposed 模块」：`handleLoadPackage` 时读守护进程下发的配置装 trace 回调，复用 M3
的传输/事件链路。省掉自建 LSPlant（C++23 modules / cmake3.28 / cxx prefab）的全部风险，且类加载时序天然正确。

## 组成
- `tracer/` —— 通用 LSPosed 模块（Kotlin/Gradle），本身无任何特定 App 逻辑。
  - `HookEntry.kt` —— LSPosed 入口，把完整期望配置交给进程级 HookRegistry，并接入动态 ClassLoader watcher。
  - `HookRegistry.kt` —— 保存真实 Xposed Unhook handle，维护 installed / pending 双状态，支持 live add/remove/replace。
  - `ClassLoaderRegistry.kt` —— 弱引用记录主/插件/动态 ClassLoader，避免阻止可卸载插件 loader 被 GC。
  - `ClassLoaderWatcher.kt` —— 常驻监听 BaseDexClassLoader 创建；仅在存在 pending 时临时监听 `ClassLoader.loadClass`。
  - `RuntimeStateStore.kt` —— 跨 Hook 共享状态，支持 process/package/hook/thread 作用域、原子计数和有界追加列表。
  - `RuntimeEventBus.kt` —— 进程内同步事件总线；Hook 可 emit，runtime target 可订阅并执行 Action Pipeline，带递归深度保护。
  - `ContextRegistry.kt` —— 弱引用维护 Application / app Context / 当前 Activity，并向 Action 模板暴露 context lifecycle 视图。
  - `LifecycleManager.kt` —— Hook Application.attach 后注册官方 ActivityLifecycleCallbacks，产生 lifecycle.* 事件并刷新 Runtime 状态。
  - `LifecycleTrigger.kt` —— `on_lifecycle` 事件名归一化和 Activity 精确/正则过滤。
  - `ActionExecutor.kt` —— 动作流水线执行器；除 Java 调用/字段/JS/DEX/shell 外，支持 State 读写与 Event → Action。
  - `InjectSocket.kt` —— 复刻 M3 的 `@reconbridge_inject` 抽象 socket 分帧协议。
- `ReconBridge-Tracer.apk` —— 预编译产物（debug 自签名，可直接安装）。
- `JAVA_HOOK_PROTOCOL.md` —— 下发配置 / 事件格式 / Action Pipeline / HookRegistry / 动态 ClassLoader 协议。

## 用法
1. `adb install -r m5/ReconBridge-Tracer.apk`
2. LSPosed 管理器：启用「ReconBridge Tracer」，把目标 App 勾进作用域。
3. PC（MCP）：`trace_java(package="com.miui.voiceassist", class_name="r70.a", method="sendStreamData", args_render="json", restart=True, seconds=20)`，然后唤起目标行为。
   - 字符串特征定位混淆方法：使用 `using_strings=["sendStream"]` 参数，m5 会在 App 进程中自动扫描 DEX 结构，反查并挂载匹配的方法（无需预先定位混淆类名）。
   - 实时篡改与回调：`patch_java(...)`（支持改参数、改返回值、返回值深层字段/Map key篡改 `mutate_return`、条件检查 `condition`、模板变量 `${...}` 及 Action Pipeline，支持 `hot=True` 免重启热加）。
   - 跨 Hook 状态/事件：在 action 中使用 `set_state/get_state/increment_state/append_state/emit_event`；另一个 Java Hook 或 `kind:"runtime"` target 可通过 `state.* / event.*` 条件与模板响应。
   - Lifecycle/Context：模板、condition 和 Action target 可直接引用 `${application}` / `${context}` / `${activity}` / `lifecycle.*`；`kind:"runtime"` target 可用 `on_lifecycle` 监听 resumed/paused/destroyed 等事件。
   - Context/Lifecycle：Action/模板/condition 可直接访问 `${application}`、`${context}`、`${activity}`、`${lifecycle.activity_state}`；runtime target 可用 `on_lifecycle` 监听 created/resumed/paused/destroyed 等事件。
   - 或手工：`post_hook({package, restart, targets:[{kind:"java",...}]})` + `collect_events(seconds)`。

## 构建
```
cd m5/tracer && ./gradlew.bat :app:assembleDebug
```
（仓库在非 ASCII 路径，`gradle.properties` 里已加 `android.overridePathCheck=true`；内置 Rhino JS 引擎，支持脚本动态计算。）

## 边界与能力
支持 Trace（观测）、字符串特征反查、实时 add/remove/replace、真正 live unhook、**pending hook + 动态 ClassLoader Watch**、**Runtime State + Event Bus**、**Lifecycle + Context Runtime**、实时篡改和完整 Action Pipeline。State 提供 process/package/hook/thread 四种作用域；不同 Hook 可通过 `${state.process.xxx}` / `condition.path=state.hook.xxx` 共享状态，也可用 `emit_event` 驱动另一个 target。Lifecycle Runtime 通过 `Application.attach` + `ActivityLifecycleCallbacks` 跟踪 Application/Context/当前 Activity，Activity 只用弱引用保存；可直接使用 `${application}`、`${context}`、`${activity}`、`lifecycle.activity_state`，并用 `on_lifecycle` 响应 resumed/paused/destroyed 等标准事件。显式 `class` 目标若当前所有已知 loader 都找不到类会进入 pending，后续动态 loader 出现后自动补装。需 LSPosed 并在管理器里勾选作用域。详见 `JAVA_HOOK_PROTOCOL.md`。
