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
  - `ActionExecutor.kt` —— 动作流水线执行器（调用 Java 方法、修改/读取字段、构造对象、执行 JS/DEX 片段、执行 shell 命令、组合 before/after callback）。
  - `InjectSocket.kt` —— 复刻 M3 的 `@reconbridge_inject` 抽象 socket 分帧协议。
- `ReconBridge-Tracer.apk` —— 预编译产物（debug 自签名，可直接安装）。
- `JAVA_HOOK_PROTOCOL.md` —— 下发配置 / 事件格式 / Action Pipeline / HookRegistry / 动态 ClassLoader 协议。

## 用法
1. `adb install -r m5/ReconBridge-Tracer.apk`
2. LSPosed 管理器：启用「ReconBridge Tracer」，把目标 App 勾进作用域。
3. PC（MCP）：`trace_java(package="com.miui.voiceassist", class_name="r70.a", method="sendStreamData", args_render="json", restart=True, seconds=20)`，然后唤起目标行为。
   - 字符串特征定位混淆方法：使用 `using_strings=["sendStream"]` 参数，m5 会在 App 进程中自动扫描 DEX 结构，反查并挂载匹配的方法（无需预先定位混淆类名）。
   - 实时篡改与回调：`patch_java(...)`（支持改参数、改返回值、返回值深层字段/Map key篡改 `mutate_return`、条件检查 `condition`、模板变量 `${...}` 及 Action Pipeline，支持 `hot=True` 免重启热加）。
   - 或手工：`post_hook({package, restart, targets:[{kind:"java",...}]})` + `collect_events(seconds)`。

## 构建
```
cd m5/tracer && ./gradlew.bat :app:assembleDebug
```
（仓库在非 ASCII 路径，`gradle.properties` 里已加 `android.overridePathCheck=true`；内置 Rhino JS 引擎，支持脚本动态计算。）

## 边界与能力
支持 Trace（观测）、字符串特征反查、实时 add/remove/replace、真正 live unhook、**pending hook + 动态 ClassLoader Watch**、`runtime_hook_status` 查询 installed/pending/loader 真实状态、实时篡改（参数/返回值覆盖/Skip原方法/深层字段与 Map key 篡改）、条件执行、`after` 阶段返回值 Path 读写、**Action Pipeline**（调用 Java 方法/改写字段/构造对象/Rhino JS片段/DEX动态执行/shell命令）及模板变量 `${...}`。显式 `class` 目标如果当前所有已知 loader 都找不到类，会进入 pending；后续 Dex/Path/InMemoryDexClassLoader 出现或目标类经 `loadClass` 返回后自动补装。需 LSPosed 并在管理器里勾选作用域。详见 `JAVA_HOOK_PROTOCOL.md`。
