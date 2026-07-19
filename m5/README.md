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
  - `HookEntry.kt` —— 读配置、按 `kind:java` 目标装 XposedBridge trace 回调、序列化命中。
  - `InjectSocket.kt` —— 复刻 M3 的 `@reconbridge_inject` 抽象 socket 分帧协议。
- `ReconBridge-Tracer.apk` —— 预编译产物（debug 自签名，可直接安装）。
- `JAVA_HOOK_PROTOCOL.md` —— 下发配置 / 事件格式 / 语义与限制。

## 用法
1. `adb install -r m5/ReconBridge-Tracer.apk`
2. LSPosed 管理器：启用「ReconBridge Tracer」，把目标 App 勾进作用域。
3. PC（MCP）：`trace_java(package="com.miui.voiceassist", class_name="r70.a", method="sendStreamData", args_render="json", restart=True, seconds=20)`，然后唤起目标行为。
   - 或手工：`post_hook({package, restart, targets:[{kind:"java",...}]})` + `collect_events(seconds)`。

## 构建
```
cd m5/tracer && ./gradlew.bat :app:assembleDebug
# 产物 app/build/outputs/apk/debug/app-debug.apk
```
（仓库在非 ASCII 路径，`gradle.properties` 里已加 `android.overridePathCheck=true`；纯 Kotlin 无 NDK，不受影响。）

## 边界
v1 只做 trace（观测），不改参数/返回值；需 LSPosed；类解析走主 classloader。详见 `JAVA_HOOK_PROTOCOL.md`。
