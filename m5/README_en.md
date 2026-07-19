[中文](README.md) | **English**

# ReconBridge M5 — General-Purpose Java Trace Executor (LSPosed)

A real-time reconnaissance tool for **LSPosed module developers**: from the PC you push "hook a method of some Java class" and within seconds see the `this` / args / return value / private fields / call order / thread of every call — **no need to build an APK or recompile to iterate**. It compresses the minute-scale loop of "add `Log.i` → gradle build → install → reboot → read logcat" into a single PC command.

## Why an LSPosed module instead of Zygisk+LSPlant
The target users are already in LSPosed; LSPosed internally is a mature ART hook engine (LSPlant). M5 builds **directly on top of it** as a "data-driven generic Xposed module": at `handleLoadPackage` it reads the config pushed by the daemon and installs trace callbacks, reusing M3's transport/event pipeline. This avoids all the risk of rolling your own LSPlant (C++23 modules / cmake 3.28 / cxx prefab), and the class-load timing is naturally correct.

## Components
- `tracer/` — the generic LSPosed module (Kotlin/Gradle), with no app-specific logic of its own.
  - `HookEntry.kt` — reads config, installs XposedBridge trace callbacks for `kind:java` targets, serializes hits.
  - `InjectSocket.kt` — reproduces M3's `@reconbridge_inject` abstract socket framing protocol.
- `ReconBridge-Tracer.apk` — prebuilt artifact (debug self-signed, installable directly).
- `JAVA_HOOK_PROTOCOL.md` — push config / event format / semantics and limitations.

## Usage
1. `adb install -r m5/ReconBridge-Tracer.apk`
2. LSPosed Manager: enable "ReconBridge Tracer" and add the target App to its scope.
3. PC (MCP): `trace_java(package="com.miui.voiceassist", class_name="r70.a", method="sendStreamData", args_render="json", restart=True, seconds=20)`, then trigger the target behavior.
   - Or manually: `post_hook({package, restart, targets:[{kind:"java",...}]})` + `collect_events(seconds)`.

## Build
```
cd m5/tracer && ./gradlew.bat :app:assembleDebug
# artifact: app/build/outputs/apk/debug/app-debug.apk
```
(The repo is under a non-ASCII path; `gradle.properties` already sets `android.overridePathCheck=true`; it's pure Kotlin with no NDK, so it's unaffected.)

## Boundaries
v1 only does trace (observation), does not modify args/return values; requires LSPosed; class resolution goes through the main classloader. See `JAVA_HOOK_PROTOCOL.md` for details.
