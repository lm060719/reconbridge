[中文](README.md) | **English**

# ReconBridge M5 — General-Purpose Java Trace Executor (LSPosed)

A real-time reconnaissance tool for **LSPosed module developers**: from the PC you push "hook a method of some Java class" and within seconds see the `this` / args / return value / private fields / call order / thread of every call — **no need to build an APK or recompile to iterate**. It compresses the minute-scale loop of "add `Log.i` → gradle build → install → reboot → read logcat" into a single PC command.

## Why an LSPosed module instead of Zygisk+LSPlant
The target users are already in LSPosed; LSPosed internally is a mature ART hook engine (LSPlant). M5 builds **directly on top of it** as a "data-driven generic Xposed module": at `handleLoadPackage` it reads the config pushed by the daemon and installs trace callbacks, reusing M3's transport/event pipeline. This avoids all the risk of rolling your own LSPlant (C++23 modules / cmake 3.28 / cxx prefab), and the class-load timing is naturally correct.

## Components
- `tracer/` — the generic LSPosed module (Kotlin/Gradle), with no app-specific logic of its own.
  - `HookEntry.kt` — reads config, installs XposedBridge trace/action callbacks for `kind:java` targets.
  - `ContextRegistry.kt` — weakly tracks Application/Context/current Activity and exposes lifecycle roots to Action expressions.
  - `LifecycleManager.kt` — hooks `Application.attach`, registers `ActivityLifecycleCallbacks`, and bridges lifecycle transitions into Runtime Events.
  - `RuntimeCommandDispatcher.kt` — Phase 5 remote Runtime command executor for direct State/Event/Context/Activity control without temporary hooks.
  - `LifecycleTrigger.kt` — normalizes `on_lifecycle` declarations and filters by Activity class/regex.
  - `ActionExecutor.kt` — Action Pipeline executor with Java calls/fields/JS/DEX/shell plus State, Event, and Lifecycle/Context Runtime access.
  - `InjectSocket.kt` — reproduces M3's `@reconbridge_inject` abstract socket framing protocol.
- `ReconBridge-Tracer.apk` — prebuilt artifact (debug self-signed, installable directly).
- `JAVA_HOOK_PROTOCOL.md` — push config / event format / Action Pipeline protocol / semantics and limitations.

## Usage
1. `adb install -r m5/ReconBridge-Tracer.apk`
2. LSPosed Manager: enable "ReconBridge Tracer" and add the target App to its scope.
3. PC (MCP): `trace_java(package="com.miui.voiceassist", class_name="r70.a", method="sendStreamData", args_render="json", restart=True, seconds=20)`, then trigger the target behavior.
   - Patching & callbacks: `patch_java(...)` or configure custom `action` pipelines.
   - Or manually: `post_hook({package, restart, targets:[{kind:"java",...}]})` + `collect_events(seconds)`.

## Build
```
cd m5/tracer && ./gradlew.bat :app:assembleDebug
# artifact: app/build/outputs/apk/debug/app-debug.apk
```
(The repo is under a non-ASCII path; `gradle.properties` already sets `android.overridePathCheck=true`; bundles embedded Rhino JS engine for dynamic script evaluations.)

## Capabilities & Boundaries
Supports Trace (observation), live add/remove/replace, true live unhook, **pending hooks with dynamic ClassLoader watching**, **Runtime State + Event Bus**, **Lifecycle + Context Runtime**, **Runtime Command Dispatcher**, and **Runtime Program / Module Manifest**. Hooks can share bounded process/package/hook/thread state, emit named events, and react through runtime targets. Action paths/templates/conditions can read `application`, `context`, `activity`, and `lifecycle.*`; Rhino JS receives `$application`, `$context`, `$activity`, and `$lifecycle`. Lifecycle tracking uses `Application.attach` plus `ActivityLifecycleCallbacks`; current Activity is held through a weak reference. `on_lifecycle` can subscribe to resumed/paused/destroyed and filter by Activity class. Explicit classes not visible from known loaders still enter `pending_class` and auto-install when a suitable loader appears. Remote Runtime Command tools include `runtime_state_get/set/remove/increment/append/clear`, `runtime_event_emit`, `runtime_context_status`, and `runtime_activity_action`. Runtime Programs can be managed with `runtime_program_install/replace/enable/disable/rollback/status`; local target ids are namespaced per program and up to five prior manifests are retained for rollback. Requires LSPosed with scope enabled. See `JAVA_HOOK_PROTOCOL.md` for details.


## Runtime Program Package (Phase 7)

Phase 6 Runtime Programs can now be exported on the PC as portable Ed25519-signed `.rbprog.json` bundles with `runtime_program_export`, verified with `runtime_program_verify_package`, and installed with `runtime_program_import`. The signed payload covers the complete manifest, declared permissions, allowed target packages, and source revision. Imports require a trusted signer by default, while the Android daemon independently rescans the manifest and rejects under-declared capabilities. Signing private keys stay on the PC and are never copied to the Android device. See `JAVA_HOOK_PROTOCOL.md` for the package format and permission list.


## Runtime Program Permission Policy (Phase 8)

Phase 7 Ed25519 signatures establish provenance and integrity; Phase 8 device policy independently decides whether a signed Runtime Program is actually allowed to execute on this device.

Each declared Program permission can be configured as `allow`, `ask`, or `deny`. The default remains `allow` for backward compatibility. Install, replace, enable, and rollback all pass through the same policy gate. `ask` can be satisfied either by a revision-scoped `approve_once` grant or a persistent per-Program approval; `deny` always wins.

Tightening policy is enforced immediately: affected enabled Programs are live-disabled, revision approvals are cleared when requested, state cleanup is applied, and the HookRegistry is reconciled. Program materialization also reevaluates policy every time, so editing the persisted Program JSON cannot bypass the policy.

PC and mobile MCP expose policy status/set and persistent approval/revocation tools. See `JAVA_HOOK_PROTOCOL.md` for full semantics.
