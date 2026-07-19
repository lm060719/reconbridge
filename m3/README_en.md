[中文](README.md) | **English**

# ReconBridge M3 — General-Purpose Dynamic Hook Executor

Zygisk injection + data-driven ShadowHook executor + real-time hit-event streaming (SSE / WS).
The module side is just a **generic executor** with no app-specific logic; hook points are described by JSON config pushed from the PC side, so changing hooks requires no recompile or reflash.

> See `HOOK_PROTOCOL.md` for the hook config protocol.

## Components

```
m3/
├─ HOOK_PROTOCOL.md            # hook config JSON protocol + event format (for PC to push)
├─ zygisk/
│  ├─ module.cpp               # Zygisk module (injection layer) + data-driven ShadowHook executor
│  └─ third_party/             # zygisk.hpp / shadowhook.h / json.hpp
└─ prebuilt/                   # libshadowhook.so + libshadowhook_nothing.so (bytedance 2.0.1)

(The daemon-side M3 code lives in src/dynamic.cpp: /hook /unhook /hooks + SSE/WS + injection IPC socket)
```

M3-related files in the flash zip:
- `zygisk/arm64-v8a.so` — injection layer (loaded by ZygiskNext)
- `system/lib64/libshadowhook.so` + `libshadowhook_nothing.so` — mounted onto /system/lib64
- `sepolicy.rule` — allows the app domain to connect to the daemon's injection socket

## Prerequisite: the device needs a Zygisk implementation
KernelSU itself does not ship Zygisk; you need **ZygiskNext (zygisksu)** or ReZygisk. The install script detects this and warns.

## Runtime architecture

```
POST /hook ─► daemon writes /data/adb/reconbridge/hooks/<pkg>.json (optional am force-stop to trigger re-injection)
target App starts ─► ZygiskNext injects zygisk/arm64-v8a.so
   injection layer (app domain) ──connect──► daemon abstract socket @reconbridge_inject (ksu domain, allowed by sepolicy)
        fetches this package's hook config; dlopen libshadowhook.so from /system/lib64 by name, shadowhook_init
        injects hooks per config (shadowhook_hook_sym_name / _sym_addr)
   on hit ─► proxy captures x0-x7 args + return value (+ optional call stack) ─► event JSON sent back to daemon via socket
daemon broadcasts ─► GET /events (SSE) and ws://host:port+1/events (WS) real-time streaming
```

**Key point: why the shadowhook library goes in /system/lib64.** The injection layer runs in the app SELinux domain and cannot read /data/adb. If shadowhook is loaded via memfd, its linker init calls `dlopen("libshadowhook_nothing.so")` to verify the linker hook — but a memfd-loaded library lives in its own anonymous linker namespace, so shadowhook can't find nothing.so → `shadowhook_init` returns 12 (INIT_LINKER). By mounting both `.so` files onto /system/lib64 via the module's `system/lib64/` (the default namespace, with nothing.so alongside) and `chcon`-ing them to `system_lib_file` (otherwise the default system_file doesn't allow app execution), the injection layer can `dlopen("libshadowhook.so")` by name just like a normal app, and init succeeds.

## Dynamic Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/hook`   | Push hook config (writes hooks/<pkg>.json, optional force-stop) |
| POST | `/unhook` | Remove all hooks for a package or a specific id |
| GET  | `/hooks`  | List the currently pushed hook configs |
| GET  | `/events` | SSE event stream (curl-friendly) |
| WS   | `/events` | `ws://host:(port+1)/events?token=…` |

## Acceptance (passed on a real device)

Device: Xiaomi SM8750 / Android 16 / KernelSU + ZygiskNext.

```bash
# 1) Push a hook: capture the args (property name) and return value of libc __system_property_get
curl -H "X-Token: $T" -X POST http://IP:8787/hook -d '{
  "package":"com.salt.music","restart":true,
  "targets":[{"id":"propget","lib":"libc.so","symbol":"__system_property_get",
    "capture":{"args":[{"index":0,"type":"string","max":128}],"ret":{"capture":true,"type":"int"}},
    "action":{"type":"observe"}}]}'

# 2) Subscribe to the event stream
curl -N -H "X-Token: $T" http://IP:8787/events
```

Both SSE and WS received hit events in real time in testing, e.g.:
```json
{"ts":1784366050786,"package":"com.salt.music","hook_id":"propget","pid":10295,"tid":22095,
 "lib":"libc.so","symbol":"__system_property_get","action":"observe",
 "args":[{"index":0,"type":"string","value":"ro.build.version.sdk"}],"ret":{"type":"int","value":2}}
```
That is: every time this native function is called, you see the args (property name string) and return value (length) in real time. **M3 acceptance passed.**

## Capabilities and Limitations

- Args/return values use the AAPCS64 integer/pointer registers x0–x7 / x0; **floating point (d0–d7) is not captured**.
- Supports `observe` / `replace_ret` (tamper with return value) / `replace_arg` (tamper with input args).
- Arg types: int / ptr / string (C string) / bytes (pointer + length, hex); optional call stack (raw PC list).
- Location methods: symbol name (`shadowhook_hook_sym_name`, auto-pending when the lib isn't loaded) or relative offset (`shadowhook_hook_sym_addr`, registers a dlopen callback to attach lazily when the lib isn't loaded).
- Injection happens at zygote fork; for already-running processes you must restart the App (`restart:true` makes the daemon force-stop it).
- Max 64 hook points per process (compile-time constant).
- Memory reads use `process_vm_readv` for protection; a bad pointer returns failure instead of crashing.
