[中文](README.md) | **English**

# ReconBridge M4 — Packer / Anti-Debug Enhancements

On top of the M3 generic executor, use **data-driven hook config** to counter full-app packers and dynamic-analysis countermeasures.
**The module itself contains no logic for any specific packer/security SDK** — all countermeasures are handled by hook config pushed from the PC side.

## 1. General In-Memory Dex Dump (for full-app packers)

A packer hands decrypted dex to ART at runtime. Hook the dex-loading entry point, grab the base address + length of the in-memory dex, and send that memory back to disk — you get the unpacked dex.

**The executor gains a `dump` capability**: on a hook hit it reads the memory `[x_base_arg, +x_size_arg)`, sends it back to the daemon via the injection socket, and saves it to `/data/adb/reconbridge/dumps/`. The hit event carries `"dump":{"saved":..,"bytes":..}`.

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/dump_dex` | Convenience push of a dump config: `{package, lib, symbol\|offset, base_arg, size_arg, max?, ext?, restart?}` |
| GET  | `/dumps`    | List saved dumps (retrieve with `/file?path=`) |

You can also push a target with `capture.dump` directly via `/hook` (see `templates/dump_dex_art.json`).

### Usage
```bash
# 1) Use M2 to analyze libart.so and find the dex-loading entry and its base/size arg positions
#    ghidra_analyze /system/lib64/libart.so  → find OpenMemory / DexFile related exports
# 2) Push the dump (symbol per the actual libart symbol; base_arg/size_arg per the arg layout)
curl -H "X-Token: $T" -X POST http://IP:8787/dump_dex -d '{
  "package":"com.target.app","lib":"libart.so",
  "symbol":"_ZN3art7DexFile10OpenMemoryEPKhm...","base_arg":0,"size_arg":1,"restart":true}'
# 3) Launch the target to trigger loading → list and retrieve the dump
curl -H "X-Token: $T" http://IP:8787/dumps
curl -H "X-Token: $T" "http://IP:8787/file?path=/data/adb/reconbridge/dumps/xxx.dex" -o xxx.dex
# 4) Analyze the unpacked dex locally with M2's dexkit_search / decompile
```

> Different Android/ART versions have different dex-loading symbols and arg layouts, so the module provides only a **generic dump mechanism**; the specific entry point is located by the PC side with M2 and then pushed — consistent with "intelligence on the PC side, the phone only does atomic capabilities".

## 2. Anti-Detection Hook Config Template Library (`templates/`)

Reusable configs for common anti-debug / anti-hook / root-detection points. Two usage patterns:

- **observe (locate)**: first hook libc's `access/fopen/openat/strstr` etc., capture the path/string args + call stack to see what the target is checking and where it originates → use M2 decompilation to pinpoint the App's **own detection function**.
- **replace_ret (precise bypass)**: apply `replace_ret` to the located detection function, returning "not detected".

| Template | Purpose |
|----------|---------|
| `anti_debug_ptrace.json`   | ptrace anti-debug bypass (replace_ret 0) |
| `root_detection_locate.json` | Locate root detection (observe access/fopen + call stack) |
| `frida_xposed_locate.json` | Locate Frida/Xposed detection (observe openat/strstr) |
| `dump_dex_art.json`        | In-memory dex dump (ART entry example; symbol must be adjusted per version) |

Usage: replace `<TARGET_PKG>` in the template with the target package name and push via `/hook`.

### Important Limitation
The executor's `replace_ret` / `replace_arg` are **unconditional** (they change every call) and do no arg-value matching. Therefore it is **not recommended** to `replace` high-frequency generic libc functions like `access/open` directly (it would affect global logic). The correct approach is: observe to locate → find the **specific** detection function in the App/packer → apply `replace_ret` only to it. Conditional bypasses like "only change the return value when the arg is a certain root path" are app-specific logic, decided by the PC side and pushed to the precise detection function, keeping the module generic.

## Relation to Other Milestones
- Locating (finding the detection function / dex entry symbol): M2 (jadx / dexkit / ghidra).
- Injection and execution: M3 generic ShadowHook executor.
- Retrieving artifacts (dumped dex / so): M1 static `/file`, M2 `pull_*`.
