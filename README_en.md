[中文](README.md) | **English**

# ReconBridge — A General-Purpose Reverse-Engineering KernelSU Module

A **general-purpose reverse-engineering backend** that runs on Android (KernelSU root) devices. The device side only performs atomic capabilities (pull APKs / read files / list `.so` / inject hooks); all the intelligence (locating functions, generating hooks, analyzing results) lives on the PC side (Claude Code + MCP).

> 📌 **One-page cheat sheet for AI agents / new sessions: [`AGENTS_QUICKSTART.md`](AGENTS_QUICKSTART.md)** — all MCP tool signatures, M5 usage, typical workflows, and common pitfalls. Read this single file to get started.

> Progress: **M1 / M2 / M3 / M4 / M5 are all complete and verified on a real device** (Xiaomi SM8750 / Android 16 / KernelSU + ZygiskNext + LSPosed).
> - **M5**: general Java trace + live tampering (LSPosed module, `trace_java` / `patch_java`) — see [`m5/README.md`](m5/README.md), [`m5/JAVA_HOOK_PROTOCOL.md`](m5/JAVA_HOOK_PROTOCOL.md).

---

> ## ⚠️ Disclaimer
>
> This project is **for authorized security research, CTF, reverse-engineering study, and defensive research only**. Users must have **proper legal authorization** for any device or app they analyze (your own devices, explicitly authorized penetration tests, publicly available teaching samples, etc.).
>
> **Do not** use this project for unauthorized cracking, bypassing copyright/license protection, stealing data, attacking third-party systems, or any activity that violates local laws. The author is not responsible for any misuse or its consequences. By continuing to use this project you acknowledge and accept these terms.

---

## Quick Start

### PC side (one-click MCP tool install)

Supports two AI clients: **Claude Code** (writes `~/.claude.json`) and **ChatGPT Codex** (writes `~/.codex/config.toml`). The default `both` means **auto-detect**: it registers only into the client(s) that are already installed (Claude is detected via `~/.claude.json`/`~/.claude/`, Codex via `~/.codex/`); the one that isn't installed is skipped automatically and no directory is created; **if neither is detected, it installs only the tool itself and writes no config** (re-run registration after you install a client, or force it with `--target`). You also need `adb` (Android platform-tools, for real-device connections).

**Recommended: one-line online install (Windows, no repo clone, no Python)**

```powershell
irm https://github.com/lm060719/reconbridge/releases/latest/download/install.ps1 | iex
```

This automatically downloads the packaged MCP exe, extracts it to `%LOCALAPPDATA%\ReconBridge\`, registers it into the client's user-level config, and lays down a `reconbridge` skill (auto-loaded into new sessions for reverse-engineering tasks):
- **Claude Code** → `mcpServers.reconbridge` in `~/.claude.json` + skill to `~/.claude/skills/`
- **ChatGPT Codex** → `[mcp_servers.reconbridge]` in `~/.codex/config.toml` + skill to `~/.codex/skills/`

**Restart the corresponding client** after install and you're ready.
> The exe bundles the MCP server and core dependencies (including androguard); jadx / Ghidra remain optional decompilation tools — extract them into `%LOCALAPPDATA%\ReconBridge\tools\` and they'll be auto-detected (check with `toolchain_status`).
> **Force-install only one** (skip detection): set `$env:RB_TARGET="codex"` (or `"claude"`) first, then run — the directory will be created even if it doesn't exist. **Wi-Fi transport**: set `$env:RB_TRANSPORT="wifi"` first.

**Update**: just re-run the install command above — it overwrites the exe in place and re-registers, preserving `work\` (pulled packages / dump data) and `tools\`.

**Uninstall**:
```powershell
irm https://github.com/lm060719/reconbridge/releases/latest/download/uninstall.ps1 | iex
```
This unregisters reconbridge from both clients and removes the install directory (by default it keeps `work\`/`tools\` data; to delete data too set `$env:RB_PURGE="1"`; to uninstall only one client set `$env:RB_TARGET="codex"`). Equivalently, the exe can self-unregister: `reconbridge-mcp.exe --unregister [--target codex]`.

**Local console (optional, GUI for picking a connection method / viewing status)**

```powershell
reconbridge-mcp --serve            # one-click install adds it to PATH — open a NEW terminal after install; the browser auto-opens 127.0.0.1:9000
# If the command isn't found (PATH not applied or not added), use the full path:
#   %LOCALAPPDATA%\ReconBridge\reconbridge-mcp\reconbridge-mcp.exe --serve
# From source: python -m reconbridge_mcp --serve
```

In the web page you can pick adb / wifi, connect with one click, and view daemon status plus read-only monitoring (active hooks / recent event stream / on-disk dumps) — no need to set env vars on the command line or copy tokens by hand. Binds only to `127.0.0.1` (local machine). `--port N` changes the port; `--no-open` skips auto-opening the browser.

**adb or wifi? The bind-address gotcha**

- **adb (USB, default)**: automatically reads the token and builds a USB tunnel — zero config, most secure (daemon binds to loopback only). The cost: connecting **pins the device-side bind address to `127.0.0.1`** (to work with the tunnel), and you must grant root to adb shell.
- **wifi (LAN direct)**: requires the device-side daemon to bind to a **LAN IP**. On the **phone's WebUI → "Network Settings" → "Bind Address"** enter `auto` (auto-binds to the `wlan0` LAN IP) and save, or run `rbctl setbind auto` on the device; then connect via `http://<phone-IP>:<port>` + token (IP / port / token are all shown in the phone WebUI).
- ⚠️ **Switching to wifi after using adb mode**: `bind` has been pinned to `127.0.0.1`, so the PC can't connect — set "Bind Address" back to `auto`. If you want to stay on wifi, stop using adb mode (each use re-pins it to `127.0.0.1`).

**Run from source (developers / Linux / macOS, requires Python 3.10+)**

```powershell
# Windows
git clone https://github.com/lm060719/reconbridge.git
cd reconbridge
./install.ps1              # create venv → install deps → register reconbridge + lay down skill (default Claude + Codex)
./install.ps1 -Target codex   # Codex only (also -Transport wifi)
```

```bash
# Linux / macOS
git clone https://github.com/lm060719/reconbridge.git
cd reconbridge
./install.sh                  # default both; Codex only: ./install.sh adb codex
```

After install, **restart the corresponding client**: in Claude Code, `claude mcp list` / `/mcp` will show `reconbridge` (25 tools); in Codex, `~/.codex/config.toml` will contain `[mcp_servers.reconbridge]`. Both get a `reconbridge` skill (in `~/.claude/skills/` or `~/.codex/skills/`, auto-loaded into new sessions for reverse-engineering tasks along with its workflow and pitfall checklist).
> The script writes `~/.claude.json` / `~/.codex/config.toml` directly (user-level scope), which is more robust than the client's built-in `add` command (the latter has quoting/encoding issues on Windows / non-ASCII paths). When writing TOML it only adds/removes the `reconbridge` table block; the rest of your config and comments are preserved verbatim. To enable Claude only within this repo directory, see [`.mcp.json.example`](.mcp.json.example). To build the exe yourself: `./build_exe.ps1` (produces `dist/reconbridge-mcp-win64.zip`).

### Device side (flash the KernelSU module)

The device must be rooted (KernelSU) with ZygiskNext installed (required for M3/M4 dynamic hooks).

```powershell
./build.ps1               # compile arm64-v8a with the NDK (requires Android NDK, see below)
./pack.ps1                # package dist/ReconBridge-M1.zip
```

In KernelSU Manager → Modules → Install from local `dist/ReconBridge-M1.zip` → reboot.
> The repo ships prebuilt artifacts (`module/bin`, `module/zygisk`, `module/system/lib64`); if you don't want to compile yourself, just run `./pack.ps1` to package, or use the zip from [Releases](../../releases).

Once installed, just tell Claude Code "connect to my phone and check status" to begin. See the milestone docs below for details.

## Milestone Overview

| Milestone | Content | Docs |
|-----------|---------|------|
| **M1** | Static transport layer: KernelSU module + C++ HTTP daemon + WebUI + static endpoints | This document (below) |
| **M2** | PC-side MCP Server: wraps the M1 endpoints + local decompilation chain (jadx / DexKit→androguard / Ghidra / Hermes) as Claude Code tools | [`pc/README.md`](pc/README.md) |
| **M3** | General dynamic hook executor: Zygisk injection + data-driven ShadowHook + SSE/WS hit streaming | [`m3/README.md`](m3/README.md) · protocol [`m3/HOOK_PROTOCOL.md`](m3/HOOK_PROTOCOL.md) |
| **M4** | Packer/anti-debug enhancements: general in-memory dex dump (`/dump_dex`) + anti-detection hook config templates | [`m4/README.md`](m4/README.md) |

Build all artifacts: `./build.ps1` → `./pack.ps1` (generates `dist/ReconBridge-M1.zip`).
> Device-side note: on Windows, passing `/data/...` paths through adb requires `export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'` (Git Bash otherwise rewrites Unix paths).

---

## M1 — Static Transport Layer

KernelSU module skeleton + C++ HTTP daemon + WebUI port toggle + static endpoints.

### Directory structure

```
逆向模块/
├─ src/
│  ├─ daemon.cpp              # C++17 daemon source
│  └─ third_party/
│     ├─ httplib.h            # cpp-httplib 0.18.3 (single header)
│     └─ json.hpp             # nlohmann/json 3.11.3 (single header)
├─ module/                    # contents of the flash zip (zip root = this directory)
│  ├─ module.prop
│  ├─ customize.sh            # install script (arch check / permissions)
│  ├─ service.sh             # late_start launches the daemon
│  ├─ rbctl                   # control script (enable/disable/info…)
│  ├─ bin/reconbridge_daemon  # build artifact (arm64-v8a)
│  └─ webroot/index.html      # KernelSU WebUI
├─ CMakeLists.txt             # cmake build (optional)
├─ build.ps1                  # build directly with NDK clang++ (recommended, no cmake needed)
├─ pack.ps1                   # package into a flash zip
└─ README.md
```

### 1. Compile

Requires Android NDK (this project uses r27c). Auto-detected under `%LOCALAPPDATA%\Android\Sdk\ndk\`.

```powershell
# Option A (recommended, no cmake): call NDK clang++ directly
./build.ps1

# Option B: cmake + ninja
cmake -B build -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE=$env:ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake `
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build
```

Artifact: `module/bin/reconbridge_daemon` (AArch64 PIE ELF, ~900 KB, statically linked libc++).

### 2. Package the flash zip

```powershell
./pack.ps1
# generates dist/ReconBridge-M1.zip
```

### 3. Flash

- KernelSU Manager → Modules → Install from local → select `ReconBridge-M1.zip` → **reboot**.
- Or via `adb`:
  ```
  adb push dist/ReconBridge-M1.zip /data/local/tmp/
  adb shell su -c "ksud module install /data/local/tmp/ReconBridge-M1.zip"
  adb reboot
  ```

### 4. Enable the port

After reboot the port is **closed by default**. In KernelSU Manager → Modules → ReconBridge, open the WebUI:

1. Turn on the "Port Toggle".
2. Note the **access URL** shown on the page (e.g. `http://192.168.x.x:8787`) and the **token**.
3. Turn the toggle off when you're done.

> The WebUI only writes `config.conf`; the daemon picks up changes via inotify and applies them instantly — it does not control the native process directly.

### 5. Acceptance (PC side, same Wi-Fi)

Set `IP`/`TOKEN`/`PKG` to actual values:

```bash
# 1) Liveness
curl -H "X-Token: TOKEN" http://IP:8787/health

# 2) List apps
curl -H "X-Token: TOKEN" "http://IP:8787/packages"

# 3) List all apk paths for an app (including all splits)
curl -H "X-Token: TOKEN" "http://IP:8787/apk?pkg=PKG"

# 4) Pull an apk (streamed, equivalent to adb pull, no adb authorization needed)
#    after getting a concrete path from the previous step:
curl -H "X-Token: TOKEN" "http://IP:8787/apk?pkg=PKG&path=/data/app/.../base.apk" -o base.apk

# 5) Pull a native so
curl -H "X-Token: TOKEN" "http://IP:8787/libs?pkg=PKG"
curl -H "X-Token: TOKEN" "http://IP:8787/libs?pkg=PKG&path=/data/app/.../lib/arm64/libfoo.so" -o libfoo.so

# 6) Read any file
curl -H "X-Token: TOKEN" "http://IP:8787/file?path=/system/build.prop"

# 7) procfs
curl -H "X-Token: TOKEN" "http://IP:8787/proc?pid=1&what=status"

# 8) Whitelisted shell
curl -H "X-Token: TOKEN" -X POST "http://IP:8787/shell" \
     -d '{"argv":["getprop","ro.product.model"]}'
```

**M1 acceptance criteria**: from the PC, using curl with a token, you can pull any app's complete APK (including all splits) and native `.so` to your local machine — equivalent to `adb pull` but without depending on adb authorization.

---

## Static Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| GET  | `/health` | Liveness probe (name/version/pid/uptime) |
| GET  | `/packages` | List installed apps (package name / versionCode / path / whether system app) |
| GET  | `/apk?pkg=` | List all apk paths for the app (base + split); add `&path=` to stream-download a single one |
| GET  | `/file?path=` | Root stream-read any file (absolute path) |
| GET  | `/libs?pkg=` | List native `.so` under the app's lib directory; add `&path=` to download a single one |
| GET  | `/proc?pid=&what=maps\|status\|cmdline` | Forward procfs |
| POST | `/shell` | Whitelisted command execution, body: `{"argv":[...]}` or `{"cmd":"..."}` |

Authentication: one of three — request header `X-Token: <token>`, `Authorization: Bearer <token>`, or query parameter `?token=<token>`.

`/shell` whitelist: `id whoami getprop uname ls cat stat du df md5sum sha1sum sha256sum pm cmd dumpsys ps getenforce settings wc head tail ip netstat pgrep mount readlink basename dirname find date`. It does not go through `sh -c`; it calls `execvp` directly and rejects anything outside the whitelist.

---

## Security Notes

- The port is **closed by default**, only opened manually by the user in the WebUI and closed manually when done; it returns to closed after reboot.
- All endpoints use token authentication; the token is randomly generated at startup (16 bytes hex).
- By default it binds to the `wlan0` LAN IP (`bind=auto`), not `0.0.0.0`; if none is detected it falls back to `0.0.0.0` with a warning. The bind address can be changed in the **WebUI → "Network Settings" → "Bind Address"** (`auto` / `0.0.0.0` / a specific IP / `127.0.0.1`). Note that connecting in adb mode automatically sets it to `127.0.0.1`.
- The device side only does data transport and contains no app-specific logic (per the design principle in `ndde.md`).

## Runtime Files

`/data/adb/reconbridge/`:
- `config.conf` — `enabled` / `port` / `bind` / `token`
- `daemon.log` — daemon log

## Known Limitations (M1)

- `/packages`'s "version" uses `versionCode` (a single `pm` call, fast); `versionName` requires `dumpsys` and is not included in M1.
- `/libs` only lists **extracted** `.so` files; if the app has `extractNativeLibs=false`, the `.so` lives inside the apk at `lib/arm64-v8a/` — pull the package via `/apk` and unpack locally (the endpoint hints this in `note`).
- `/shell`'s `cmd` string is split naively on whitespace and does not support quotes; use the `argv` array form for complex commands.
