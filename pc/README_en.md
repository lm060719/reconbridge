[中文](README.md) | **English**

# ReconBridge MCP Server (M2)

Wraps M1's device static endpoints + the PC-side local decompilation toolchain into MCP tools that Claude Code can call directly.

## Capability Overview (25 tools total)

> The table below lists M2's 12 atomic / decompilation capabilities; there are also M3/M5 dynamic hooks, Java trace, scenario capture, on-disk artifacts, etc. For the complete list see the repo root [`AGENTS_QUICKSTART.md`](../AGENTS_QUICKSTART.md).

**Device atomic capabilities (wrapping the M1 HTTP endpoints)**
| Tool | Purpose |
|------|---------|
| `device_status` | Probe the daemon /health and connection method |
| `list_packages` | List apps (supports name_filter / only_third_party) |
| `pull_apk` | Pull all apks (base+split) to the work directory, verify byte count |
| `pull_libs` | Pull native .so to the work directory |
| `read_remote_file` | Root-read any file (small text inlined) |
| `proc_info` | /proc/<pid>/{maps,status,cmdline} |
| `remote_shell` | Whitelisted root command |

**PC-side local decompilation toolchain**
| Tool | Backend | Purpose |
|------|---------|---------|
| `decompile_apk` | jadx | apk → Java source |
| `dexkit_search` | androguard | Locate classes/methods/fields/strings in dex (see query syntax below) |
| `ghidra_analyze` | Ghidra headless | .so export/import tables, strings, functions, suspicious functions, optional decompilation |
| `hermes_decompile` | hbctool (best-effort) | RN Hermes .hbc decompilation |
| `toolchain_status` | — | Check toolchain readiness |

> About DexKit: there is no official Windows/Python prebuilt package (removed from PyPI), so `dexkit_search` uses **androguard** as an equivalent dex-search backend, covering "locate classes/methods/fields/strings".

## Connection Method (transport)

- **adb (default, recommended)**: over USB. Automatically reads the device token, binds the daemon to the device's `127.0.0.1`, opens the port, and sets up `adb forward`; requests hit `127.0.0.1:8787` on the local machine. **localhost-only, not exposed to the LAN**, no manual token config.
- **wifi**: set `RECONBRIDGE_TRANSPORT=wifi` + `RECONBRIDGE_URL` + `RECONBRIDGE_TOKEN` to connect directly to a device on the LAN.

## Environment Setup

```powershell
cd pc
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

External tools (`toolchain_status` shows detection results):
- **jadx**: extract into `pc/tools/jadx` (bundled).
- **androguard**: `pip install androguard` (in requirements).
- **Ghidra + JDK21**: Ghidra 12 requires JDK21, and its **install path must be ASCII** (this project's directory contains Chinese characters, which crashes Ghidra's log4j). By default place it on the same drive at `<drive>:\ReconBridgeTools\` (e.g. `E:\ReconBridgeTools\ghidra_12.1.2_PUBLIC` and `jdk-21.x`). Override with `RECONBRIDGE_NATIVE_TOOLS`.

## Registering with Claude Code / ChatGPT Codex

**Recommended: one-line online install (packaged exe, no clone / venv)**
```powershell
irm https://github.com/lm060719/reconbridge/releases/latest/download/install.ps1 | iex
```
Downloads the packaged MCP exe to `%LOCALAPPDATA%\ReconBridge\` and self-registers. By default it auto-detects installed clients: Claude Code (`~/.claude.json`) and ChatGPT Codex (`~/.codex/config.toml`) — the one not installed is skipped, no directory created. Force-install only one with `$env:RB_TARGET="codex"` (or `"claude"`). Build the exe: repo root `./build_exe.ps1` (PyInstaller onedir → `dist/reconbridge-mcp-win64.zip`); the exe can self-register too: `reconbridge-mcp.exe --register [--target claude|codex|both] [--transport adb|wifi]`.

**Local web console**: `reconbridge-mcp --serve` (from source: `python -m reconbridge_mcp --serve`) starts a GUI console bound only to `127.0.0.1:9000` — pick adb/wifi, connect with one click, view daemon status and read-only monitoring (active hooks / event stream / dumps). Adjustable via `--port N` / `--host H` / `--no-open`.

**From source**: the project root already has `.mcp.json` (project-level config). Starting Claude Code in that directory prompts you to approve the `reconbridge` MCP server; once approved it's ready.

Manual method:
```powershell
claude mcp add reconbridge --env PYTHONPATH=<pc path> --env RECONBRIDGE_TRANSPORT=adb -- <venv>\Scripts\python.exe -m reconbridge_mcp
```

## `dexkit_search` Query Syntax

```jsonc
{"find":"method", "method_name":"onReceive"}          // by method name (plain name = substring match)
{"find":"method", "using_strings":["sms_code","sign"]} // methods that reference these strings (great for locating)
{"find":"class",  "class_name":"smscode"}              // by class name
{"find":"field",  "class_name":"Config","field_name":"token"}
{"find":"string", "string":"http"}                     // string constants in dex
// plain names match by substring; if they contain regex metacharacters they're treated as regex; you can add "max_results": N
```

## Self-Test

```powershell
.venv\Scripts\python test_mcp_e2e.py   # self-test over the real MCP stdio protocol
```

## M2 Acceptance

In Claude Code, a single sentence completes **pull package → decompile → locate class/method/so**, with no manual phone operation throughout.
For example: "Pull the package for `com.xxx`, decompile it, and find the methods doing signing/encryption and the related .so."

## Work Directory

Default `pc/work/<package>/`: `apk/` (pulled apks), `libs/` (.so), `*-jadx/` (decompiled source).
Override with `RECONBRIDGE_WORKDIR`.
