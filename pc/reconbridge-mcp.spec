# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 配方：把 ReconBridge MCP server 打成 onedir 可执行目录。
#
# onedir（非 onefile）：产物是 dist/reconbridge-mcp/ 目录（含 reconbridge-mcp.exe + _internal/）。
# MCP server 每次 Claude Code 启动都会被拉起，onedir 无每次解压临时目录的开销，冷启动快、
# 也不易被杀软误报。build_exe.ps1 随后把该目录打成 zip 发布。
#
# 关键依赖 androguard / mcp 有大量动态导入与数据文件，用 collect_all 一网打尽。

from PyInstaller.utils.hooks import (
    collect_all, collect_submodules, collect_data_files, collect_dynamic_libs,
    copy_metadata,
)

datas = []
binaries = []
hiddenimports = []

# mcp：可安全 collect_all（FastMCP 有动态导入，一网打尽）
_d, _b, _h = collect_all("mcp")
datas += _d
binaries += _b
hiddenimports += _h

# androguard：dexkit_search 的 dex 搜索后端。注意——collect_submodules("androguard") 会用
# pkgutil.walk_packages 递归 import 每个子包来发现其 __path__，途中会 import androguard.pentest，
# 它 `import frida`（未装）失败后直接调用 exit() 抛 SystemExit——SystemExit 不被 walk 的 onerror
# 捕获，导致 PyInstaller 收集子进程崩溃（filter 只过滤结果、拦不住这次 import）。
# pentest / ui / cli 是 frida+Qt 的 GUI/CLI 工具，AnalyzeAPK 用不到。故只收安全子包，
# 绝不走顶层 androguard 的 walk；数据资源（api 映射表等）与动态库单独收（只 import 顶层，安全）。
hiddenimports += collect_submodules("androguard.core")
hiddenimports += collect_submodules("androguard.decompiler")
hiddenimports += ["androguard.misc", "androguard.session",
                  "androguard.util", "androguard.message"]
datas += collect_data_files("androguard")
binaries += collect_dynamic_libs("androguard")
# 打进 .dist-info 元数据：toolchain_status 用 importlib.metadata.version("androguard") 探测版本，
# PyInstaller 默认不带 dist-info，缺了会 PackageNotFoundError → 报成 androguard 缺失。
datas += copy_metadata("androguard")

# httpx / anyio：MCP stdio 传输与 HTTP client 走它们；子模块补全避免漏收
hiddenimports += collect_submodules("httpx")
hiddenimports += collect_submodules("anyio")
hiddenimports += ["reconbridge_mcp", "reconbridge_mcp.server",
                  "reconbridge_mcp.register", "reconbridge_mcp.client",
                  "reconbridge_mcp.external", "reconbridge_mcp.settings"]

block_cipher = None

a = Analysis(
    ["mcp_entry.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PyQt5", "PySide2", "IPython"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="reconbridge-mcp",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="reconbridge-mcp",
)
