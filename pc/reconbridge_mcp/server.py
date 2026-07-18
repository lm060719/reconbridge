"""ReconBridge MCP Server —— 把 M1 静态接口 + PC 本地反编译工具链暴露为 Claude Code 可调用的工具。

传输：stdio。运行：`python -m reconbridge_mcp`（见 __main__.py）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .client import ReconError, client
from .settings import settings
from . import external

mcp = FastMCP("reconbridge")


def _pkg_dir(package_name: str, sub: str) -> Path:
    d = settings.workdir / package_name / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


# =====================================================================
# 设备原子工具（封装 M1 HTTP 接口）
# =====================================================================

@mcp.tool()
def device_status() -> dict:
    """探测手机守护进程状态与连接方式，返回 /health 及当前传输配置。用于排查连不上的问题。"""
    health = client.get_json("/health")
    return {
        "transport": settings.transport,
        "base_url": client._base,  # noqa: SLF001 便于诊断
        "health": health,
    }


@mcp.tool()
def list_packages(name_filter: str = "", only_third_party: bool = False) -> dict:
    """列出设备上已安装应用（包名 / versionCode / 安装路径 / 是否系统应用）。

    name_filter: 只保留包名包含该子串的（不区分大小写）；空则不过滤。
    only_third_party: True 时只返回非系统应用。
    """
    data = client.get_json("/packages")
    pkgs = data.get("packages", [])
    nf = name_filter.lower()
    out = []
    for p in pkgs:
        if only_third_party and p.get("system"):
            continue
        if nf and nf not in p.get("package", "").lower():
            continue
        out.append(p)
    return {"count": len(out), "total_installed": data.get("count"), "packages": out}


@mcp.tool()
def pull_apk(package_name: str) -> dict:
    """拉取某应用的**全部** apk（base.apk + 所有 split_config.*.apk）到 PC 工作目录。

    返回本地文件路径列表；等价 adb pull 但走 reconbridge，不依赖 adb 授权。
    """
    info = client.get_json("/apk", {"pkg": package_name})
    apks = info.get("apks", [])
    if not apks:
        raise ReconError(f"{package_name} 无 apk 或未安装")
    dest_dir = _pkg_dir(package_name, "apk")
    results = []
    for a in apks:
        remote = a["path"]
        dest = dest_dir / a["name"]
        n = client.download("/apk", {"pkg": package_name, "path": remote}, dest)
        ok = (a.get("size", -1) in (-1, n))
        results.append({"name": a["name"], "local_path": str(dest),
                        "bytes": n, "remote_size": a.get("size"), "size_match": ok})
    return {"package": package_name, "count": len(results),
            "dir": str(dest_dir), "files": results}


@mcp.tool()
def pull_libs(package_name: str) -> dict:
    """拉取某应用 lib 目录下已落地的 native .so 到 PC 工作目录。

    若应用 extractNativeLibs=false，可能没有落地 so（此时用 pull_apk 拉包后本地解包 lib/arm64-v8a/）。
    """
    info = client.get_json("/libs", {"pkg": package_name})
    libs = info.get("libs", [])
    dest_dir = _pkg_dir(package_name, "libs")
    results = []
    for so in libs:
        dest = dest_dir / so["name"]
        n = client.download("/libs", {"pkg": package_name, "path": so["path"]}, dest)
        results.append({"name": so["name"], "local_path": str(dest), "bytes": n})
    return {"package": package_name, "count": len(results), "dir": str(dest_dir),
            "note": info.get("note"), "files": results}


@mcp.tool()
def read_remote_file(path: str, save_as: str = "", max_inline_kb: int = 64) -> dict:
    """root 读取设备上任意文件（流式）。

    path: 设备绝对路径。
    save_as: PC 本地保存路径；为空时存到工作目录 files/ 下。
    小于 max_inline_kb 且疑似文本时，附带内联内容预览。
    """
    dest = Path(save_as) if save_as else (settings.workdir / "files" / Path(path).name)
    n = client.download("/file", {"path": path}, dest)
    result: dict[str, Any] = {"remote_path": path, "local_path": str(dest), "bytes": n}
    if n <= max_inline_kb * 1024:
        raw = dest.read_bytes()
        try:
            result["text"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            result["text"] = None
            result["hint"] = "二进制文件，未内联；见 local_path"
    return result


@mcp.tool()
def proc_info(pid: int, what: str = "status") -> dict:
    """读取 /proc/<pid>/<what>，what ∈ maps|status|cmdline。"""
    text = client.get_text("/proc", {"pid": str(pid), "what": what})
    return {"pid": pid, "what": what, "content": text}


@mcp.tool()
def remote_shell(argv: Optional[list[str]] = None, cmd: str = "") -> dict:
    """在设备上以 root 执行**白名单内**命令。优先用 argv 数组（安全，无需引号）。

    白名单：id whoami getprop uname ls cat stat du df md5sum sha1sum sha256sum
            pm cmd dumpsys ps getenforce settings wc head tail ip netstat pgrep
            mount readlink basename dirname find date。白名单外返回 403。
    """
    body: dict[str, Any] = {}
    if argv:
        body["argv"] = argv
    elif cmd:
        body["cmd"] = cmd
    else:
        raise ReconError("需要 argv 或 cmd")
    return client.post_json("/shell", body)


# =====================================================================
# PC 本地反编译工具链（详见 external.py）
# =====================================================================

@mcp.tool()
def decompile_apk(apk_path: str, output_dir: str = "") -> dict:
    """用 jadx 反编译 apk 到 Java 源码目录，返回反编译输出目录。

    apk_path: 本地 apk（用 pull_apk 拉下来的 base.apk）。
    output_dir: 输出目录；为空时放到 apk 同级的 jadx-out/。
    """
    return external.decompile_apk(apk_path, output_dir)


@mcp.tool()
def dexkit_search(apk_path: str, query: dict) -> dict:
    """用 DexKit 在 apk 的 dex 里做链式查询（定位类/方法/字段）。

    query 为结构化查询描述，支持的形式见 external.py 文档；例如：
      {"find": "method", "method_name": "encrypt"}
      {"find": "method", "using_strings": ["sign", "md5"]}
      {"find": "class", "class_name": "SecurityUtil"}
    """
    return external.dexkit_search(apk_path, query)


@mcp.tool()
def ghidra_analyze(so_path: str, options: Optional[dict] = None) -> dict:
    """用 Ghidra headless 分析 .so，返回导出表 / 导入表 / 字符串 / 函数列表 / 可疑函数。

    options: {"strings_min_len": 5, "max_functions": 400, "decompile": ["symbol1", 0x1234]}
             decompile 里给符号名或偏移可返回其反编译伪代码。
    """
    return external.ghidra_analyze(so_path, options or {})


@mcp.tool()
def hermes_decompile(bundle_path: str, output_dir: str = "") -> dict:
    """反编译 React Native Hermes 字节码 .hbc（通常在 apk 的 assets/index.android.bundle）。"""
    return external.hermes_decompile(bundle_path, output_dir)


# =====================================================================
# 动态 hook / dump（M3 / M4）—— 封装守护进程动态接口
# =====================================================================

@mcp.tool()
def post_hook(config: dict) -> dict:
    """下发 hook 配置（M3）。config 见 m3/HOOK_PROTOCOL.md：
    {package, restart?, targets:[{id,lib,symbol|offset,capture:{args,ret,backtrace,dump},action}]}。
    注入在目标下次启动时生效（restart:true 会 force-stop 目标触发重注入）。
    """
    return client.post_json("/hook", config)


@mcp.tool()
def list_hooks() -> dict:
    """列出当前已下发的 hook 配置。"""
    return client.get_json("/hooks")


@mcp.tool()
def unhook(package: str, hook_id: str = "") -> dict:
    """移除某包的 hook：不给 hook_id 则移除该包全部；给了则只移除该 id。"""
    body = {"package": package}
    if hook_id:
        body["id"] = hook_id
    return client.post_json("/unhook", body)


@mcp.tool()
def collect_events(seconds: float = 10.0, max_events: int = 200) -> dict:
    """连 hook 事件流(SSE)收集 seconds 秒内的命中事件（参数/返回值/调用栈/dump 通知）。

    先 post_hook 下发配置并启动/重启目标，再调用本工具采集。
    """
    evts = client.collect_sse(seconds=seconds, max_events=max_events)
    return {"count": len(evts), "seconds": seconds, "events": evts}


@mcp.tool()
def dump_dex(package: str, symbol: str = "", offset: str = "", base_arg: int = 0,
             size_arg: int = 1, lib: str = "libart.so", restart: bool = True) -> dict:
    """通用内存 dex dump（M4）：hook dex 加载入口，把内存中已解密的 dex 回传落盘。

    symbol/offset 指定入口（用 ghidra_analyze 分析 /system/lib64/libart.so 定位）；
    base_arg/size_arg 为 dex 基址/长度所在参数下标。命中后用 list_dumps / read_remote_file 取回。
    """
    body: dict[str, Any] = {"package": package, "lib": lib, "base_arg": base_arg,
                            "size_arg": size_arg, "restart": restart}
    if symbol:
        body["symbol"] = symbol
    if offset:
        body["offset"] = offset
    return client.post_json("/dump_dex", body)


@mcp.tool()
def list_dumps() -> dict:
    """列出已落盘的内存 dump（用 read_remote_file 或 pull 取回）。"""
    return client.get_json("/dumps")


@mcp.tool()
def toolchain_status() -> dict:
    """检查 PC 本地反编译工具链（jadx / DexKit / Ghidra / Hermes）是否就绪及其路径。"""
    return external.toolchain_status()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
