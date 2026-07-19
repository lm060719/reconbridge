"""ReconBridge MCP Server —— 把 M1 静态接口 + PC 本地反编译工具链暴露为 Claude Code 可调用的工具。

传输：stdio。运行：`python -m reconbridge_mcp`（见 __main__.py）。
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .client import ReconError, client, _fold_stack
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
def collect_events(seconds: float = 10.0, max_events: int = 200,
                   until_first_hit: bool = False, until_n_events: int = 0,
                   fold_stack: bool = True,
                   include_recent: bool = False, since_seq: int = 0,
                   quiet_ms: int = 0) -> dict:
    """连 hook 事件流(SSE)收集命中事件（参数/返回值/调用栈/dump 通知）。

    先 post_hook 下发配置并启动/重启目标，再调用本工具采集。

    - seconds: 采集窗口上限（兜底）。
    - until_first_hit=True: **命中即返回**，不空等满窗口（消除“掐点说话”，见 P0-1）；
      until_n_events=N: 收满 N 条命中即返回。二者任一达标即刻返回（+短暂收拢同批事件）。
    - include_recent=True: **事后采集**——先从守护进程环形缓冲补捞历史命中（P0-1），命中即便
      发生在本次采集开始之前也能拿到，并可立刻满足早返回；since_seq 只取该游标之后的增量。
    - fold_stack=True: 折叠调用栈顶部的 hook 框架帧，直接看到真实 caller（raw 传 False）。
    """
    evts = client.collect_sse(seconds=seconds, max_events=max_events,
                              until_first_hit=until_first_hit, until_n_events=until_n_events,
                              fold_stack=fold_stack, include_recent=include_recent,
                              since_seq=since_seq, quiet_ms=quiet_ms)
    return {"count": len(evts), "seconds": seconds,
            "early_return": bool(until_first_hit or until_n_events), "events": evts}


# =====================================================================
# 场景捕获 + 差分（P2）—— 把"A 与 B 行为为何不同"做成一等公民
# =====================================================================

_SCEN_DIR = settings.workdir / "scenarios"


def _scenario_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)[:64] or "scenario"
    _SCEN_DIR.mkdir(parents=True, exist_ok=True)
    return _SCEN_DIR / f"{safe}.json"


def _sig(e: Any) -> Optional[str]:
    """方法签名（用于分组/比对）：优先 hook_id（稳定，一目标一 id），否则 class.method。"""
    if not isinstance(e, dict):
        return None
    return e.get("hook_id") or f"{e.get('class', '?')}.{e.get('method', '?')}"


def _display(e: Any) -> str:
    return f"{e.get('class', '?')}.{e.get('method', '?')}" if isinstance(e, dict) else "?"


def _fp(e: Any) -> str:
    """事件的"值指纹"：拼参数/返回值/路径/字段的值，用于判断两场景同一方法参数是否不同。"""
    if not isinstance(e, dict):
        return ""
    parts = []
    for a in (e.get("args") or []):
        parts.append(f"a{a.get('index')}={a.get('value')}")
    if "ret" in e:
        parts.append(f"ret={e.get('ret')}")
    for p in (e.get("paths") or []):
        parts.append(f"{p.get('path')}={p.get('value')}")
    for f in (e.get("fields") or []):
        parts.append(f"{f.get('name')}={f.get('value')}")
    return " | ".join(parts)


@mcp.tool()
def capture_scenario(name: str, seconds: float = 20.0, quiet_ms: int = 1500,
                     max_events: int = 500, fold_stack: bool = True) -> dict:
    """记录一个「场景」的命中时间线，存盘供 diff_scenarios 比对（P2）。

    前提：先用 post_hook / trace_java arm 好一组（通常较宽的）hook，目标进程已带这些 hook 运行。
    调用本工具后**在窗口内做一次目标操作**（如「查看X」）；抓完这一波（连续 quiet_ms 无新事件即停）
    后存盘到 work/scenarios/<name>.json。

    典型流程：arm 宽 trace → capture_scenario("A") 做操作A → capture_scenario("B") 做操作B
              → diff_scenarios("A","B") 直接看出两者方法/参数差异。
    - quiet_ms: 命中后静默这么久即认为本波结束返回（0=不早停，跑满 seconds）。
    """
    cursor = client.get_recent(limit=0).get("latest_seq", 0)
    evts = client.collect_sse(seconds=seconds, max_events=max_events, fold_stack=fold_stack,
                              include_recent=True, since_seq=cursor, quiet_ms=quiet_ms)
    store = {"name": name, "captured_at": int(time.time() * 1000),
             "since_seq": cursor, "count": len(evts), "events": evts}
    path = _scenario_path(name)
    path.write_text(json.dumps(store, ensure_ascii=False, indent=1), encoding="utf-8")
    methods: dict[str, int] = {}
    for e in evts:
        s = _sig(e)
        if s:
            methods[s] = methods.get(s, 0) + 1
    return {"name": name, "count": len(evts), "distinct_methods": len(methods),
            "methods": methods, "saved": str(path),
            "note": ("空命中——确认已 arm hook 且窗口内确实触发了操作" if not evts else "")}


@mcp.tool()
def list_scenarios() -> dict:
    """列出已捕获的场景（work/scenarios/ 下）及各自命中数。"""
    out = []
    if _SCEN_DIR.is_dir():
        for p in sorted(_SCEN_DIR.glob("*.json")):
            try:
                s = json.loads(p.read_text(encoding="utf-8"))
                out.append({"name": s.get("name", p.stem), "count": s.get("count"),
                            "captured_at": s.get("captured_at"), "path": str(p)})
            except Exception:
                continue
    return {"count": len(out), "scenarios": out}


@mcp.tool()
def diff_scenarios(a: str, b: str) -> dict:
    """比对两个已捕获场景，给出**方法级差异**（P2）——直接回答"A 与 B 行为为何不同"。

    返回：只在 A 命中的方法 / 只在 B 命中的方法 / 两者都命中但**参数值不同**的方法。
    命中最常见的一类逆向：如「查看X」跳转而「打开X」不跳、App 对话渲染答案卡而悬浮窗不渲染。
    """
    pa, pb = _scenario_path(a), _scenario_path(b)
    if not pa.exists():
        raise ReconError(f"场景 {a} 不存在（先 capture_scenario('{a}')）")
    if not pb.exists():
        raise ReconError(f"场景 {b} 不存在（先 capture_scenario('{b}')）")
    sa = json.loads(pa.read_text(encoding="utf-8"))
    sb = json.loads(pb.read_text(encoding="utf-8"))

    def index(scn: dict) -> dict:
        d: dict[str, dict] = {}
        for e in scn.get("events", []):
            s = _sig(e)
            if not s:
                continue
            slot = d.setdefault(s, {"display": _display(e), "count": 0, "fps": set()})
            slot["count"] += 1
            fp = _fp(e)
            if fp:
                slot["fps"].add(fp)
        return d

    ia, ib = index(sa), index(sb)
    only_a = [{"method": ia[s]["display"], "sig": s, "hits": ia[s]["count"]}
              for s in ia if s not in ib]
    only_b = [{"method": ib[s]["display"], "sig": s, "hits": ib[s]["count"]}
              for s in ib if s not in ia]
    both, differing = [], []
    for s in ia:
        if s not in ib:
            continue
        both.append({"method": ia[s]["display"], "sig": s,
                     "a_hits": ia[s]["count"], "b_hits": ib[s]["count"]})
        if ia[s]["fps"] != ib[s]["fps"]:
            av = sorted(ia[s]["fps"] - ib[s]["fps"])[:8]
            bv = sorted(ib[s]["fps"] - ia[s]["fps"])[:8]
            if av or bv:
                differing.append({"method": ia[s]["display"], "sig": s,
                                  "only_in_a_values": av, "only_in_b_values": bv})
    return {"a": a, "b": b, "a_count": sa.get("count"), "b_count": sb.get("count"),
            "only_in_a": sorted(only_a, key=lambda x: -x["hits"]),
            "only_in_b": sorted(only_b, key=lambda x: -x["hits"]),
            "in_both": both, "differing_args": differing,
            "summary": (f"{len(only_a)} 个方法只在 A 命中、{len(only_b)} 个只在 B 命中、"
                        f"{len(differing)} 个两者都命中但参数不同")}


@mcp.tool()
def recent_events(limit: int = 50, since_seq: int = 0) -> dict:
    """取守护进程环形缓冲里**最近的命中事件**（事后采集，P0-1）——无需正连着 SSE。

    典型用法：post_hook 下发后先记下游标（recent_events(limit=0) 的 latest_seq），触发目标行为，
    再 recent_events(since_seq=<游标>) 补捞这期间的所有命中；或忘了开采集时直接捞最近若干条。
    返回 {latest_seq, count, events}；latest_seq 可作下次 since_seq 只取增量。
    """
    data = client.get_recent(limit=limit, since_seq=since_seq)
    evts = [_fold_stack(e) for e in data.get("events", [])]
    return {"latest_seq": data.get("latest_seq"), "count": len(evts), "events": evts}


@mcp.tool()
def trace_java(package: str, class_name: str, method: str,
               params: Optional[list] = None,
               args_render: str = "tostring",
               capture_args: Optional[list] = None,
               fields: Optional[list] = None,
               paths: Optional[list] = None,
               this: str = "class",
               ret: bool = True,
               when: str = "after",
               stack: bool = False,
               hook_id: str = "",
               debug: bool = False,
               restart: bool = True,
               seconds: float = 12.0,
               max_events: int = 200,
               until_first_hit: bool = False,
               until_n_events: int = 0,
               fold_stack: bool = True,
               include_recent: bool = False,
               since_seq: int = 0,
               hot: bool = False) -> dict:
    """一步下发一个 Java 方法 trace 并采集命中（M5）。

    需设备已装 **ReconBridge Tracer** LSPosed 模块并在 LSPosed 里启用 + 勾选目标 App 作用域。
    在目标进程用 XposedBridge hook `class_name.method`，实时回传 this/参数/返回值/字段/调用栈，
    走与 M3 相同的 socket→SSE 链路。协议见 m5/JAVA_HOOK_PROTOCOL.md。

    - params: 精确重载的参数类型全名列表（如 ["java.lang.String","java.lang.String"]）；
      省略=hook 所有同名重载；method="<init>" 则 hook 构造函数。
    - capture_args: 逐参数抓取 [{"index":0,"render":"tostring","max":2000}]；省略=按 tostring 抓全部参数。
    - fields: 反射读取的（私有）字段 [{"target":"this","name":"Z3","render":"tostring"}]。
    - paths: **嵌套字段路径捕获**（P0-3），直接拿深埋在 payload 对象里的值，不靠 toString 撞运气：
      [{"path":"args[1].payload.load_url","render":"tostring","max":2000}]。
      路径语法 args[N]/this/ret 起头，`.name` 逐层（反射字段→getter→Map key），`[n]` 索引数组/List；
      裸字段名等价 this.<name>。解析不到的段返回 {"unresolved":true}。
    - this: this 渲染 class|tostring|none；when: before|after|both。
    - render: tostring|class|json|**deep**（deep=反射把对象图深度序列化成 JSON，带深度/环/节点预算防爆）。

    注意：模块在进程启动时读配置，故对已运行的目标需 restart=True（force-stop 触发重载），
    之后在 seconds 窗口内手动触发目标行为（如唤起小爱问一句）即可收到命中。

    - until_first_hit=True / until_n_events=N: **命中即返回**，不空等满窗口（P0-1）；
      对“重启目标→手动触发一次→拿到命中”的迭代尤其省时，无需再和窗口掐点。
    - fold_stack=True: 折叠调用栈顶部 hook 框架帧，直接看到真实 caller。
    - hot=True: **免重启热加**（P0-2）——若目标进程在跑，直接往运行中的进程增量追加这个 hook
      （restart 强制置 False + mode:append），**不 force-stop、不用重新唤醒/重说**。返回的 posted.note /
      hot_injected 会告诉你热注入了几个进程；为 0 说明目标没在跑（配置会在下次启动生效）。
      需设备装的是**支持热加的 tracer**（新版 APK）；旧版或 native 目标不响应热加，仍需 restart。
    """
    capture: dict[str, Any] = {"this": this, "when": when, "stack": stack}
    if capture_args is not None:
        capture["args"] = capture_args
    else:
        capture["all_args"] = True
    if ret:
        capture["ret"] = {"capture": True, "render": args_render}
    if fields:
        capture["fields"] = fields
    if paths:
        capture["paths"] = paths
    target: dict[str, Any] = {
        "kind": "java",
        "id": hook_id or f"{class_name.rsplit('.', 1)[-1]}_{method}",
        "class": class_name,
        "method": method,
        "capture": capture,
    }
    if params is not None:
        target["params"] = params
    config: dict[str, Any] = {"package": package, "restart": restart, "debug": debug,
                              "targets": [target]}
    if hot:
        config["restart"] = False   # 热加：不 force-stop
        config["mode"] = "append"   # 增量合并进现有配置
    posted = client.post_json("/hook", config)
    evts = client.collect_sse(seconds=seconds, max_events=max_events,
                              until_first_hit=until_first_hit, until_n_events=until_n_events,
                              fold_stack=fold_stack, include_recent=include_recent,
                              since_seq=since_seq)
    return {"posted": posted, "count": len(evts), "seconds": seconds,
            "early_return": bool(until_first_hit or until_n_events), "events": evts}


@mcp.tool()
def patch_java(package: str, class_name: str, method: str,
               params: Optional[list] = None,
               replace_args: Optional[list] = None,
               replace_return: Optional[dict] = None,
               skip_original: bool = False,
               trace: bool = True,
               capture_args: Optional[list] = None,
               this: str = "class",
               when: str = "after",
               hook_id: str = "",
               debug: bool = False,
               restart: bool = True,
               seconds: float = 0.0,
               max_events: int = 100) -> dict:
    """实时篡改一个 Java 方法（M5 v2）：改参数 / 改返回值 / 跳过原方法。

    需设备已装 **ReconBridge Tracer** LSPosed 模块并启用+勾选目标作用域。篡改是**持久**的
    （下发后一直生效，直到 unhook）。协议见 m5/JAVA_HOOK_PROTOCOL.md。

    - replace_args: 进入原方法前覆盖参数，[{"index":1,"value":"新内容","type":"string"}]。
      type ∈ string|int|long|boolean|double|float|short|byte|char；省略 type 则按 JSON 原生类型。
    - replace_return: 覆盖返回值，{"value":0,"type":"int"}（对无 skip_original 时在 after 生效）。
    - skip_original: True 则不执行原方法，直接返回 replace_return（没给则返回 null）——用于“拦掉某调用”。
    - trace: True 同时把命中回传（含 tampered 标记）；想静默篡改设 trace=False（when=none）。
    - seconds>0 时下发后顺便采集命中；=0 只下发（篡改持续生效）。

    例：把某 String 参数换掉 → replace_args=[{"index":1,"value":"...","type":"string"}]；
        让某校验方法恒返回 true → replace_return={"value":true,"type":"boolean"}, skip_original=True。
    注意：模块进程启动时读配置，已运行目标需 restart=True。
    """
    target: dict[str, Any] = {
        "kind": "java",
        "id": hook_id or f"{class_name.rsplit('.', 1)[-1]}_{method}",
        "class": class_name,
        "method": method,
    }
    if params is not None:
        target["params"] = params
    cap: dict[str, Any] = {"this": this, "when": (when if trace else "none")}
    if capture_args is not None:
        cap["args"] = capture_args
    elif trace:
        cap["all_args"] = True
    if trace:
        cap["ret"] = {"capture": True, "render": "tostring"}
    target["capture"] = cap
    act: dict[str, Any] = {}
    if replace_args is not None:
        act["replace_args"] = replace_args
    if replace_return is not None:
        act["replace_return"] = replace_return
    if skip_original:
        act["skip_original"] = True
    if act:
        target["action"] = act
    config = {"package": package, "restart": restart, "debug": debug, "targets": [target]}
    posted = client.post_json("/hook", config)
    result: dict[str, Any] = {"posted": posted}
    if seconds and seconds > 0:
        evts = client.collect_sse(seconds=seconds, max_events=max_events)
        result.update({"count": len(evts), "seconds": seconds, "events": evts})
    return result


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
def list_artifacts(package_name: str = "") -> dict:
    """列出 PC 工作目录里某包（或全部包）已产出的物件：已拉的 apk、已拉的 native so、
    已反编译的 jadx 目录、已反编译的 Hermes 目录。免去“到底拉过/反编译过没有”的翻找（P1-6）。

    package_name 为空则枚举工作目录下所有包。路径可直接喂给 decompile_apk / ghidra_analyze。
    """
    base = settings.workdir

    def scan(pkg_dir: Path) -> dict:
        apk_dir = pkg_dir / "apk"
        libs_dir = pkg_dir / "libs"
        apks = sorted(str(p) for p in apk_dir.glob("*.apk")) if apk_dir.is_dir() else []
        libs = sorted(str(p) for p in libs_dir.glob("*.so")) if libs_dir.is_dir() else []
        # jadx 输出默认在 apk 同级的 "<stem>-jadx/"；Hermes 在 "<stem>-hermes/"
        jadx = sorted(str(p) for p in pkg_dir.rglob("*-jadx") if p.is_dir())
        hermes = sorted(str(p) for p in pkg_dir.rglob("*-hermes") if p.is_dir())
        return {
            "package": pkg_dir.name,
            "apks": apks,
            "libs": libs,
            "jadx_dirs": jadx,
            "hermes_dirs": hermes,
            "has_apk": bool(apks),
            "has_decompiled": bool(jadx),
        }

    if package_name:
        pkg_dir = base / package_name
        if not pkg_dir.is_dir():
            return {"package": package_name, "exists": False,
                    "note": "工作目录下无该包产出物；用 pull_apk / pull_libs 先拉取"}
        return {"exists": True, **scan(pkg_dir)}

    pkgs = []
    if base.is_dir():
        for d in sorted(base.iterdir()):
            if not d.is_dir() or d.name in ("files",):
                continue
            info = scan(d)
            if info["apks"] or info["libs"] or info["jadx_dirs"] or info["hermes_dirs"]:
                pkgs.append(info)
    return {"workdir": str(base), "count": len(pkgs), "packages": pkgs}


@mcp.tool()
def toolchain_status() -> dict:
    """检查 PC 本地反编译工具链（jadx / DexKit / Ghidra / Hermes）是否就绪及其路径。"""
    return external.toolchain_status()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
