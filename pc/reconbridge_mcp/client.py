"""与手机 M1 守护进程通信的 HTTP 客户端。

两种传输：
  - adb：经 USB。自动读取设备 token、把守护进程绑到设备 127.0.0.1、开启端口、建立 adb forward，
          然后所有请求打到本机 127.0.0.1:<port>。localhost-only，不暴露到局域网，安全且免配置。
  - wifi：直接用 RECONBRIDGE_URL + RECONBRIDGE_TOKEN 访问局域网内的设备。
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Optional

import httpx

from .settings import settings


class ReconError(RuntimeError):
    pass


# 调用栈里属于 hook 框架 / 反射派发的噪音帧标记：栈顶连续命中这些的会被折叠，
# 让调用方一眼看到真正的业务 caller（见 P1-5）。可用 raw_stack=True 关闭折叠。
_HOOK_FRAME_MARKERS = (
    "com.reconbridge.tracer",          # 本模块的 TraceCallback.emit 等
    "de.robv.android.xposed",          # XposedBridge / XC_MethodHook
    "XposedBridge",
    "XC_MethodHook",
    "LSPHooker_",                      # LSPosed 生成的 hooker 类
    "java.lang.reflect.Method.invoke",  # 反射派发
    "java.lang.reflect.Constructor.newInstance",
)


def _fold_stack(evt: Any) -> Any:
    """折叠事件调用栈顶部连续的 hook 框架帧。非命中/无 stack 的事件原样返回。"""
    if not isinstance(evt, dict):
        return evt
    st = evt.get("stack")
    if not isinstance(st, list) or not st:
        return evt
    i = 0
    while i < len(st) and isinstance(st[i], str) and any(m in st[i] for m in _HOOK_FRAME_MARKERS):
        i += 1
    if i <= 0:
        return evt
    out = dict(evt)
    out["stack"] = [f"…（{i} 个 hook 框架帧已折叠）"] + st[i:]
    out["stack_folded"] = i
    return out


class ReconClient:
    def __init__(self) -> None:
        self._ready = False
        self._base: str = ""
        self._token: str = settings.token
        self._serial: str = settings.serial  # 多设备时自动解析（见 _resolve_serial）

    # ---------------- adb 辅助 ----------------
    def _adb(self, *args: str, check: bool = True, timeout: int = 30) -> str:
        cmd = [settings.adb]
        if self._serial:
            cmd += ["-s", self._serial]
        cmd += list(args)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        if check and p.returncode != 0:
            raise ReconError(f"adb 失败: {' '.join(args)}\n{p.stderr.strip() or p.stdout.strip()}")
        return p.stdout

    def _su(self, script: str, timeout: int = 60) -> str:
        """在设备上以 root 执行一段 sh。"""
        return self._adb("shell", "su", "-c", script, timeout=timeout)

    def _resolve_serial(self) -> None:
        """未显式指定 serial 时，自动挑选唯一在线设备，忽略 offline/unauthorized 残留链路。

        解决多链路（如残留的 adb-...tls-connect offline 链路）导致 `more than one device`
        直接失败、要人工 `adb disconnect` 的摩擦（P1-4）。多台在线时报清单让用户选。
        """
        if self._serial:
            return
        out = subprocess.run([settings.adb, "devices"], capture_output=True, text=True,
                             timeout=15, encoding="utf-8", errors="replace").stdout
        online, other = [], []
        for line in out.splitlines()[1:]:
            line = line.rstrip()
            if not line or "\t" not in line:
                continue
            serial, state = line.split("\t", 1)
            state = state.strip()
            if state == "device":
                online.append(serial)
            else:
                other.append(f"{serial}({state})")
        if len(online) == 1:
            self._serial = online[0]
        elif not online:
            hint = ("；被忽略的链路：" + ", ".join(other)) if other else ""
            raise ReconError(f"没有在线设备（adb devices 无 device 状态项）{hint}")
        else:
            raise ReconError(
                "检测到多台在线设备：" + ", ".join(online) +
                "；请设 RECONBRIDGE_SERIAL 指定其一" +
                (f"（已忽略离线链路：{', '.join(other)}）" if other else ""))

    # ---------------- 连接建立（幂等） ----------------
    def ensure(self) -> None:
        if self._ready:
            return
        if settings.transport == "wifi":
            if not settings.url or not settings.token:
                raise ReconError("wifi 模式需要 RECONBRIDGE_URL 和 RECONBRIDGE_TOKEN")
            self._base = settings.url.rstrip("/")
            self._token = settings.token
        else:
            self._ensure_adb()
        # 探活
        self._ready = True
        try:
            self.get_json("/health")
        except Exception as e:
            self._ready = False
            raise ReconError(f"无法连接守护进程：{e}")

    def _ensure_adb(self) -> None:
        # 0) 多设备/离线链路自动处理：挑唯一在线设备
        self._resolve_serial()
        # 1) 读取设备端 token / port（若守护进程尚未生成 config，尝试 start 一次）
        conf = self._su(f"cat {settings.device_conf} 2>/dev/null || true")
        kv = {}
        for line in conf.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
        if not kv.get("token"):
            # 拉起守护进程让它生成 token
            self._su(f"sh {settings.rbctl} start")
            import time
            time.sleep(1.5)
            conf = self._su(f"cat {settings.device_conf} 2>/dev/null || true")
            kv = {}
            for line in conf.splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
        token = kv.get("token", "")
        if not token:
            raise ReconError("无法从设备读取 token，请确认 reconbridge 模块已安装并重启过")
        port = int(kv.get("port", settings.port) or settings.port)

        # 2) 绑到设备 127.0.0.1 并开启端口（localhost-only，经 forward 访问）
        self._su(f"sh {settings.rbctl} setbind 127.0.0.1")
        self._su(f"sh {settings.rbctl} enable")
        import time
        time.sleep(1.2)

        # 3) 建立 adb forward
        self._adb("forward", f"tcp:{port}", f"tcp:{port}")

        self._base = f"http://127.0.0.1:{port}"
        self._token = token

    # ---------------- HTTP ----------------
    @property
    def _headers(self) -> dict:
        return {"X-Token": self._token}

    def get_json(self, path: str, params: Optional[dict] = None) -> Any:
        self.ensure()
        with httpx.Client(timeout=settings.timeout) as c:
            r = c.get(self._base + path, params=params, headers=self._headers)
        if r.status_code != 200:
            raise ReconError(f"GET {path} -> {r.status_code}: {r.text[:300]}")
        return r.json()

    def get_text(self, path: str, params: Optional[dict] = None) -> str:
        self.ensure()
        with httpx.Client(timeout=settings.timeout) as c:
            r = c.get(self._base + path, params=params, headers=self._headers)
        if r.status_code != 200:
            raise ReconError(f"GET {path} -> {r.status_code}: {r.text[:300]}")
        return r.text

    def post_json(self, path: str, body: Any) -> Any:
        self.ensure()
        with httpx.Client(timeout=settings.timeout) as c:
            r = c.post(self._base + path, json=body, headers=self._headers)
        if r.status_code not in (200, 504):
            raise ReconError(f"POST {path} -> {r.status_code}: {r.text[:300]}")
        return r.json()

    def download(self, path: str, params: dict, dest: Path) -> int:
        """流式下载到 dest，返回字节数。"""
        self.ensure()
        dest.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        with httpx.Client(timeout=settings.timeout) as c:
            with c.stream("GET", self._base + path, params=params, headers=self._headers) as r:
                if r.status_code != 200:
                    raise ReconError(f"下载 {path} -> {r.status_code}: {r.read()[:300]!r}")
                with open(dest, "wb") as f:
                    for chunk in r.iter_bytes(1 << 16):
                        f.write(chunk)
                        total += len(chunk)
        return total

    def collect_sse(self, seconds: float = 10.0, max_events: int = 200,
                    until_first_hit: bool = False, until_n_events: int = 0,
                    linger_ms: int = 350, fold_stack: bool = True) -> list:
        """连 /events(SSE) 收集 hook 命中事件，返回事件（dict）列表。

        - seconds: 采集窗口上限（兜底）。
        - until_first_hit / until_n_events: 早返回阈值——命中即返回，不空等满窗口（P0-1）。
          “命中”= 带 hook_id 的事件（dump_saved 等通知不计）。达阈值后再等 linger_ms 收拢
          同批到达的事件（如同一次调用的 before+after、多目标齐发），避免只拿到半批。
        - fold_stack: 折叠调用栈顶部的 hook 框架帧（P1-5），raw 需求可传 False。

        实现说明：SSE 阻塞读放到后台线程，主线程按 wall-clock 轮询阈值，达标即刻返回并
        强制关闭底层连接——这样“命中即返回”真正是秒级，而不必等下一个 ~15s 保活 ping 才醒。
        """
        import json as _json
        import threading
        import time

        self.ensure()
        events: list = []
        hits = 0
        lock = threading.Lock()
        stop = threading.Event()
        holder: dict[str, Any] = {}

        def reader() -> None:
            nonlocal hits
            try:
                c = httpx.Client(timeout=httpx.Timeout(seconds + 20, read=None))
                holder["client"] = c
                with c.stream("GET", self._base + "/events", headers=self._headers) as r:
                    holder["resp"] = r
                    for line in r.iter_lines():
                        if stop.is_set():
                            break
                        if not line.startswith("data: "):
                            continue  # ": ping" 保活注释等，跳过
                        payload = line[6:].strip()
                        if not payload:
                            continue
                        try:
                            evt: Any = _json.loads(payload)
                        except Exception:
                            evt = payload
                        if fold_stack:
                            evt = _fold_stack(evt)
                        with lock:
                            events.append(evt)
                            if isinstance(evt, dict) and "hook_id" in evt:
                                hits += 1
            except Exception:
                pass
            finally:
                try:
                    if holder.get("client") is not None:
                        holder["client"].close()
                except Exception:
                    pass

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        deadline = time.time() + seconds
        stop_deadline: Optional[float] = None
        want_early = until_first_hit or until_n_events > 0
        threshold = until_n_events if until_n_events > 0 else 1
        while True:
            time.sleep(0.05)
            now = time.time()
            with lock:
                n_ev, n_hit = len(events), hits
            if want_early and n_hit >= threshold and stop_deadline is None:
                stop_deadline = now + linger_ms / 1000.0
            if now > deadline or n_ev >= max_events:
                break
            if stop_deadline is not None and now >= stop_deadline:
                break

        # 令后台线程尽快退出：关连接以打断阻塞的 iter_lines
        stop.set()
        for key in ("resp", "client"):
            try:
                obj = holder.get(key)
                if obj is not None:
                    obj.close()
            except Exception:
                pass
        with lock:
            return list(events)

    def disable_port(self) -> None:
        """收尾：关闭设备端口（仅 adb 模式有意义）。"""
        if settings.transport == "adb":
            try:
                self._su(f"sh {settings.rbctl} disable")
            except Exception:
                pass


client = ReconClient()
