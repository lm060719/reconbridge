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


class ReconClient:
    def __init__(self) -> None:
        self._ready = False
        self._base: str = ""
        self._token: str = settings.token

    # ---------------- adb 辅助 ----------------
    def _adb(self, *args: str, check: bool = True, timeout: int = 30) -> str:
        cmd = [settings.adb]
        if settings.serial:
            cmd += ["-s", settings.serial]
        cmd += list(args)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        if check and p.returncode != 0:
            raise ReconError(f"adb 失败: {' '.join(args)}\n{p.stderr.strip() or p.stdout.strip()}")
        return p.stdout

    def _su(self, script: str, timeout: int = 60) -> str:
        """在设备上以 root 执行一段 sh。"""
        return self._adb("shell", "su", "-c", script, timeout=timeout)

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

    def collect_sse(self, seconds: float = 10.0, max_events: int = 200) -> list:
        """连 /events(SSE) 收集 seconds 秒内的 hook 命中事件，返回 JSON 字符串列表。"""
        import json as _json
        import time

        self.ensure()
        events: list = []
        deadline = time.time() + seconds
        # 注意：不要设激进的 read 超时。SSE 保活 ping 约 15s 一次，稀疏事件（如某个
        # Java 方法偶尔命中）在两次 ping 之间会有 >6s 空隙；若 read 超时短于 ping 间隔，
        # httpx 会在空隙里 ReadTimeout 导致整体提前返回、收不到后续命中。故 read=None，
        # 由 deadline 控制窗口，ping 负责保活兜底（每条 ping/事件后都会检查 deadline）。
        try:
            with httpx.Client(timeout=httpx.Timeout(seconds + 20, read=None)) as c:
                with c.stream("GET", self._base + "/events", headers=self._headers) as r:
                    for line in r.iter_lines():
                        if line.startswith("data: "):
                            payload = line[6:].strip()
                            if payload:
                                try:
                                    events.append(_json.loads(payload))
                                except Exception:
                                    events.append(payload)
                        if time.time() > deadline or len(events) >= max_events:
                            break
        except Exception:
            pass
        return events

    def disable_port(self) -> None:
        """收尾：关闭设备端口（仅 adb 模式有意义）。"""
        if settings.transport == "adb":
            try:
                self._su(f"sh {settings.rbctl} disable")
            except Exception:
                pass


client = ReconClient()
