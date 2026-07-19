"""PC 本地 Web 控制台（`reconbridge-mcp --serve`）。

命令行起一个只绑 127.0.0.1 的小 HTTP 服务，浏览器打开就是图形界面：选连接方式
（adb / wifi）、一键连接、看 daemon 状态 + 只读监控（活动 hook / 近期事件流 / 落盘 dumps）。

后端全部复用 client.py 的 ReconClient 单例（连接与取数逻辑），前端在 webconsole.html
里轮询本服务的 /api/*。仅本机可用，不做鉴权。
"""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .client import client, ReconError, _fold_stack

_HTML_CACHE: bytes | None = None


def _load_html() -> bytes:
    """读取打包/源码里的 webconsole.html（首次读入后缓存）。"""
    global _HTML_CACHE
    if _HTML_CACHE is not None:
        return _HTML_CACHE
    data = "<h1>webconsole.html 缺失</h1>".encode("utf-8")
    try:
        import importlib.resources as ir
        data = (ir.files("reconbridge_mcp") / "webconsole.html").read_bytes()
    except Exception:
        try:
            import os
            p = os.path.join(os.path.dirname(__file__), "webconsole.html")
            with open(p, "rb") as f:
                data = f.read()
        except Exception:
            pass
    _HTML_CACHE = data
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "ReconBridgeConsole/1.0"

    # ---- 底层发送 ----
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---- 路由 ----
    def do_GET(self) -> None:
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)
        try:
            if path == "/" or path == "/index.html":
                self._send(200, _load_html(), "text/html; charset=utf-8")
            elif path == "/api/status":
                self._json(self._status())
            elif path == "/api/devices":
                self._json({"ok": True, "devices": client.list_devices()})
            elif path == "/api/hooks":
                self._json({"ok": True, "data": client.get_json("/hooks")})
            elif path == "/api/dumps":
                self._json({"ok": True, "data": client.get_json("/dumps")})
            elif path == "/api/recent":
                limit = int((qs.get("limit") or ["60"])[0])
                since = int((qs.get("since_seq") or ["0"])[0])
                data = client.get_recent(limit=limit, since_seq=since)
                evts = [_fold_stack(e) for e in data.get("events", [])]
                self._json({"ok": True, "latest_seq": data.get("latest_seq"),
                            "count": len(evts), "events": evts})
            else:
                self._json({"ok": False, "error": "not found"}, 404)
        except ReconError as e:
            self._json({"ok": False, "error": str(e)})
        except Exception as e:  # noqa: BLE001 控制台不抛裸异常
            self._json({"ok": False, "error": f"{type(e).__name__}: {e}"})

    def do_POST(self) -> None:
        u = urlparse(self.path)
        body = self._read_body()
        try:
            if u.path == "/api/connect":
                client.reconnect(
                    transport=body.get("transport", "adb"),
                    serial=body.get("serial", ""),
                    url=body.get("url", ""),
                    token=body.get("token", ""),
                )
                self._json(self._status())
            elif u.path == "/api/disconnect":
                client.disconnect()
                self._json(self._status())
            elif u.path == "/api/unhook":
                pkg = body.get("package", "")
                if not pkg:
                    self._json({"ok": False, "error": "缺少 package"})
                    return
                b = {"package": pkg}
                if body.get("hook_id"):
                    b["id"] = body["hook_id"]
                self._json({"ok": True, "data": client.post_json("/unhook", b)})
            else:
                self._json({"ok": False, "error": "not found"}, 404)
        except ReconError as e:
            self._json({"ok": False, "error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._json({"ok": False, "error": f"{type(e).__name__}: {e}"})

    # ---- 组装状态（连上则顺带探活 /health）----
    def _status(self) -> dict:
        st = client.status()
        st["ok"] = True
        if st.get("connected"):
            try:
                st["health"] = client.get_json("/health")
            except Exception as e:
                st["connected"] = False
                st["health"] = None
                st["error"] = str(e)
        else:
            st["health"] = None
        return st

    def log_message(self, fmt: str, *args) -> None:
        # 简洁访问日志到 stderr（本地控制台，非 stdio，不影响 MCP）
        sys.stderr.write("[console] %s\n" % (fmt % args))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="reconbridge-mcp --serve",
        description="启动 PC 本地 Web 控制台（选连接方式 / 看状态与监控）",
    )
    ap.add_argument("--serve", action="store_true", help="启动控制台（分派标志）")
    ap.add_argument("--port", type=int, default=9000, help="监听端口，默认 9000")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机 127.0.0.1")
    ap.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args(argv)

    open_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{open_host}:{args.port}/"

    try:
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as e:
        print(f"[reconbridge] 无法监听 {args.host}:{args.port} —— {e}", file=sys.stderr)
        print("  换个端口试试：reconbridge-mcp --serve --port 9010", file=sys.stderr)
        return 1

    print(f"[reconbridge] 控制台已启动：{url}")
    print("  在浏览器里选连接方式、看状态与监控。Ctrl+C 停止。")
    if args.host not in ("127.0.0.1", "localhost"):
        print(f"  注意：绑定在 {args.host}，控制台会暴露到局域网（默认应只用 127.0.0.1）。")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[reconbridge] 已停止。")
    finally:
        httpd.server_close()
    return 0
