"""Cruiser 运行监控 HTTP 服务。

调度主进程内后台线程启动；也可独立运行：
    uv run python -m cruiser.dashboard
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from cruiser import runtime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FRONT = os.path.join(_ROOT, "frontend")
_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


class _Handler(BaseHTTPRequestHandler):
    server_version = "CruiserDashboard/1.0"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = unquote(parsed.path or "/")
        qs = parse_qs(parsed.query or "")
        try:
            if path == "/api/snapshot":
                self._json(runtime.snapshot())
                return
            if path == "/api/challenge":
                code = (qs.get("code") or [""])[0].strip()
                if not code:
                    self._json({"error": "missing code"}, 400)
                    return
                detail = runtime.challenge_detail(code)
                if detail is None:
                    self._json({"error": "not found"}, 404)
                    return
                self._json(detail)
                return
            if path == "/api/logs":
                code = (qs.get("code") or [""])[0].strip()
                after = _int(qs.get("after", ["0"])[0], 0)
                limit = _int(qs.get("limit", ["300"])[0], 300)
                self._json(runtime.logs_since(after=after, code=code, limit=limit))
                return
            self._static(path)
        except Exception as e:  # noqa: BLE001
            self._json({"error": type(e).__name__, "detail": str(e)}, 500)

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path: str) -> None:
        if path == "/":
            path = "/index.html"
        rel = path.lstrip("/")
        if ".." in rel or rel.startswith("/"):
            self.send_error(404)
            return
        full = os.path.normpath(os.path.join(_FRONT, rel))
        if not full.startswith(os.path.normpath(_FRONT) + os.sep) and full != os.path.normpath(_FRONT):
            self.send_error(403)
            return
        if not os.path.isfile(full):
            self.send_error(404)
            return
        ext = os.path.splitext(full)[1].lower()
        data = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", _MIME.get(ext, "application/octet-stream"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _int(v: str, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _pick_port(host: str, preferred: int) -> int:
    import socket

    for port in [preferred] + list(range(preferred + 1, preferred + 12)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.close()
            return port
        except OSError:
            try:
                s.close()
            except Exception:
                pass
    return preferred


def serve(host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd


def start_dashboard() -> tuple[str, int] | None:
    """后台启动。环境变量 CRUISER_DASHBOARD=0 关闭。"""
    if os.environ.get("CRUISER_DASHBOARD", "1") in ("0", "false", "no"):
        return None
    host = os.environ.get("CRUISER_DASHBOARD_HOST", "127.0.0.1").strip() or "127.0.0.1"
    preferred = _int(os.environ.get("CRUISER_DASHBOARD_PORT", "8765"), 8765)
    port = _pick_port(host, preferred)
    httpd = serve(host, port)

    def _run() -> None:
        try:
            httpd.serve_forever(poll_interval=0.5)
        except Exception:
            pass

    t = threading.Thread(target=_run, name="cruiser-dashboard", daemon=True)
    t.start()
    display = host if host not in ("0.0.0.0", "::") else "127.0.0.1"
    print(f"[Dashboard] 监控面板 http://{display}:{port}", flush=True)
    return display, port


def main() -> None:
    host = os.environ.get("CRUISER_DASHBOARD_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = _int(os.environ.get("CRUISER_DASHBOARD_PORT", "8765"), 8765)
    port = _pick_port(host, port)
    httpd = serve(host, port)
    display = host if host not in ("0.0.0.0", "::") else "127.0.0.1"
    print(f"[Dashboard] 监控面板 http://{display}:{port} （独立模式，读 reports/）", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("[Dashboard] 已停止", flush=True)


if __name__ == "__main__":
    # 独立进程也要加载 .env（包 init 已做）；保证能找到 reports/
    os.chdir(_ROOT)
    main()
