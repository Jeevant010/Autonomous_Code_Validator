from __future__ import annotations

import http.server
import socketserver
import threading

from worker import fetch


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/go-local":
            port = self.server.server_address[1]
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"ok" if self.path == "/ok" else b"not found"
        self.send_response(200 if self.path == "/ok" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


def _start() -> tuple[socketserver.TCPServer, threading.Thread, int]:
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


def _stop(server: socketserver.TCPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_local_fetch() -> None:
    server, thread, port = _start()
    try:
        assert fetch(f"http://localhost:{port}/ok") == "ok"
    finally:
        _stop(server, thread)


def test_allowed_redirect() -> None:
    server, thread, port = _start()
    try:
        assert fetch(f"http://localhost:{port}/go-local") == "ok"
    finally:
        _stop(server, thread)
