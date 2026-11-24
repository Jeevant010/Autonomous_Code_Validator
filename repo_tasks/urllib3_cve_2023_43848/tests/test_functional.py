"""Behaviour that must keep working after the CVE-2023-43848 fix.

Redirects must still work, and the 307/308 methods must still preserve the body
because those status codes are defined to keep the method and payload.
"""

from __future__ import annotations

import http.server
import socketserver
import threading

import pytest
import urllib3


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    status = 303
    seen: dict[str, object] = {}

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if self.path == "/start":
            self.send_response(_RedirectHandler.status)
            self.send_header("Location", "/landing")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        _RedirectHandler.seen = {"method": self.command, "body": body}
        payload = b"landed"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture()
def server():
    socketserver.TCPServer.allow_reuse_address = True
    instance = socketserver.TCPServer(("127.0.0.1", 0), _RedirectHandler)
    port = instance.server_address[1]
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        instance.shutdown()
        instance.server_close()


def _send(port: int, method: str, body: bytes) -> dict[str, object]:
    pool = urllib3.HTTPConnectionPool("127.0.0.1", port, timeout=10)
    try:
        response = pool.urlopen(
            method,
            "/start",
            body=body,
            headers={"Content-Type": "application/json"},
            redirect=True,
        )
        assert response.status == 200
    finally:
        pool.close()
    return dict(_RedirectHandler.seen)


def test_plain_redirect_is_followed(server: int) -> None:
    _RedirectHandler.status = 303
    seen = _send(server, "GET", b"")
    assert seen["method"] == "GET"


def test_303_changes_post_to_get(server: int) -> None:
    _RedirectHandler.status = 303
    seen = _send(server, "POST", b"payload")
    assert seen["method"] == "GET"


def test_307_preserves_method_and_body(server: int) -> None:
    _RedirectHandler.status = 307
    seen = _send(server, "POST", b"payload")
    assert seen["method"] == "POST"
    assert seen["body"] == b"payload"


def test_308_preserves_method_and_body(server: int) -> None:
    _RedirectHandler.status = 308
    seen = _send(server, "PUT", b"payload")
    assert seen["method"] == "PUT"
    assert seen["body"] == b"payload"


def test_http_header_dict_still_works() -> None:
    headers = urllib3._collections.HTTPHeaderDict()
    headers["X-Test"] = "1"
    assert headers["X-Test"] == "1"
    assert urllib3.__version__
