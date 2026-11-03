import http.server
import socketserver
import threading

from worker import fetch


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


def test_local_fetch() -> None:
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert fetch(f"http://localhost:{port}/ok") == "ok"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
