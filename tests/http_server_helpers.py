from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ThreadedHTTPServer:
    """Run a request handler on an ephemeral 127.0.0.1 port in a daemon thread.

    Subclasses set ``path`` and implement ``build_handler``; the start/shutdown
    lifecycle lives here so individual servers only describe how they respond.
    """

    path = "/"

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        raise NotImplementedError

    def __enter__(self) -> str:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.build_handler())
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True
        )
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}{self.path}"

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LocalHTTPFileServer(ThreadedHTTPServer):
    """Context manager serving a fixed body at /feed.txt on an ephemeral port."""

    path = "/feed.txt"

    def __init__(self, body: bytes) -> None:
        self.body = body

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        body = self.body

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                del fmt, args

        return Handler


class LocalHTTPTextServer(ThreadedHTTPServer):
    """Context manager serving a fixed body at /sample.txt with a chosen content type."""

    path = "/sample.txt"

    def __init__(self, body: bytes, content_type: str = "text/plain") -> None:
        self.body = body
        self.content_type = content_type

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        body = self.body
        content_type = self.content_type

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                del fmt, args

        return Handler
