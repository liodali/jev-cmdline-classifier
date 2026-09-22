"""A tiny fake TypeSafe System One server for offline client tests.

Usage::

    with FakeTypeSafe() as server:
        server.enqueue_json(200, {"answers": {...}})
        ...  # point the client at server.endpoint
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional


class _Handler(BaseHTTPRequestHandler):
    server_version = "FakeTypeSafe/0.1"

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            self.server.requests.append(  # type: ignore[attr-defined]
                {"path": self.path, "headers": dict(self.headers), "body": json.loads(body or "{}")}
            )
        except json.JSONDecodeError:
            self.server.requests.append(  # type: ignore[attr-defined]
                {"path": self.path, "headers": dict(self.headers), "body": body}
            )

        status, payload = self.server.next_response()  # type: ignore[attr-defined]
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return  # keep test output quiet


class FakeTypeSafe(ThreadingHTTPServer):
    """Serve queued responses and record every request it receives."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.requests: list = []
        self._responses: list = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    def enqueue(self, status: int, payload: Optional[dict] = None) -> None:
        with self._lock:
            self._responses.append((status, payload if payload is not None else {}))

    def enqueue_json(self, status: int, payload: dict) -> None:
        self.enqueue(status, payload)

    def next_response(self):
        with self._lock:
            if self._responses:
                return self._responses.pop(0)
        return 500, {"error": "no queued response"}

    @property
    def endpoint(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/v1/systemone"

    def __enter__(self) -> "FakeTypeSafe":
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.shutdown()
        self.server_close()
