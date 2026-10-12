"""Event-driven wake: agents listen on a local port instead of polling their inbox.

A wake event carries no message content, only a pointer. The agent still has
to read the message through the authenticated mailbox.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

MAX_BODY_BYTES = 16 * 1024
_log = logging.getLogger(__name__)
# Never route local wake calls through a system proxy.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def sign(secret: bytes, timestamp: str, body: bytes) -> str:
    return hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def send_wake(url: str, secret: bytes, payload: dict[str, Any], timeout: float = 5.0) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    timestamp = str(int(time.time()))
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Wake-Timestamp": timestamp,
            "X-Wake-Signature": sign(secret, timestamp, body),
        },
    )
    with _opener.open(request, timeout=timeout) as response:
        if response.status != 204:
            raise RuntimeError(f"wake rejected with HTTP {response.status}")


class WakeRouter:
    """Mailbox wake callback: sends a signed wake to the recipient's listener."""

    def __init__(self) -> None:
        self._routes: dict[str, tuple[str, bytes]] = {}

    def add(self, recipient: str, url: str, secret: bytes) -> None:
        self._routes[recipient] = (url, secret)

    def __call__(self, recipient: str, message_id: str) -> None:
        url, secret = self._routes[recipient]
        send_wake(url, secret, {"event_id": str(uuid.uuid4()), "recipient": recipient, "message_id": message_id})


class WakeListener:
    """Accepts signed, fresh, non-replayed wake events and hands them to one worker, in order."""

    def __init__(
        self,
        secret: bytes,
        handler: Callable[[dict[str, Any]], None],
        host: str = "127.0.0.1",
        port: int = 0,
        max_skew_seconds: int = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._secret = secret
        self._handler = handler
        self._max_skew = max_skew_seconds
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        listener = self

        class _RequestHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server naming
                status = listener._accept(self.path, self.headers, self.rfile)
                self.send_response(status)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - silence default logging
                pass

        self._server = ThreadingHTTPServer((host, port), _RequestHandler)
        self._threads: list[threading.Thread] = []

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/wake"

    def start(self) -> "WakeListener":
        self._threads = [
            threading.Thread(target=self._server.serve_forever, daemon=True),
            threading.Thread(target=self._work, daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._queue.put(None)
        for thread in self._threads:
            thread.join(timeout=5)

    def _accept(self, path: str, headers: Any, stream: Any) -> int:
        if path != "/wake":
            return 404
        try:
            length = int(headers.get("Content-Length", "0"))
        except ValueError:
            return 400
        if not 0 < length <= MAX_BODY_BYTES:
            return 413
        body = stream.read(length)
        timestamp = headers.get("X-Wake-Timestamp", "")
        signature = headers.get("X-Wake-Signature", "")
        now = self._clock()
        if not timestamp.isdigit() or abs(now - int(timestamp)) > self._max_skew:
            return 401
        if not hmac.compare_digest(signature, sign(self._secret, timestamp, body)):
            return 401
        try:
            payload = json.loads(body)
            event_id = str(payload["event_id"])
        except (ValueError, KeyError, TypeError):
            return 400
        with self._lock:
            if event_id in self._seen:
                return 409
            # Events older than the skew window are already rejected, so forget them.
            self._seen = {key: seen for key, seen in self._seen.items() if now - seen <= 2 * self._max_skew}
            self._seen[event_id] = now
        self._queue.put(payload)
        return 204

    def _work(self) -> None:
        while (event := self._queue.get()) is not None:
            try:
                self._handler(event)
            except Exception:
                _log.exception("wake handler failed")
