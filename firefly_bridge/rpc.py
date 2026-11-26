"""Minimal newline-delimited JSON-RPC 2.0 client for ACP over stdio.

Only the methods in ``DAEMON_CLIENT_METHODS`` may be sent. ``session/new``,
``authenticate``, config changes and forks stay forbidden: the daemon attaches
to an existing, pinned session and never creates or reconfigures one.
"""

from __future__ import annotations

import itertools
import json
import threading

from firefly_bridge.acp import ForbiddenMethod

DAEMON_CLIENT_METHODS = frozenset(
    {"initialize", "session/load", "session/prompt", "session/cancel"}
)
NOTIFICATION_METHODS = frozenset({"session/cancel"})
MAX_RPC_FRAME = 16 * 1024 * 1024
DEFAULT_MAX_FRAME_BYTES = MAX_RPC_FRAME
MAX_OVERSIZED_SKIP_BYTES = 16 * 1024 * 1024


class ConnectionClosed(Exception):
    pass


class PendingCall:
    def __init__(self, rpc_id) -> None:
        self.id = rpc_id
        self._event = threading.Event()
        self.result = None
        self.error = None
        self.closed = False

    def _resolve(self, msg: dict) -> None:
        self.result = msg.get("result")
        self.error = msg.get("error")
        self._event.set()

    def _close(self) -> None:
        self.closed = True
        self._event.set()

    def done(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None) -> bool:
        return self._event.wait(timeout)


class JsonRpcConnection:
    def __init__(
        self,
        reader,
        writer,
        *,
        on_notification=None,
        on_request=None,
        max_frame_bytes: int | None = None,
        max_frame: int | None = None,
        skip_oversized: bool = False,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._on_notification = on_notification or (lambda msg: None)
        self._on_request = on_request or (lambda msg: None)
        bound = max_frame if max_frame is not None else (
            max_frame_bytes if max_frame_bytes is not None else MAX_RPC_FRAME
        )
        self._max_frame_bytes = int(bound)
        self._skip_oversized = bool(skip_oversized)
        self._write_lock = threading.Lock()
        self._pending: dict = {}
        self._pending_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._thread: threading.Thread | None = None
        self.closed = threading.Event()
        self.malformed_lines = 0
        self.oversized_lines = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._read_loop, name="ffb-rpc", daemon=True)
        self._thread.start()

    # -- outbound ------------------------------------------------------------
    def request(self, method: str, params: dict, rpc_id=None) -> PendingCall:
        if method not in DAEMON_CLIENT_METHODS or method in NOTIFICATION_METHODS:
            raise ForbiddenMethod(method)
        if self.closed.is_set():
            raise ConnectionClosed("closed")
        rpc_id = rpc_id if rpc_id is not None else f"ffb-{next(self._ids)}"
        call = PendingCall(rpc_id)
        with self._pending_lock:
            self._pending[rpc_id] = call
        self._write({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})
        return call

    def notify(self, method: str, params: dict) -> None:
        if method not in NOTIFICATION_METHODS:
            raise ForbiddenMethod(method)
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def respond(self, rpc_id, result: dict) -> None:
        self._write({"jsonrpc": "2.0", "id": rpc_id, "result": result})

    def respond_error(self, rpc_id, code: int, message: str) -> None:
        self._write({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})

    def _write(self, msg: dict) -> None:
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        with self._write_lock:
            try:
                self._writer.write(data)
                self._writer.flush()
            except (BrokenPipeError, ValueError, OSError) as exc:
                self._mark_closed()
                raise ConnectionClosed("write_failed") from exc

    # -- inbound -------------------------------------------------------------
    def _drain_oversized_line(self, initial: bytes) -> bool:
        drained = len(initial)
        while not initial.endswith(b"\n"):
            chunk = self._reader.readline(65536)
            if not chunk:
                return False
            drained += len(chunk)
            if drained > MAX_OVERSIZED_SKIP_BYTES:
                return False
            initial = chunk
        return True

    def _read_loop(self) -> None:
        limit = self._max_frame_bytes
        try:
            while True:
                line = self._reader.readline(limit + 1)
                if len(line) > limit:
                    self.oversized_lines += 1
                    if self._skip_oversized and self._drain_oversized_line(line):
                        continue
                    break
                if not line:
                    break
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    self.malformed_lines += 1
                    continue
                if not isinstance(msg, dict):
                    self.malformed_lines += 1
                    continue
                self.dispatch(msg)
        except (OSError, ValueError):
            pass
        finally:
            self._mark_closed()

    def dispatch(self, msg: dict) -> None:
        if "method" in msg and "id" in msg:
            self._on_request(msg)
        elif "method" in msg:
            self._on_notification(msg)
        elif "id" in msg:
            with self._pending_lock:
                call = self._pending.pop(msg["id"], None)
            if call is not None:
                call._resolve(msg)

    def _mark_closed(self) -> None:
        self.closed.set()
        with self._pending_lock:
            calls = list(self._pending.values())
            self._pending.clear()
        for call in calls:
            call._close()
