"""Authenticated Unix IPC; no HTTP, TCP, proxy or cross-host ingress.

Per-principal HMAC authenticates operation, target, timestamp, nonce and args.
Transport is local/private; same-UID processes are not a hostile-user boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import socketserver
import stat
import threading
import time
from pathlib import Path

from firefly_bridge.broker_store import SENDERS, StoreError
from firefly_bridge.envelope import load_key
from firefly_bridge.privacy import safe

MAX_FRAME = 131072
MAX_AF_UNIX_PATH = 100


def _chdir_for_unix_socket(path: Path):
    """Context manager to bind/connect AF_UNIX sockets whose full path exceeds 104 bytes on macOS."""
    from contextlib import contextmanager

    @contextmanager
    def _ctx():
        raw = str(path)
        if len(raw.encode("utf-8")) <= MAX_AF_UNIX_PATH:
            yield raw
            return
        cwd = os.getcwd()
        os.chdir(path.parent)
        try:
            yield path.name
        finally:
            os.chdir(cwd)

    return _ctx()


def canonical(request):
    return json.dumps(
        {k: v for k, v in request.items() if k != "mac"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def signed_request(key, principal, session_id, op, args=None):
    r = {
        "v": 1,
        "principal": principal,
        "session_id": session_id,
        "ts": time.time(),
        "nonce": secrets.token_hex(16),
        "op": op,
        "args": args or {},
    }
    r["mac"] = hmac.new(key, canonical(r), hashlib.sha256).hexdigest()
    return r


class Authenticator:
    def __init__(self, keys_dir, store, session_id):
        self.keys = {}
        self.store = store
        self.session_id = session_id
        if not keys_dir:
            raise StoreError("ipc_keys_dir_required")
        principals = tuple(getattr(store, "senders", SENDERS)) + ("human", "recipient")
        for principal in principals:
            p = Path(keys_dir) / (principal + ".key")
            if p.exists():
                if p.is_symlink():
                    raise StoreError("ipc_key_symlink_forbidden")
                key = load_key(p)
                if key in self.keys.values():
                    raise StoreError("ipc_keys_must_be_distinct")
                self.keys[principal] = key
        if not self.keys:
            raise StoreError("ipc_keys_missing")

    def verify(self, request):
        if not isinstance(request, dict) or set(request) != {
            "v",
            "principal",
            "session_id",
            "ts",
            "nonce",
            "op",
            "args",
            "mac",
        }:
            raise StoreError("ipc_schema_invalid")
        principal = request["principal"]
        key = self.keys.get(principal) if isinstance(principal, str) else None
        if (
            not key
            or request["v"] != 1
            or request["session_id"] != self.session_id
            or not isinstance(request["mac"], str)
            or not hmac.compare_digest(
                request["mac"], hmac.new(key, canonical(request), hashlib.sha256).hexdigest()
            )
        ):
            raise StoreError("ipc_auth_failed")
        self.store.accept_nonce(principal, request["nonce"], request["ts"])
        return principal


class IpcServer:
    def __init__(self, path, daemon):
        self.path = Path(path)
        auth = Authenticator(daemon.cfg.ipc_keys_dir, daemon.store, daemon.cfg.session_id)
        if self.path.exists():
            # Only the exclusive broker authority may remove its stale socket.
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise StoreError("ipc_path_not_owned_socket")
            self.path.unlink()

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(2)
                try:
                    frame = self.rfile.readline(MAX_FRAME + 1)
                    if len(frame) > MAX_FRAME or not frame.endswith(b"\n"):
                        raise StoreError("ipc_frame_too_large")
                    request = json.loads(frame)
                    principal = auth.verify(request)
                    result = daemon.handle_ipc(principal, request["op"], request["args"])
                    result = safe(result)
                except Exception:
                    # Never echo parser, credentials, tool output or raw exception.
                    result = {"error": "ipc_request_refused"}
                data = (json.dumps(result) + "\n").encode()
                if len(data) > MAX_FRAME:
                    data = b'{"error":"ipc_response_too_large"}\n'
                try:
                    self.wfile.write(data)
                except OSError:
                    pass

        with _chdir_for_unix_socket(self.path) as bind_addr:
            self.server = socketserver.UnixStreamServer(bind_addr, Handler)
        os.chmod(self.path, 0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join(3)
        self.server.server_close()
        self.path.unlink(missing_ok=True)


def ipc_call(cfg, op, args=None):
    request = signed_request(
        load_key(cfg.ipc_key_file), cfg.ipc_principal, cfg.session_id, op, args
    )
    frame = (json.dumps(request) + "\n").encode()
    if len(frame) > MAX_FRAME:
        raise StoreError("ipc_frame_too_large")
    path = Path(cfg.state_dir) / "broker.sock"
    info = path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise StoreError("ipc_socket_not_private")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        with _chdir_for_unix_socket(path) as connect_addr:
            sock.connect(connect_addr)
        sock.sendall(frame)
        with sock.makefile("rb") as stream:
            reply = stream.readline(MAX_FRAME + 1)
        if len(reply) > MAX_FRAME:
            raise StoreError("ipc_response_too_large")
        return json.loads(reply)
