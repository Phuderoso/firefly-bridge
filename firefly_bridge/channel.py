"""Channel: stock Grok ACP leader adapter, wake-file writer, and safe CLI.

Bridges agent-a -> peera-peerb (or mock leader in dry-run) over the stock Grok
ACP leader protocol (`grok agent --leader --leader-socket SOCK stdio`),
while enforcing all local safety gates:
  - No `tmux send-keys`, no keyboard/composer injection.
  - Never restarts or touches peerb's TUI process or the live hold process unless asked.
  - Wake-origin `session/request_permission` is always denied (`wake_origin_tool_denied`)
    on this client's connection, even if `answer_permissions` is set. Default
    `permission_mode` is `pending` (never `allow_all_own_turns` on the peerb profile).
    `kind: recado` (default) and `kind: tool_request` are text; neither auto-answers
    a tool. Named pending card is written; agent-a never Allow.
  - Redacts secrets and private paths (`privacy.render_content` / `safe`) before
    writing receipts or wake files.
  - Writes the peer reply into the configured wake directory (`reply_<ts>.md`)
    and updates `WAKE.md` for synchronous turn replies and for late replies via `watch-wake`.
  - Oversized `session/update` frames (up to 16 MB in real sessions) are drained
    without killing the ACP connection.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import select
import signal
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

from firefly_bridge import __version__
from firefly_bridge.audit import LOCAL_ZONE, local_time
from firefly_bridge.config import (
    ENV_PREFIX,
    ConfigError,
    _coerce,
    default_config_path,
    parse_toml_text,
)
from firefly_bridge.envelope import load_key, sign_text
from firefly_bridge.messages import new_message_id, validate_session_id
from firefly_bridge.privacy import redact_text, render_content, safe, validate_body
from firefly_bridge.wake_envelope import (
    DEFAULT_PENDING_CARD,
    count_permission_requests,
    count_real_approvals,
    count_wake_origin_denied,
    parse_wake_envelope,
    pending_card_from_request,
    wake_origin_permission_result,
    write_pending_card,
)

# Generic placeholders only. Deployment paths belong in
# ~/.config/firefly-bridge/config.toml or FIREFLY_BRIDGE_* environment variables.
DEFAULT_SOCKET = "~/.grok/leader.sock"
DEFAULT_SESSION_ID = "sess-example-0001"
DEFAULT_WORKSPACE = "~/.local/share/firefly-bridge/workspace"
DEFAULT_GROK_BIN = "~/.grok/bin/grok"
DEFAULT_LEDGER = "~/.local/state/firefly-bridge/ledger.json"
DEFAULT_HOLD_PID_FILE = "~/.local/state/firefly-bridge/hold.pid"
DEFAULT_APPROVALS_LOG = "~/.local/state/firefly-bridge/auto-approvals.jsonl"
DEFAULT_WAKE_NOTES = "~/.local/share/firefly-bridge/wake-notes"
DEFAULT_UPDATES_JSONL = ""  # derived from session_cwd + session_id when empty
DEFAULT_STATE_DIR = "~/.local/state/firefly-bridge"


class ChannelError(RuntimeError):
    pass


@dataclass
class ChannelConfig:
    socket_path: str = DEFAULT_SOCKET
    session_id: str = DEFAULT_SESSION_ID
    session_cwd: str = DEFAULT_WORKSPACE
    grok_bin: str = DEFAULT_GROK_BIN
    sender: str = "agent-a"
    prefix: str = "agent-a: "
    auth_mode: str = "prefix"
    hmac_key_file: str = ""
    ledger_path: str = DEFAULT_LEDGER
    hold_pid_file: str = DEFAULT_HOLD_PID_FILE
    approvals_log_path: str = DEFAULT_APPROVALS_LOG
    wake_dir: str = DEFAULT_WAKE_NOTES
    wake_filename: str = "WAKE.md"
    reply_prefix: str = "reply_"
    inbound_dir: str = "memory/shared/inbound"
    updates_jsonl_path: str = DEFAULT_UPDATES_JSONL
    connect_timeout_s: float = 30.0
    load_timeout_s: float = 120.0
    turn_timeout_s: float = 600.0
    max_frame_bytes: int = 16 * 1024 * 1024  # match rpc.MAX_RPC_FRAME (rc6)
    max_oversized_skip_bytes: int = 32 * 1024 * 1024
    max_body_bytes: int = 32000
    max_reply_bytes: int = 64000
    strip_grok_sandbox: bool = False  # opt-in only; never strip the leader sandbox by default
    # When hold_pid is alive, the hold answers permissions for agent-a-prefixed turns.
    # answer_permissions stays false unless an explicit user flag says otherwise.
    # Even then, wake-origin session/request_permission is denied (never allow).
    # peerb/channel default is pending — not deployment allow_all_own_turns.
    answer_permissions: bool = False
    permission_mode: str = "pending"
    pending_card_path: str = DEFAULT_PENDING_CARD
    protected_tools_enabled: bool = True
    state_dir: str = DEFAULT_STATE_DIR
    ipc_key_file: str = ""
    ipc_principal: str = "agent-a"
    use_daemon_ipc: bool = True  # route through unified Daemon IPC when broker.sock + key are live

    def resolved(self) -> ChannelConfig:
        def exp(p: str) -> str:
            return os.path.expandvars(os.path.expanduser(p)) if p else ""

        out = ChannelConfig(
            socket_path=exp(self.socket_path),
            session_id=validate_session_id(self.session_id),
            session_cwd=exp(self.session_cwd),
            grok_bin=exp(self.grok_bin),
            sender=self.sender,
            prefix=self.prefix,
            auth_mode=self.auth_mode,
            hmac_key_file=exp(self.hmac_key_file),
            ledger_path=exp(self.ledger_path),
            hold_pid_file=exp(self.hold_pid_file),
            approvals_log_path=exp(self.approvals_log_path),
            wake_dir=exp(self.wake_dir),
            wake_filename=self.wake_filename or "WAKE.md",
            reply_prefix=self.reply_prefix or "reply_",
            inbound_dir=self.inbound_dir or "memory/shared/inbound",
            updates_jsonl_path=exp(self.updates_jsonl_path),
            connect_timeout_s=float(self.connect_timeout_s),
            load_timeout_s=float(self.load_timeout_s),
            turn_timeout_s=float(self.turn_timeout_s),
            max_frame_bytes=int(self.max_frame_bytes),
            max_oversized_skip_bytes=int(self.max_oversized_skip_bytes),
            max_body_bytes=int(self.max_body_bytes),
            max_reply_bytes=int(self.max_reply_bytes),
            strip_grok_sandbox=bool(self.strip_grok_sandbox),
            answer_permissions=bool(self.answer_permissions),
            permission_mode=self.permission_mode,
            pending_card_path=exp(self.pending_card_path),
            protected_tools_enabled=bool(self.protected_tools_enabled),
            state_dir=exp(self.state_dir),
            ipc_key_file=exp(self.ipc_key_file),
            ipc_principal=self.ipc_principal,
            use_daemon_ipc=bool(self.use_daemon_ipc),
        )
        if not out.updates_jsonl_path:
            out.updates_jsonl_path = exp(derive_updates_jsonl(out.session_cwd, out.session_id))
        return out



def derive_updates_jsonl(session_cwd: str, session_id: str) -> str:
    """Guess the stock Grok updates.jsonl path from the pinned session cwd + id."""
    if not session_cwd or not session_id:
        return ""
    cwd = os.path.expandvars(os.path.expanduser(session_cwd))
    return str(Path("~/.grok/sessions") / quote(cwd, safe="") / session_id / "updates.jsonl")


_SHARED_FROM_BRIDGE = frozenset(
    {
        "socket_path",
        "session_id",
        "session_cwd",
        "grok_bin",
        "sender",
        "prefix",
        "auth_mode",
        "hmac_key_file",
        "connect_timeout_s",
        "load_timeout_s",
        "turn_timeout_s",
        "max_frame_bytes",
        "max_body_bytes",
        "max_reply_bytes",
        "strip_grok_sandbox",
        "permission_mode",
        "pending_card_path",
        "protected_tools_enabled",
        "state_dir",
        "ipc_key_file",
        "ipc_principal",
        "wake_dir",
        "wake_filename",
        "reply_prefix",
        "inbound_dir",
        "updates_jsonl_path",
        "hold_pid_file",
        "approvals_log_path",
        "ledger_path",
        "answer_permissions",
    }
)


def load_channel_config(
    path: str | Path | None = None,
    overrides: dict | None = None,
    env: dict | None = None,
) -> ChannelConfig:
    """Load ChannelConfig from a TOML file and FIREFLY_BRIDGE_* env vars.

    Lookup order (later wins): built-in placeholders, optional [bridge] shared
    keys, [channel] table, FIREFLY_BRIDGE_<FIELD>, then ``overrides`` (CLI).
    The default file is ``$XDG_CONFIG_HOME/firefly-bridge/config.toml``.
    """
    env = dict(os.environ if env is None else env)
    field_map = {f.name: f for f in fields(ChannelConfig)}
    known = set(field_map)
    values: dict = {}

    def _put(name: str, raw_val) -> None:
        try:
            values[name] = _coerce(name, raw_val, field_map[name].type)
        except ConfigError as exc:
            raise ChannelError(str(exc)) from exc

    explicit = path or env.get(ENV_PREFIX + "CONFIG")
    candidate = Path(explicit).expanduser() if explicit else default_config_path()
    if explicit and not candidate.exists():
        raise ChannelError("config_file_not_found")
    if candidate.exists():
        try:
            data = parse_toml_text(candidate.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ChannelError("config_toml_invalid") from exc
        bridge = data.get("bridge") if isinstance(data.get("bridge"), dict) else {}
        section = data.get("channel") if isinstance(data.get("channel"), dict) else {}
        flat = {k: v for k, v in data.items() if not isinstance(v, dict) and k in known}
        for src in (flat, {k: v for k, v in bridge.items() if k in _SHARED_FROM_BRIDGE}, section):
            unknown = set(src) - known
            if unknown:
                raise ChannelError("unknown_config_keys:" + ",".join(sorted(unknown)))
            for k, v in src.items():
                _put(k, v)
    for name in known:
        key = ENV_PREFIX + name.upper()
        if key in env:
            _put(name, env[key])
    if overrides:
        for k, v in overrides.items():
            if v is not None:
                if k not in known:
                    raise ChannelError(f"unknown_config_keys:{k}")
                _put(k, v)
    return ChannelConfig(**values)


class ChannelLedger:
    """At-most-once JSON file ledger (path comes from ChannelConfig.ledger_path)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.lock_path = Path(str(self.path) + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}\n", encoding="utf-8")

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8") or "{}")
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with tmp.open("a", encoding="utf-8") as fh:
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(self.path)

    def claim(self, message_id: str, payload: dict) -> tuple[bool, dict, dict]:
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            data = self._read()
            if message_id in data:
                return False, data[message_id], data
            now = time.time()
            rec = {
                "message_id": message_id,
                "attempt_committed": True,
                "outcome": "unknown",
                **payload,
                "ts": now,
                "ts_local": local_time(now),
                "timezone": LOCAL_ZONE,
            }
            data[message_id] = rec
            self._write(data)
            return True, rec, data

    def update(self, message_id: str, **fields) -> dict:
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            data = self._read()
            if message_id in data and isinstance(data[message_id], dict):
                data[message_id].update(fields)
                self._write(data)
            return data

    def get(self, message_id: str) -> dict | None:
        return self._read().get(message_id)


def check_pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM


def read_hold_pid(pid_file: str | Path) -> int | None:
    p = Path(pid_file)
    if not p.is_file():
        return None
    try:
        return int(p.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def write_wake_artifacts(
    wake_dir: str | Path,
    *,
    message_id: str,
    prompt_id: str | None,
    stop_reason: str | None,
    reply_text: str,
    source_kind: str = "channel_turn",
    now_epoch: float | None = None,
    wake_filename: str = "WAKE.md",
    reply_prefix: str = "reply_",
) -> dict:
    """Write ``<reply_prefix><timestamp>.md`` and update the wake file in ``wake_dir``."""
    joint = Path(wake_dir)
    joint.mkdir(parents=True, exist_ok=True)
    ts = time.time() if now_epoch is None else float(now_epoch)
    dt_utc = datetime.fromtimestamp(ts, timezone.utc)  # noqa: UP017
    dt_loc = datetime.fromtimestamp(ts, ZoneInfo(LOCAL_ZONE))
    stamp = dt_loc.strftime("%Y-%m-%dT%H-%M-%S")
    short_id = (message_id or prompt_id or uuid.uuid4().hex)[:16]
    safe_short = "".join(c for c in short_id if c.isalnum() or c in "_-") or "peerb"
    prefix = reply_prefix or "reply_"
    resp_name = f"{prefix}{stamp}_{safe_short}.md"
    resp_path = joint / resp_name
    wake_path = joint / (wake_filename or "WAKE.md")

    redacted_reply, rendered_ok = render_content(reply_text or "")
    body_text = str(redacted_reply) if rendered_ok else "[REDACTION_FAILED]"

    resp_content = (
        f"# Resposta da peera-peerb ({source_kind})\n\n"
        f"- **Quando (UTC):** `{dt_loc.isoformat(timespec='seconds')}`\n"
        f"- **Quando (UTC):** `{dt_utc.isoformat(timespec='seconds')}`\n"
        f"- **Message ID:** `{message_id}`\n"
        f"- **Prompt ID:** `{prompt_id or 'n/a'}`\n"
        f"- **Stop Reason:** `{stop_reason or 'n/a'}`\n\n"
        f"## Mensagem\n\n"
        f"{body_text.strip()}\n"
    )
    tmp_resp = resp_path.with_suffix(".md.tmp")
    tmp_resp.write_text(resp_content, encoding="utf-8")
    tmp_resp.replace(resp_path)

    preview = body_text.strip().replace("\n", " ")[:280]
    wake_content = (
        f"# WAKE — reply from the peer\n\n"
        f"- **updated_at_local:** `{dt_loc.isoformat(timespec='seconds')}`\n"
        f"- **updated_at_utc:** `{dt_utc.isoformat(timespec='seconds')}`\n"
        f"- **source_kind:** `{source_kind}`\n"
        f"- **message_id:** `{message_id}`\n"
        f"- **prompt_id:** `{prompt_id or 'n/a'}`\n"
        f"- **stop_reason:** `{stop_reason or 'n/a'}`\n"
        f"- **latest_file:** `{resp_path.name}`\n"
        f"- **latest_path:** `{resp_path}`\n\n"
        f"## Preview\n\n"
        f"{preview}\n"
    )
    tmp_wake = wake_path.with_suffix(".md.tmp")
    tmp_wake.write_text(wake_content, encoding="utf-8")
    tmp_wake.replace(wake_path)

    return {
        "resposta_file": str(resp_path),
        "resposta_name": resp_path.name,
        "wake_file": str(wake_path),
        "updated_at_local": dt_loc.isoformat(timespec="seconds"),
        "reply_verified": rendered_ok and bool(body_text.strip()),
    }


def recover_reply_from_updates_jsonl(
    updates_path: str | Path,
    *,
    outbound_text: str,
    prompt_id: str | None = None,
    min_timestamp: float = 0.0,
    tail_bytes: int = 8 * 1024 * 1024,
) -> dict | None:
    """Read-only recovery of peerb's reply from updates.jsonl when stream is cut or late."""
    p = Path(updates_path)
    if not p.is_file():
        return None
    try:
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > tail_bytes:
                fh.seek(size - tail_bytes)
                fh.readline()  # discard partial first line
            raw_lines = fh.read().splitlines()
    except OSError:
        return None

    target_prompt_id = prompt_id
    found_user = target_prompt_id is not None
    chunks: list[str] = []
    stop_reason: str | None = None

    for raw in raw_lines:
        if not raw.strip():
            continue
        try:
            d = json.loads(raw)
        except Exception:
            continue
        ts = float(d.get("timestamp") or 0)
        if min_timestamp and ts < min_timestamp - 5:
            continue
        params = d.get("params") if isinstance(d.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        upd = params.get("update") if isinstance(params.get("update"), dict) else {}
        su = upd.get("sessionUpdate")

        if not found_user and su == "user_message_chunk":
            content = upd.get("content") if isinstance(upd.get("content"), dict) else {}
            if content.get("text") == outbound_text:
                found_user = True
            continue

        if found_user and target_prompt_id is None:
            pid = meta.get("promptId") or upd.get("prompt_id")
            if isinstance(pid, str) and pid:
                target_prompt_id = pid

        if target_prompt_id is not None:
            pid = meta.get("promptId") or upd.get("prompt_id")
            if pid != target_prompt_id:
                continue
            if su == "agent_message_chunk":
                content = upd.get("content") if isinstance(upd.get("content"), dict) else {}
                text = content.get("text")
                if isinstance(text, str) and text:
                    chunks.append(text)
            elif su == "turn_completed":
                stop_reason = upd.get("stop_reason") or upd.get("stopReason") or "end_turn"

    if not chunks and not stop_reason:
        return None
    return {
        "prompt_id": target_prompt_id,
        "stop_reason": stop_reason,
        "reply_text": "\n\n".join(chunks) if len(chunks) > 1 else ("".join(chunks)),
        "chunk_count": len(chunks),
    }


@dataclass
class AcpTurnResult:
    message_id: str
    session_id: str
    outbound_text: str
    init_ok: bool = False
    load_ok: bool = False
    load_meta_session: str | None = None
    delivered: bool = False
    queued: bool = False
    prompt_id: str | None = None
    stop_reason: str | None = None
    reply_text_redacted: str = ""
    reply_verified: bool = False
    reply_source: str = "none"
    perm_seen_n: int = 0
    perm_answered_n: int = 0
    approvals_n: int = 0
    approvals: list[dict] = field(default_factory=list)
    envelope_kind: str = "recado"
    wake_origin_denied_n: int = 0
    pending_card: dict | None = None
    pending_card_error: str | None = None
    oversized_frames_skipped: int = 0
    malformed_frames_skipped: int = 0
    elapsed_s: float = 0.0
    wake_artifacts: dict | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "session_id": self.session_id,
            "init_ok": self.init_ok,
            "load_ok": self.load_ok,
            "load_meta_session": self.load_meta_session,
            "delivered": self.delivered,
            "queued": self.queued,
            "prompt_id": self.prompt_id,
            "stop_reason": self.stop_reason,
            "reply_text_redacted": self.reply_text_redacted,
            "reply_len": len(self.reply_text_redacted),
            "reply_verified": self.reply_verified,
            "reply_source": self.reply_source,
            "perm_seen_n": self.perm_seen_n,
            "perm_answered_n": self.perm_answered_n,
            "approvals_n": self.approvals_n,
            "approvals": self.approvals[:40],
            "envelope_kind": self.envelope_kind,
            "envelope_auto_answer_permission": False,
            "wake_origin_denied_n": self.wake_origin_denied_n,
            "pending_card": self.pending_card,
            "pending_card_error": self.pending_card_error,
            "oversized_frames_skipped": self.oversized_frames_skipped,
            "malformed_frames_skipped": self.malformed_frames_skipped,
            "elapsed_s": round(self.elapsed_s, 2),
            "wake_artifacts": self.wake_artifacts,
            "error": self.error,
        }


def build_outbound_text(cfg: ChannelConfig, message_id: str, body: str) -> str:
    validate_body(body, cfg.max_body_bytes)
    expected_prefix = f"{cfg.sender}: "
    if cfg.prefix != expected_prefix:
        raise ChannelError("prefix_must_match_sender")
    if cfg.auth_mode == "hmac":
        if not cfg.hmac_key_file:
            raise ChannelError("hmac_key_file_required")
        key = load_key(cfg.hmac_key_file)
        return sign_text(
            key,
            prefix=cfg.prefix,
            sender=cfg.sender,
            session_id=cfg.session_id,
            message_id=message_id,
            body=body,
        )
    return cfg.prefix + body


def _approvals_since(approvals_path: str | Path, t0: float) -> list[dict]:
    p = Path(approvals_path)
    if not p.is_file():
        return []
    rows: list[dict] = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if float(rec.get("ts") or 0) >= t0:
                rows.append(
                    {
                        "kind": rec.get("tool_kind"),
                        "title": redact_text(str(rec.get("title") or "")[:180]),
                        "reason": rec.get("reason"),
                        "ts": rec.get("ts"),
                    }
                )
    except OSError:
        pass
    return rows


def _daemon_ipc_ready(cfg: ChannelConfig) -> bool:
    if not cfg.use_daemon_ipc or not cfg.state_dir or not cfg.ipc_key_file:
        return False
    sock = Path(cfg.state_dir) / "broker.sock"
    key = Path(cfg.ipc_key_file)
    if not sock.exists() or not key.is_file():
        return False
    try:
        st = sock.lstat()
        return (
            stat.S_ISSOCK(st.st_mode)
            and st.st_uid == os.getuid()
            and stat.S_IMODE(st.st_mode) == 0o600
        )
    except OSError:
        return False


def _run_via_daemon_ipc(
    cfg: ChannelConfig,
    mid: str,
    body: str,
    *,
    write_wake: bool = True,
) -> dict:
    from types import SimpleNamespace

    from firefly_bridge.ipc import ipc_call

    ipc_cfg = SimpleNamespace(
        state_dir=cfg.state_dir,
        ipc_key_file=cfg.ipc_key_file,
        ipc_principal=cfg.ipc_principal,
        session_id=cfg.session_id,
    )
    t0 = time.time()
    envelope = parse_wake_envelope(body)
    enq = ipc_call(ipc_cfg, "enqueue", {"message_id": mid, "body": body, "wake_origin": True})
    if "error" in enq or enq.get("queue_state") in ("refused", "failed", "cancelled", "closed"):
        return {
            "mode": "daemon_ipc",
            "message_id": mid,
            "session_id": cfg.session_id,
            "delivered": False,
            "queued": False,
            "stop_reason": enq.get("stop_reason"),
            "error": enq.get("error") or enq.get("reason") or "enqueue_refused",
            "receipt": enq,
        }
    deadline = t0 + cfg.turn_timeout_s
    rec = enq
    while time.time() < deadline:
        qstate = rec.get("queue_state")
        if qstate in ("delivered", "cancelled", "failed", "closed"):
            break
        time.sleep(min(0.1, max(0.01, deadline - time.time())))
        rec = ipc_call(ipc_cfg, "receipt", {"message_id": mid})
        if "error" in rec:
            break

    qstate = rec.get("queue_state")
    delivered = qstate == "delivered"
    stop_reason = rec.get("stop_reason") or ("end_turn" if delivered else None)
    reply_redacted = str(rec.get("reply_redacted") or "")
    prompt_id = rec.get("prompt_id")
    wake_art = rec.get("wake_artifacts")
    if write_wake and wake_art is None and cfg.wake_dir and (reply_redacted or stop_reason):
        wake_art = write_wake_artifacts(
            cfg.wake_dir,
            message_id=mid,
            prompt_id=prompt_id,
            stop_reason=stop_reason,
            reply_text=reply_redacted,
            source_kind="daemon_ipc_turn",
            wake_filename=cfg.wake_filename,
            reply_prefix=cfg.reply_prefix,
        )
    return {
        "mode": "daemon_ipc",
        "message_id": mid,
        "session_id": cfg.session_id,
        "init_ok": True,
        "load_ok": True,
        "load_meta_session": cfg.session_id,
        "delivered": delivered,
        "queued": qstate in ("queued", "in_flight", "delivered", "unknown"),
        "prompt_id": prompt_id,
        "stop_reason": stop_reason,
        "reply_text_redacted": reply_redacted,
        "reply_len": len(reply_redacted),
        "reply_verified": bool(rec.get("reply_verified")),
        "reply_source": rec.get("reply_recovery") or "daemon_ipc",
        "perm_seen_n": count_permission_requests(rec.get("permission_events") or []),
        "perm_answered_n": sum(
            1 for e in (rec.get("permission_events") or []) if e.get("phase") == "response_sent"
        ),
        "approvals_n": count_real_approvals(rec.get("permission_events") or []),
        "approvals": list(rec.get("permission_events") or []),
        "envelope_kind": envelope.kind,
        "envelope_auto_answer_permission": False,
        "wake_origin_denied_n": count_wake_origin_denied(rec.get("permission_events") or []),
        "pending_card": rec.get("pending_card"),
        "oversized_frames_skipped": 0,
        "malformed_frames_skipped": 0,
        "elapsed_s": round(time.time() - t0, 2),
        "wake_artifacts": wake_art,
        "error": None if delivered else (rec.get("reason") or rec.get("error")),
    }


def run_channel_turn(
    cfg: ChannelConfig,
    body: str,
    *,
    message_id: str | None = None,
    dry_run: bool = False,
    spawn_cmd: list[str] | None = None,
    write_wake: bool = True,
) -> dict:
    """Execute a Channel turn (or dry-run / mock turn) and return a JSON-safe receipt."""
    cfg = cfg.resolved()
    mid = message_id or new_message_id()
    envelope = parse_wake_envelope(body)
    outbound = build_outbound_text(cfg, mid, body)
    hold_pid = read_hold_pid(cfg.hold_pid_file)
    hold_alive = check_pid_alive(hold_pid)
    daemon_ipc_ready = _daemon_ipc_ready(cfg)

    sock_path = Path(cfg.socket_path)
    sock_exists = sock_path.exists()
    sock_ok = False
    if sock_exists:
        st = sock_path.lstat()
        sock_ok = (
            stat.S_ISSOCK(st.st_mode)
            and st.st_uid == os.getuid()
            and (stat.S_IMODE(st.st_mode) & 0o077) == 0
        )

    if dry_run:
        return {
            "mode": "dry_run",
            "live_bytes_written": False,
            "message_id": mid,
            "session_id": cfg.session_id,
            "sender": cfg.sender,
            "prefix_ok": outbound.startswith(cfg.prefix),
            "outbound_preview": redact_text(outbound[:240]),
            "outbound_bytes": len(outbound.encode("utf-8")),
            "socket_path": cfg.socket_path,
            "socket_exists": sock_exists,
            "socket_private_owned": sock_ok,
            "daemon_ipc_ready": daemon_ipc_ready,
            "hold_pid": hold_pid,
            "hold_alive": hold_alive,
            # What actually answers a wake-origin permission on this route. Wake
            # tools are always denied; answer_permissions/permission_mode do not apply.
            "permission_handler": "wake_origin_deny" if daemon_ipc_ready else "leader_stdio_wake_deny",
            # Stdio route with the hold alive: the hold may answer the same request id.
            "hold_race": bool(hold_alive and not daemon_ipc_ready),
            "permission_mode": cfg.permission_mode,
            "envelope_kind": envelope.kind,
            "envelope_auto_answer_permission": False,
            "wake_dir": cfg.wake_dir,
            "wake_target": str(Path(cfg.wake_dir) / "WAKE.md"),
            "ready_for_live": bool(daemon_ipc_ready or sock_ok),
        }

    if spawn_cmd is None and daemon_ipc_ready:
        return _run_via_daemon_ipc(cfg, mid, body, write_wake=write_wake)

    if spawn_cmd is None:
        if not sock_exists:
            raise ChannelError("leader_socket_missing")
        if not sock_ok:
            raise ChannelError("leader_socket_not_private_owned_socket")
        spawn_cmd = [
            cfg.grok_bin,
            "agent",
            "--leader",
            "--leader-socket",
            cfg.socket_path,
            "stdio",
        ]

    ledger = ChannelLedger(cfg.ledger_path)
    claimed, existing_rec, _ = ledger.claim(
        mid,
        {
            "session_id": cfg.session_id,
            "source": cfg.sender,
            "text": redact_text(outbound),
            "which": "channel",
            "stopReason": None,
        },
    )
    if not claimed:
        return {
            "mode": "already_claimed_no_resend",
            "resend_attempted": False,
            "message_id": mid,
            "existing_receipt": safe(existing_rec),
        }

    # Wake turn: never auto-approve. answer_permissions / permission_mode must
    # not select allow_once here. Deny wake-origin so no clickable Allow sits.

    env = os.environ.copy()
    if cfg.strip_grok_sandbox:
        env.pop("GROK_SANDBOX", None)
    if os.path.isabs(cfg.grok_bin):
        env["PATH"] = os.path.dirname(cfg.grok_bin) + os.pathsep + env.get("PATH", "")

    cwd = cfg.session_cwd if cfg.session_cwd and Path(cfg.session_cwd).is_dir() else os.getcwd()
    t0 = time.time()
    res = AcpTurnResult(
        message_id=mid,
        session_id=cfg.session_id,
        outbound_text=outbound,
        envelope_kind=envelope.kind,
    )

    proc = subprocess.Popen(
        spawn_cmd,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    assert proc.stdin is not None and proc.stdout is not None

    buf = b""
    skipping_oversized = False
    skipped_bytes = 0
    results_by_id: dict = {}
    agent_chunks: list[str] = []
    current_msg_parts: list[str] = []
    last_chunk_id: int | None = None
    active_prompt_id: str | None = None
    prompt_sent = False
    turn_running_ours = False

    def flush_current_msg() -> None:
        nonlocal last_chunk_id
        if current_msg_parts:
            combined = "".join(current_msg_parts).strip()
            if combined:
                agent_chunks.append(combined)
            current_msg_parts.clear()
        last_chunk_id = None

    def send_frame(frame: dict) -> None:
        data = (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8")
        proc.stdin.write(data)
        proc.stdin.flush()

    def handle_frame(raw_line: bytes) -> None:
        nonlocal active_prompt_id, turn_running_ours, last_chunk_id
        line = raw_line.strip()
        if not line:
            return
        try:
            msg = json.loads(line)
        except Exception:
            res.malformed_frames_skipped += 1
            return
        if not isinstance(msg, dict):
            res.malformed_frames_skipped += 1
            return

        if "id" in msg and "method" in msg:
            method = msg.get("method")
            if method == "session/request_permission":
                res.perm_seen_n += 1
                if turn_running_ours or prompt_sent:
                    send_frame(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "result": wake_origin_permission_result(msg),
                        }
                    )
                    res.perm_answered_n += 1
                    res.wake_origin_denied_n += 1
                    card = pending_card_from_request(
                        msg,
                        envelope=envelope,
                        message_id=mid,
                        sender=cfg.sender,
                    )
                    res.pending_card = card
                    res.approvals.append(card)
                    if cfg.pending_card_path:
                        try:
                            write_pending_card(cfg.pending_card_path, card)
                        except OSError as exc:
                            res.pending_card_error = type(exc).__name__
                return
            send_frame(
                {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32601, "message": "agent channel client"},
                }
            )
            return

        if "id" in msg and ("result" in msg or "error" in msg):
            results_by_id[msg["id"]] = msg
            return

        method = msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        if method == "_x.ai/queue/changed":
            entries = params.get("entries") if isinstance(params.get("entries"), list) else []
            for entry in entries:
                if isinstance(entry, dict) and entry.get("text") == outbound:
                    res.queued = True
                    if isinstance(entry.get("id"), str):
                        active_prompt_id = entry["id"]
                        res.prompt_id = active_prompt_id
            running_text = params.get("runningText") or ""
            running_id = params.get("runningPromptId")
            if isinstance(running_text, str) and running_text == outbound:
                res.queued = True
                turn_running_ours = True
                if isinstance(running_id, str):
                    active_prompt_id = running_id
                    res.prompt_id = active_prompt_id
            elif isinstance(running_text, str) and running_text.startswith(cfg.prefix):
                turn_running_ours = True
            return

        if method == "_x.ai/session/prompt_complete":
            pid = params.get("promptId")
            if active_prompt_id and pid == active_prompt_id:
                if not res.stop_reason and isinstance(params.get("stopReason"), str):
                    res.stop_reason = params["stopReason"]
            return

        if method in ("session/update", "_x.ai/session/update") and prompt_sent:
            if params.get("sessionId") and params.get("sessionId") != cfg.session_id:
                return
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            upd = params.get("update") if isinstance(params.get("update"), dict) else {}
            su = upd.get("sessionUpdate")
            pid = meta.get("promptId") or upd.get("prompt_id")

            if su == "turn_completed":
                flush_current_msg()
                if active_prompt_id and pid == active_prompt_id:
                    sr = upd.get("stop_reason") or upd.get("stopReason")
                    if isinstance(sr, str) and not res.stop_reason:
                        res.stop_reason = sr
                return

            if su in ("tool_call", "agent_thought_chunk"):
                if not active_prompt_id or not pid or pid == active_prompt_id:
                    flush_current_msg()
                return

            if su == "agent_message_chunk":
                # If we know our promptId from queue/changed, filter strictly by it;
                # otherwise accept agent_message_chunk after our prompt was sent.
                if active_prompt_id and pid and pid != active_prompt_id:
                    return
                if not active_prompt_id and isinstance(pid, str) and pid:
                    active_prompt_id = pid
                    res.prompt_id = pid
                cid = meta.get("chunkId")
                if (
                    isinstance(cid, int)
                    and last_chunk_id is not None
                    and cid <= last_chunk_id
                ):
                    flush_current_msg()
                if isinstance(cid, int):
                    last_chunk_id = cid
                content = upd.get("content")
                text_piece = None
                if isinstance(content, dict) and content.get("type") == "text":
                    text_piece = content.get("text")
                elif isinstance(content, str):
                    text_piece = content
                if isinstance(text_piece, str) and text_piece:
                    current_msg_parts.append(text_piece)

    def pump_until(deadline: float, stop_when_id=None) -> None:
        nonlocal buf, skipping_oversized, skipped_bytes
        while time.time() < deadline:
            if stop_when_id is not None and stop_when_id in results_by_id:
                return
            if proc.poll() is not None and not buf:
                return
            wait = min(0.25, max(0.0, deadline - time.time()))
            r, _, _ = select.select([proc.stdout], [], [], wait)
            if not r:
                continue
            try:
                chunk = os.read(proc.stdout.fileno(), 65536)
            except OSError:
                return
            if not chunk:
                return
            if skipping_oversized:
                nl = chunk.find(b"\n")
                if nl == -1:
                    skipped_bytes += len(chunk)
                    if skipped_bytes > cfg.max_oversized_skip_bytes:
                        raise ChannelError("oversized_frame_exceeded_skip_cap")
                    continue
                skipping_oversized = False
                skipped_bytes = 0
                buf = chunk[nl + 1 :]
            else:
                buf += chunk

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if len(line) > cfg.max_frame_bytes:
                    res.oversized_frames_skipped += 1
                    continue
                handle_frame(line)
                if stop_when_id is not None and stop_when_id in results_by_id:
                    return

            if len(buf) > cfg.max_frame_bytes:
                res.oversized_frames_skipped += 1
                skipping_oversized = True
                skipped_bytes = len(buf)
                buf = b""

    try:
        send_frame(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "0.1.0",
                    "clientInfo": {"name": "firefly-bridge", "version": __version__},
                    "capabilities": {},
                },
            }
        )
        pump_until(time.time() + cfg.connect_timeout_s, stop_when_id=1)
        init_msg = results_by_id.get(1)
        if not init_msg or "result" not in init_msg:
            res.error = "initialize_failed"
            ledger.update(mid, outcome="unknown", block_code="initialize_failed")
            return res.to_dict()
        res.init_ok = True

        send_frame({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        pump_until(time.time() + 0.2)

        send_frame(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/load",
                "params": {
                    "sessionId": cfg.session_id,
                    "cwd": cwd,
                    "mcpServers": [],
                },
            }
        )
        pump_until(time.time() + cfg.load_timeout_s, stop_when_id=2)
        load_msg = results_by_id.get(2)
        if not load_msg or "result" not in load_msg:
            res.error = "session_load_failed"
            ledger.update(mid, outcome="unknown", block_code="session_load_failed")
            return res.to_dict()
        res.load_ok = True
        load_res = load_msg.get("result")
        if isinstance(load_res, dict):
            meta = load_res.get("_meta") if isinstance(load_res.get("_meta"), dict) else {}
            res.load_meta_session = meta.get("sessionId")
            if res.load_meta_session and res.load_meta_session != cfg.session_id:
                res.error = "session_id_mismatch"
                ledger.update(mid, outcome="unknown", block_code="session_id_mismatch")
                return res.to_dict()

        # Drain any trailing load replay frames briefly before sending our prompt
        pump_until(time.time() + 0.3)
        current_msg_parts.clear()
        agent_chunks.clear()
        last_chunk_id = None
        prompt_sent = True

        send_frame(
            {
                "jsonrpc": "2.0",
                "id": mid,
                "method": "session/prompt",
                "params": {
                    "sessionId": cfg.session_id,
                    "prompt": [{"type": "text", "text": outbound}],
                },
            }
        )
        pump_until(time.time() + cfg.turn_timeout_s, stop_when_id=mid)
        prompt_msg = results_by_id.get(mid)

        if prompt_msg and "result" in prompt_msg:
            res.delivered = True
            p_res = prompt_msg["result"]
            if isinstance(p_res, dict):
                res.stop_reason = p_res.get("stopReason") or res.stop_reason
                p_meta = p_res.get("_meta") if isinstance(p_res.get("_meta"), dict) else {}
                if not res.prompt_id and isinstance(p_meta.get("promptId"), str):
                    res.prompt_id = p_meta["promptId"]
        elif prompt_msg and "error" in prompt_msg:
            res.stop_reason = "error"
            res.error = "rpc_error"

        flush_current_msg()
        raw_reply = "\n\n".join(agent_chunks) if len(agent_chunks) > 1 else "".join(agent_chunks)
        if raw_reply:
            res.reply_source = "acp_stream"
        elif cfg.updates_jsonl_path:
            recovered = recover_reply_from_updates_jsonl(
                cfg.updates_jsonl_path,
                outbound_text=outbound,
                prompt_id=res.prompt_id,
                min_timestamp=t0,
            )
            if recovered and recovered.get("reply_text"):
                raw_reply = recovered["reply_text"]
                res.reply_source = "updates_jsonl_recovery"
                if not res.stop_reason and recovered.get("stop_reason"):
                    res.stop_reason = recovered["stop_reason"]
                    res.delivered = True
                if not res.prompt_id and recovered.get("prompt_id"):
                    res.prompt_id = recovered["prompt_id"]

        rendered, ok = render_content(raw_reply)
        res.reply_text_redacted = str(rendered) if ok else "[REDACTION_FAILED]"
        res.reply_verified = bool(ok and raw_reply.strip())
        logged = _approvals_since(cfg.approvals_log_path, t0)
        if logged:
            res.approvals.extend(logged)
        res.approvals_n = sum(1 for a in res.approvals if a.get("action") != "deny")
        res.elapsed_s = time.time() - t0

        ledger.update(
            mid,
            outcome="responded" if res.stop_reason else "unknown",
            stopReason=res.stop_reason,
            promptId=res.prompt_id,
            perm_seen_n=res.perm_seen_n,
            approvals_n=res.approvals_n,
            reply_len=len(res.reply_text_redacted),
            reply_source=res.reply_source,
        )

        if write_wake and (res.reply_verified or res.stop_reason):
            res.wake_artifacts = write_wake_artifacts(
                cfg.wake_dir,
                message_id=mid,
                prompt_id=res.prompt_id,
                stop_reason=res.stop_reason,
                reply_text=raw_reply,
                source_kind="channel_turn",
                wake_filename=cfg.wake_filename,
                reply_prefix=cfg.reply_prefix,
            )

        return res.to_dict()
    finally:
        for pipe in (proc.stdin, proc.stdout):
            if pipe is not None:
                try:
                    pipe.close()
                except Exception:
                    pass
        try:
            proc.send_signal(signal.SIGTERM)
        except Exception:
            pass
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def sync_late_replies(
    cfg: ChannelConfig,
    *,
    state_file: str | Path | None = None,
) -> dict:
    """Scan updates.jsonl and inbound/ for new peerb replies to agent-a and write wake files.

    Covers:
      1. Any agent-a-prefixed turn in `updates.jsonl` that settled after the client timed out.
      2. Any new note in `memory/shared/inbound/*agent*.md` written by peerb on her own.
    """
    cfg = cfg.resolved()
    joint = Path(cfg.wake_dir)
    joint.mkdir(parents=True, exist_ok=True)
    st_path = Path(state_file) if state_file else (joint / ".wake_watch_state.json")

    state = {"seen_prompt_ids": [], "seen_files": {}, "last_offset": 0}
    first_run = not st_path.is_file()
    if not first_run:
        try:
            loaded = json.loads(st_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                state.update(loaded)
                first_run = "last_initialized" not in loaded
        except Exception:
            first_run = True

    seen_prompts = set(state.get("seen_prompt_ids") or [])
    seen_files = dict(state.get("seen_files") or {})
    woken: list[dict] = []

    # Also seed promptIds already recorded as responded in the channel ledger
    # so we never duplicate a wake file for a turn that already finished synchronously.
    ledger_file = Path(cfg.ledger_path)
    if ledger_file.is_file():
        try:
            ledger_data = json.loads(ledger_file.read_text(encoding="utf-8") or "{}")
            if isinstance(ledger_data, dict):
                for entry in ledger_data.values():
                    if isinstance(entry, dict) and entry.get("outcome") in (
                        "responded",
                        "responded_after_unstick",
                    ):
                        for key in ("promptId", "leader_prompt_id", "prompt_id"):
                            val = entry.get(key)
                            if isinstance(val, str) and val:
                                seen_prompts.add(val)
        except Exception:
            pass

    # 1. Check updates.jsonl for completed agent-a turns not yet woken
    upd_path = Path(cfg.updates_jsonl_path)
    if upd_path.is_file():
        try:
            size = upd_path.stat().st_size
            offset = int(state.get("last_offset") or 0)
            if offset < 0 or offset > size:
                offset = max(0, size - 4 * 1024 * 1024)
            with upd_path.open("rb") as fh:
                fh.seek(offset)
                if offset > 0:
                    fh.readline()
                lines = fh.read().splitlines()

            now_epoch = time.time()
            sender_active = False
            cur_pid: str | None = None
            cur_chunks: list[str] = []
            for raw in lines:
                if not raw.strip():
                    continue
                try:
                    d = json.loads(raw)
                except Exception:
                    continue
                ev_ts = float(d.get("timestamp") or 0.0)
                params = d.get("params") if isinstance(d.get("params"), dict) else {}
                meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
                upd = params.get("update") if isinstance(params.get("update"), dict) else {}
                su = upd.get("sessionUpdate")
                if su == "user_message_chunk":
                    txt = (upd.get("content") or {}).get("text") or ""
                    sender_active = isinstance(txt, str) and txt.startswith(cfg.prefix)
                    cur_pid = None
                    cur_chunks = []
                elif sender_active and su == "agent_message_chunk":
                    pid = meta.get("promptId")
                    if isinstance(pid, str) and pid:
                        cur_pid = pid
                    txt = (upd.get("content") or {}).get("text") or ""
                    if isinstance(txt, str) and txt:
                        cur_chunks.append(txt)
                elif sender_active and su == "turn_completed":
                    pid = upd.get("prompt_id") or meta.get("promptId") or cur_pid
                    sr = upd.get("stop_reason") or upd.get("stopReason") or "end_turn"
                    if pid and pid not in seen_prompts and cur_chunks:
                        # On first run, seed turns older than 1 hour without waking
                        if first_run and ev_ts > 0 and (now_epoch - ev_ts) > 3600:
                            seen_prompts.add(pid)
                        else:
                            art = write_wake_artifacts(
                                joint,
                                message_id=f"prompt_{pid[:16]}",
                                prompt_id=pid,
                                stop_reason=sr,
                                reply_text="\n\n".join(cur_chunks),
                                source_kind="late_turn_updates_jsonl",
                                wake_filename=cfg.wake_filename,
                                reply_prefix=cfg.reply_prefix,
                            )
                            seen_prompts.add(pid)
                            woken.append(art)
                    sender_active = False
                    cur_pid = None
                    cur_chunks = []
            state["last_offset"] = max(0, size - 65536)
        except OSError:
            pass

    # 2. Check memory/shared/inbound/ for new files addressed to agent-a
    inbound = Path(cfg.session_cwd) / (cfg.inbound_dir or "memory/shared/inbound")
    if inbound.is_dir():
        for md in sorted(inbound.glob("*.md")):
            try:
                mtime = md.stat().st_mtime
            except OSError:
                continue
            prev_mtime = float(seen_files.get(md.name) or 0.0)
            if prev_mtime == 0.0 and "last_initialized" not in state:
                # Seed existing files on first run without re-triggering old history
                seen_files[md.name] = mtime
                continue
            if mtime > prev_mtime:
                try:
                    content = md.read_text(encoding="utf-8")
                except OSError:
                    continue
                art = write_wake_artifacts(
                    joint,
                    message_id=f"file_{md.stem[:24]}",
                    prompt_id=None,
                    stop_reason="file_drop",
                    reply_text=content,
                    source_kind=f"inbound:{md.name}",
                    wake_filename=cfg.wake_filename,
                    reply_prefix=cfg.reply_prefix,
                    now_epoch=mtime,
                )
                seen_files[md.name] = mtime
                woken.append(art)

    state["seen_prompt_ids"] = sorted(seen_prompts)[-200:]
    state["seen_files"] = seen_files
    state["last_initialized"] = time.time()
    tmp_st = st_path.with_suffix(".tmp")
    tmp_st.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    tmp_st.replace(st_path)

    return {
        "ok": True,
        "woken_count": len(woken),
        "woken": woken,
        "state_file": str(st_path),
    }

# Backward-compatible aliases (older drafts).
run_channel = run_channel_turn
harvest_late_replies = sync_late_replies
