"""Private local broker and experimental ACP attestation adapter.

No real leader support is assumed: missing capabilities/state blocks dispatch.
Timeout never cancels. Prefix and local waiting state never establish ownership.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from firefly_bridge import __version__
from firefly_bridge.audit import LOCAL_ZONE, fingerprint, local_time, tool_metadata
from firefly_bridge.authority import AuthorityError, TargetAuthority, canonical_target
from firefly_bridge.broker_store import BrokerStore, StoreError
from firefly_bridge.config import BridgeConfig, ConfigError, load_config
from firefly_bridge.envelope import KeyFileError, load_key, sign_text
from firefly_bridge.errors import PreSendRejected
from firefly_bridge.ipc import IpcServer
from firefly_bridge.permissions import (
    PermissionPolicy,
    denied_decision,
    extract_paths,
    selected_result,
)
from firefly_bridge.privacy import render_content, safe, validate_body
from firefly_bridge.protected import LAWS, protected_paths_reason
from firefly_bridge.queue import (
    BusyRefused,
    Outbox,
    Turn,
    TurnTimeout,
)
from firefly_bridge.queue_store import load_queue_state_path
from firefly_bridge.recovery import ChatHistory, ReplyLocator, UnavailableChatHistory, recover_reply
from firefly_bridge.rpc import ConnectionClosed, JsonRpcConnection
from firefly_bridge.wake_envelope import (
    WAKE_ORIGIN_DENY_REASON,
    body_marks_wake_origin,
    parse_wake_envelope,
    pending_card_from_request,
    wake_origin_permission_decision,
    wake_origin_permission_result,
    write_pending_card,
)


class DaemonError(RuntimeError):
    pass


class AcpSession:
    """One live ACP client attached to a pinned session."""

    def __init__(
        self,
        cfg: BridgeConfig,
        *,
        policy: PermissionPolicy | None = None,
        chat_history: ChatHistory | None = None,
    ) -> None:
        self.cfg = cfg.validate(require_target=False)
        # Broker-owned guard cannot be disabled by selecting/injecting a policy.
        self.protection = PermissionPolicy(
            mode="pending",
            protected_tools_enabled=cfg.protected_tools_enabled,
            base_dir=cfg.session_cwd or os.getcwd(),
            **cfg.protected_resources(),
        )
        self.policies = {}
        for sender in self.cfg.agent_names():
            mode = cfg.permission_mode_for(sender)
            if mode in ("allow_all", "allow_all_own_turns"):
                print(
                    f"!!! DANGER: {sender} allow_all_own_turns AUTO-APPROVES ELIGIBLE TOOLS/PATHS "
                    "ONLY ON ITS ATTESTED BRIDGE-INITIATED TURNS, SUBJECT TO THE PROTECTED-TOOL GATE. NOT HUMAN APPROVAL. "
                    "Public default is pending. !!!",
                    file=sys.stderr,
                )
            self.policies[sender] = PermissionPolicy(
                mode=mode,
                shared_dir=cfg.shared_dir,
                allowed_tool_kinds=list(cfg.allowed_tool_kinds),
                base_dir=cfg.session_cwd or os.getcwd(),
                protected_tools_enabled=cfg.protected_tools_enabled,
                **cfg.protected_resources(),
            )
        if policy is not None:
            # Test/embedding injection affects only cfg.sender, never other clients.
            self.policies[cfg.sender] = policy
        self.chat_history = chat_history or UnavailableChatHistory()
        self._reply_parse_failed = False
        self._malformed_baseline = 0
        self._terminal_cache = None
        self.proc: subprocess.Popen | None = None
        self.conn: JsonRpcConnection | None = None
        self._own_turn_lock = threading.RLock()
        self._own_turn: Turn | None = None
        self._pending_perms: dict = {}  # rpc id -> request
        self.permission_log: list[dict] = []
        self.alerts: list[dict] = []
        self.loaded_session_id: str | None = None
        self._hmac_key: bytes | None = None
        # Never infer ownership from text, a local waiter, or load replay.
        self._origin: dict | None = None
        self._running_turn_id: str | None = None
        self.incarnation: str | None = None
        self.turn_attestation_supported = False
        self.scoped_cancel_supported = False
        self.approval_receipts_path: Path | None = None
        self.atomic_admission_supported = False
        self.remote_state = "unknown"
        self.revision = None
        self.state_seq = -1
        self.state_observed_at = 0.0
        self.control_seq = -1
        self.active_call = None
        self.observation_expired = False
        self._reply_chunks = []
        self._reply_bytes = 0
        self._reply_seq = 0
        self._reply_gap = False
        self._answered_permissions = set()
        # --- stock_grok mode state (RC9 unified daemon) ---
        self._stock_prompt_id: str | None = None
        self._stock_turn_running: bool = False
        self._stock_msg_parts: list[str] = []
        self._stock_last_chunk_id: int | None = None
        self._stock_stop_reason: str | None = None
        self._stock_started_at: float = 0.0
        self.authority_dirs = ()
        self.authority_files = ()
        self.authority_allowed = lambda turn: False
        self.authority_respond = lambda turn, rid, result: False
        self.auto_allowed = lambda sender: False
        self.dispatch_allowed = lambda turn: False
        self.persist_claim = lambda turn, origin: (_ for _ in ()).throw(
            DaemonError("broker_required")
        )
        self.permission_claim = lambda turn_id, rid: False
        self.record_permission = lambda record: None
        self.on_control = lambda *args, **kwargs: None
        self.on_orphan_terminal = lambda params, update: None

    @property
    def policy(self):
        """Compatibility accessor for the configured single sender only."""
        return self.policies[self.cfg.sender]

    @policy.setter
    def policy(self, value):
        self.policies[self.cfg.sender] = value

    # ------------------------------------------------------------------
    def start(self) -> None:
        if not self.cfg.socket_path or not Path(self.cfg.socket_path).exists():
            raise DaemonError("leader_socket_missing")
        info = Path(self.cfg.socket_path).lstat()
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise DaemonError("leader_socket_not_private_owned_socket")
        env = os.environ.copy()
        if self.cfg.strip_grok_sandbox:
            env.pop("GROK_SANDBOX", None)
        # Never invent a PATH; only prepend the parent of an absolute grok_bin.
        if os.path.isabs(self.cfg.grok_bin):
            env["PATH"] = os.path.dirname(self.cfg.grok_bin) + os.pathsep + env.get("PATH", "")
        cwd = self.cfg.session_cwd or os.getcwd()
        try:
            self.proc = subprocess.Popen(
                [
                    self.cfg.grok_bin,
                    "agent",
                    "--leader",
                    "--leader-socket",
                    self.cfg.socket_path,
                    "stdio",
                ],
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise DaemonError("grok_binary_not_found") from exc
        assert self.proc.stdin and self.proc.stdout
        self.conn = JsonRpcConnection(
            self.proc.stdout,
            self.proc.stdin,
            on_notification=self._on_notification,
            on_request=self._on_request,
            max_frame_bytes=self.cfg.max_frame_bytes,
            skip_oversized=self.cfg.skip_oversized_frames,
        )
        self.conn.start()
        self._handshake()
        if self.cfg.auth_mode == "hmac":
            self._hmac_key = load_key(self.cfg.hmac_key_file)

    def _handshake(self) -> None:
        assert self.conn is not None
        init = self.conn.request(
            "initialize",
            {
                "protocolVersion": "0.1.0",
                "clientInfo": {"name": "firefly-bridge", "version": __version__},
                "capabilities": {},
            },
        )
        if not init.wait(self.cfg.connect_timeout_s) or init.closed or init.error:
            raise DaemonError("initialize_failed")
        capabilities = (
            (init.result or {}).get("capabilities", {}) if isinstance(init.result, dict) else {}
        )
        extension = capabilities.get("agentBridge", {}) if isinstance(capabilities, dict) else {}
        self.turn_attestation_supported = (
            isinstance(extension, dict) and extension.get("turnAttestation") == 1
        )
        self.scoped_cancel_supported = (
            isinstance(extension, dict) and extension.get("scopedCancel") is True
        )
        self.atomic_admission_supported = (
            isinstance(extension, dict) and extension.get("atomicAdmission") is True
        )
        # ACP requires the client to emit notifications/initialized; the method
        # is a notification, so we write it raw (it is not in DAEMON_CLIENT_METHODS
        # as a request). Keep it tiny and non-configurable.
        self.conn._write(  # noqa: SLF001 - intentional post-initialize notice
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        load = self.conn.request(
            "session/load",
            {
                "sessionId": self.cfg.session_id,
                "cwd": self.cfg.session_cwd or os.getcwd(),
                "mcpServers": [],
            },
        )
        if not load.wait(self.cfg.load_timeout_s) or load.closed or load.error:
            raise DaemonError("session_load_failed")
        meta = (load.result or {}).get("_meta") if isinstance(load.result, dict) else None
        if isinstance(meta, dict) and isinstance(meta.get("sessionId"), str):
            self.loaded_session_id = meta["sessionId"]
            if self.loaded_session_id != self.cfg.session_id:
                raise DaemonError("session_id_mismatch")
        else:
            self.loaded_session_id = None  # requested is not verified
        extension = meta.get("agentBridge", {}) if isinstance(meta, dict) else {}
        self.incarnation = extension.get("incarnation") if isinstance(extension, dict) else None
        if not isinstance(self.incarnation, str) or not self.incarnation:
            self.incarnation = None
        if self.cfg.adapter_mode == "stock_grok":
            if self.loaded_session_id is None:
                self.loaded_session_id = self.cfg.session_id
            if not self.incarnation:
                self.incarnation = "stock-grok-" + secrets.token_hex(8)
            self.remote_state = "idle"
            self.state_observed_at = time.monotonic()

    # ------------------------------------------------------------------
    def _flush_stock_msg(self) -> None:
        if self._stock_msg_parts:
            combined = "".join(self._stock_msg_parts).strip()
            if combined:
                try:
                    size = len(combined.encode("utf-8"))
                except UnicodeError:
                    self._reply_parse_failed = True
                else:
                    if self._reply_bytes + size <= self.cfg.max_reply_bytes:
                        self._reply_chunks.append(combined)
                        self._reply_bytes += size
                    else:
                        self._reply_parse_failed = True
                        self.alerts.append({"kind": "reply_limit_discarded"})
                        del self.alerts[:-100]
            self._stock_msg_parts.clear()
        self._stock_last_chunk_id = None

    def _on_stock_notification(self, msg: dict) -> None:
        method = msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        with self._own_turn_lock:
            own = self._own_turn
            if method == "_x.ai/queue/changed":
                entries = params.get("entries") if isinstance(params.get("entries"), list) else []
                running_text = params.get("runningText") or ""
                running_id = params.get("runningPromptId")
                if own is not None:
                    for entry in entries:
                        if isinstance(entry, dict) and entry.get("text") == own.outbound_text:
                            if isinstance(entry.get("id"), str):
                                self._stock_prompt_id = entry["id"]
                    if isinstance(running_text, str) and running_text == own.outbound_text:
                        self._stock_turn_running = True
                        if isinstance(running_id, str):
                            self._stock_prompt_id = running_id
                        self._running_turn_id = own.turn_id
                        self.remote_state = "busy"
                    elif not running_text and not entries and not self._stock_turn_running:
                        self.remote_state = "idle"
                        self.state_observed_at = time.monotonic()
                else:
                    if running_text or entries:
                        self.remote_state = "busy"
                    else:
                        self.remote_state = "idle"
                        self.state_observed_at = time.monotonic()
                return

            if method == "_x.ai/session/prompt_complete":
                pid = params.get("promptId")
                if own is not None and self._stock_prompt_id and pid == self._stock_prompt_id:
                    sr = params.get("stopReason")
                    if isinstance(sr, str) and not self._stock_stop_reason:
                        self._stock_stop_reason = sr
                return

            if method in ("session/update", "_x.ai/session/update") and own is not None:
                if params.get("sessionId") and params.get("sessionId") != self.cfg.session_id:
                    return
                meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
                upd = params.get("update") if isinstance(params.get("update"), dict) else {}
                su = upd.get("sessionUpdate")
                pid = meta.get("promptId") or upd.get("prompt_id")

                if su == "turn_completed":
                    self._flush_stock_msg()
                    if self._stock_prompt_id and pid == self._stock_prompt_id:
                        sr = upd.get("stop_reason") or upd.get("stopReason")
                        if isinstance(sr, str) and not self._stock_stop_reason:
                            self._stock_stop_reason = sr
                    return

                if su in ("tool_call", "agent_thought_chunk"):
                    if not self._stock_prompt_id or not pid or pid == self._stock_prompt_id:
                        self._flush_stock_msg()
                    return

                if su == "agent_message_chunk":
                    if self._stock_prompt_id and pid and pid != self._stock_prompt_id:
                        return
                    if not self._stock_prompt_id and isinstance(pid, str) and pid:
                        self._stock_prompt_id = pid
                        self._stock_turn_running = True
                        self._running_turn_id = own.turn_id
                    cid = meta.get("chunkId")
                    if (
                        isinstance(cid, int)
                        and self._stock_last_chunk_id is not None
                        and cid <= self._stock_last_chunk_id
                    ):
                        self._flush_stock_msg()
                    if isinstance(cid, int):
                        self._stock_last_chunk_id = cid
                    content = upd.get("content")
                    text_piece = None
                    if isinstance(content, dict) and content.get("type") == "text":
                        text_piece = content.get("text")
                    elif isinstance(content, str):
                        text_piece = content
                    if isinstance(text_piece, str) and text_piece:
                        self._stock_msg_parts.append(text_piece)

    def _on_notification(self, msg: dict) -> None:
        if self.cfg.adapter_mode == "stock_grok" and not self.turn_attestation_supported:
            self._on_stock_notification(msg)
            return
        if msg.get("method") != "session/update":
            return
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        outer = params.get("_meta")
        meta = outer.get("agentBridge") if isinstance(outer, dict) else None
        update = params.get("update")
        if not isinstance(update, dict) or not isinstance(meta, dict):
            return
        with self._own_turn_lock:
            verified_session = (
                self.turn_attestation_supported
                and self.incarnation
                and self.loaded_session_id == self.cfg.session_id
                and params.get("sessionId") == self.cfg.session_id
                and meta.get("incarnation") == self.incarnation
                and meta.get("replay") is not True
            )
            if not verified_session:
                return
            kind = update.get("sessionUpdate")
            if kind == "bridge_control":
                # Separate authenticated leader control, NEVER message/chunk text.
                seq = meta.get("controlSeq")
                actor, op = meta.get("actor"), update.get("op")
                if (
                    type(seq) is int
                    and seq > self.control_seq
                    and actor in ("human", "recipient")
                    and op in ("basta", "pause", "revoke", "opt_in")
                ):
                    try:
                        self.on_control(
                            actor,
                            op,
                            update.get("senders", list(self.cfg.agent_names())),
                            control_seq=seq,
                            incarnation=self.incarnation,
                        )
                    except StoreError:
                        return
                    self.control_seq = seq
                return
            if kind == "bridge_state":
                seq = meta.get("stateSeq")
                if type(seq) is int and seq > self.state_seq:
                    self.state_seq = seq
                    self.remote_state = (
                        update.get("state")
                        if update.get("state") in ("idle", "busy")
                        else "unknown"
                    )
                    revision = meta.get("revision")
                    self.revision = revision if isinstance(revision, str) and revision else None
                    self.state_observed_at = time.monotonic()
                return
            if kind == "turn_ended" and self._own_turn is None:
                self.on_orphan_terminal(params, update)
                self.remote_state = "unknown"
                self.revision = None
                return
            if kind == "turn_started":
                self._running_turn_id = (
                    self._origin["turnId"] if self._matches_origin(params, meta) else None
                )
                self.remote_state = "busy"
            if kind == "agent_message_chunk" and self._owns_permission(params):
                seq = meta.get("chunkSeq")
                content = update.get("content")
                if (
                    type(seq) is not int
                    or seq < 1
                    or not isinstance(content, dict)
                    or content.get("type") != "text"
                    or not isinstance(content.get("text"), str)
                ):
                    self._reply_parse_failed = True
                    return
                if seq <= self._reply_seq:
                    return  # Duplicate/replay never enters the reply.
                if seq != self._reply_seq + 1:
                    self._reply_gap = True
                    self._reply_parse_failed = True
                self._reply_seq = seq
                chunk = content["text"]
                try:
                    size = len(chunk.encode("utf-8"))
                except UnicodeError:
                    self._reply_parse_failed = True
                    return
                if self._reply_bytes + size <= self.cfg.max_reply_bytes:
                    self._reply_chunks.append(chunk)
                    self._reply_bytes += size
                else:
                    self._reply_parse_failed = True
                    self.alerts.append({"kind": "reply_limit_discarded"})
                    del self.alerts[:-100]

    def ready(self) -> bool:
        if self.cfg.adapter_mode == "stock_grok" and not self.turn_attestation_supported:
            return bool(
                self.cfg.live_send
                and self.conn is not None
                and not self.conn.closed.is_set()
                and self.loaded_session_id == self.cfg.session_id
                and self._own_turn is None
                and self.remote_state == "idle"
            )
        return bool(
            self.cfg.live_send
            and self.conn is not None
            and not self.conn.closed.is_set()
            and self.turn_attestation_supported
            and self.atomic_admission_supported
            and self.loaded_session_id == self.cfg.session_id
            and self.incarnation
            and self.remote_state == "idle"
            and self.revision
            and time.monotonic() - self.state_observed_at <= self.cfg.admission_max_age_s
        )

    def _matches_origin(self, params: dict, meta=None) -> bool:
        if meta is None:
            outer = params.get("_meta")
            meta = outer.get("agentBridge") if isinstance(outer, dict) else None
        return bool(
            self.cfg.live_send
            and self.turn_attestation_supported
            and self.loaded_session_id == self.cfg.session_id
            and self.incarnation
            and self._origin
            and isinstance(meta, dict)
            and meta.get("replay") is not True
            and params.get("sessionId") == self.cfg.session_id
            and all(meta.get(k) == v for k, v in self._origin.items())
        )

    def _owns_permission(self, params: dict) -> bool:
        if self.cfg.adapter_mode == "stock_grok" and not self.turn_attestation_supported:
            sess = params.get("sessionId")
            return bool(
                self.cfg.live_send
                and self._own_turn is not None
                and self._stock_turn_running
                and (not sess or sess == self.cfg.session_id)
            )
        return bool(
            self._own_turn
            and self._matches_origin(params)
            and self._running_turn_id == self._origin["turnId"]
        )

    def _authority_ok(self, own):
        try:
            return bool(self.authority_allowed(own))
        except Exception:
            return False

    def _permission_decision(self, msg, own):
        if getattr(own, "wake_origin", False):
            return wake_origin_permission_decision(msg)
        if not self._authority_ok(own):
            return denied_decision(msg, "authority_not_held")
        params = msg.get("params", {})
        tool = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
        # Authority is a broker invariant, not a configurable broad-mode privilege.
        reason = protected_paths_reason(
            extract_paths(tool),
            self.cfg.session_cwd or os.getcwd(),
            protected_dirs=self.authority_dirs,
            protected_files=self.authority_files,
        )
        if reason:
            return denied_decision(msg, reason)
        return self.protection.protected_decision(msg) or self.policies[own.sender].decide(
            msg, own_turn=True
        )

    def _pending_card_path(self) -> Path:
        return Path(self.cfg.state_dir) / "pending_card.json"

    def _deny_wake_origin(self, msg, own) -> None:
        """Wake-origin permission: same result as wake_origin_permission_result.

        agent-a deployment allow_all_own_turns / auto_allowed must not Allow.
        Missing reject_once becomes cancelled, not silence.
        """
        rid = msg.get("id")
        decision = wake_origin_permission_decision(msg)
        result = wake_origin_permission_result(msg)
        entry = self._permission_entry(msg, own, decision)
        envelope = parse_wake_envelope(own.body)
        card = pending_card_from_request(
            msg,
            envelope=envelope,
            message_id=own.message_id,
            sender=own.sender,
        )
        own.pending_card = card
        self.observation_expired = True
        self.alerts.append({"kind": "wake_origin_tool_denied", "reason": WAKE_ORIGIN_DENY_REASON})
        del self.alerts[:-100]
        try:
            claimed = self.permission_claim(own.turn_id, rid)
        except Exception:
            # Audit store down: still deny. A refusal never needs a claim to be safe.
            claimed = True
            self.alerts.append({"kind": "permission_audit_unavailable"})
        self._answered_permissions.add(rid)
        if not claimed:
            # Another authority already answered this request id: one response per id.
            self.alerts.append({"kind": "wake_origin_already_claimed", "reason": WAKE_ORIGIN_DENY_REASON})
            del self.alerts[:-100]
            return
        try:
            self._log_approval(msg, decision)
        except Exception:
            self.alerts.append({"kind": "permission_audit_unavailable"})
        try:
            write_pending_card(self._pending_card_path(), card)
        except OSError as exc:
            self.alerts.append({"kind": "pending_card_write_failed", "error": type(exc).__name__})
            print(f"warning: pending_card_write_failed: {type(exc).__name__}", file=sys.stderr)
        if self.conn is not None:
            self.conn.respond(rid, result)
        try:
            self.record_permission({**entry, "phase": "response_sent"})
        except Exception:
            self.alerts.append({"kind": "permission_audit_unavailable"})

    def _permission_entry(self, msg, own, decision):
        at = time.time()
        entry = safe(
            {
                "action": decision.action,
                "reason": decision.reason,
                "sender": own.sender,
                "message_id": own.message_id,
                "turn_id": own.turn_id,
                "request_sha256": fingerprint(msg.get("id")),
                "at": at,
                "at_local": local_time(at),
                "timezone": LOCAL_ZONE,
                **tool_metadata(msg, decision, self.cfg.session_cwd or os.getcwd()),
            }
        )
        self.permission_log.append(entry)
        own.permission_events.append(entry)
        del self.permission_log[:-100]
        del own.permission_events[:-100]
        return entry

    def _deny_permission(self, msg, own, decision, entry, *, claimed=False):
        self.observation_expired = True
        self.alerts.append({"kind": "protected_tool_denied", "reason": decision.reason})
        del self.alerts[:-100]
        rid = msg["id"]
        try:
            if not claimed and not self.permission_claim(own.turn_id, rid):
                return
            self._log_approval(msg, decision)
        except Exception:
            self.alerts.append({"kind": "permission_audit_unavailable"})
            return
        self._answered_permissions.add(rid)
        # A missing server-offered reject_once means silence, NEVER an allow.
        if decision.option_id is not None:
            self.conn.respond(rid, selected_result(decision.option_id))
            try:
                self.record_permission({**entry, "phase": "response_sent"})
            except Exception:
                self.alerts.append({"kind": "permission_audit_unavailable"})

    def _deny_authority(self, msg, own, *, claimed=False):
        decision = denied_decision(msg, "authority_not_held")
        entry = self._permission_entry(msg, own, decision)
        self._deny_permission(msg, own, decision, entry, claimed=claimed)

    def _on_request(self, msg: dict) -> None:
        # Deliberately silence all foreign/unrecognized requests, including cleanup.
        if self.conn is None or msg.get("method") != "session/request_permission":
            return
        with self._own_turn_lock:
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            own = self._own_turn
            if not self._owns_permission(params):
                return
            rid = msg.get("id")
            if type(rid) not in (str, int) or rid in self._answered_permissions:
                return
            if len(self._answered_permissions) >= 100:
                self.observation_expired = True
                return
            if getattr(own, "wake_origin", False):
                self._deny_wake_origin(msg, own)
                return
            decision = self._permission_decision(msg, own)
            entry = self._permission_entry(msg, own, decision)
            if decision.action == "deny":
                self._deny_permission(msg, own, decision, entry)
                return
            if (
                decision.action == "approve"
                and decision.option_id is not None
                and not self.observation_expired
                and self.auto_allowed(own.sender)
            ):
                if not self._authority_ok(own):
                    self._deny_authority(msg, own)
                    return
                try:
                    if not self.permission_claim(own.turn_id, rid):
                        return
                    self._log_approval(msg, decision)
                except Exception:
                    self.observation_expired = True
                    self.alerts.append({"kind": "permission_audit_unavailable"})
                    return
                # Revalidate AFTER audit, at the response action, serialized with
                # authority close. Audit/claim success is not authority ownership.
                if not self.authority_respond(own, rid, selected_result(decision.option_id)):
                    self._deny_authority(msg, own, claimed=True)
                    return
                self._answered_permissions.add(rid)
                try:
                    self.record_permission({**entry, "phase": "response_sent"})
                except Exception:
                    self.observation_expired = True
                    self.alerts.append({"kind": "permission_audit_unavailable"})
            else:
                try:
                    self._log_approval(msg, decision)
                except Exception:
                    self.observation_expired = True
                    self.alerts.append({"kind": "permission_audit_unavailable"})
                if len(self._pending_perms) < 100:
                    self._pending_perms[rid] = {"message_id": own.message_id}
                self.alerts.append(
                    {
                        "kind": "permission_pending",
                        "message_id": own.message_id,
                        "reason": "human_decision_surface_unavailable",
                    }
                )
                del self.alerts[:-100]

    def _log_approval(self, request: dict, decision) -> None:
        # Retains the useful intent of the preexisting change, never raw tool data.
        if self.approval_receipts_path is None:
            raise DaemonError("approval_audit_not_configured")
        at = time.time()
        record = safe(
            {
                "at": at,
                "at_local": local_time(at),
                "timezone": LOCAL_ZONE,
                "message_id": self._own_turn.message_id,
                "phase": "decision_intent",
                **tool_metadata(request, decision, self.cfg.session_cwd or os.getcwd()),
                "turn_id": self._own_turn.turn_id,
                "request_sha256": fingerprint(request.get("id")),
                "sender": self._own_turn.sender,
                "action": "reject_once"
                if decision.action == "deny"
                else "allow_once"
                if decision.action == "approve"
                else "pending",
                "reason": decision.reason,
            }
        )
        self.record_permission(record)
        if (
            self.approval_receipts_path.exists()
            and self.approval_receipts_path.stat().st_size >= 1048576
        ):
            self.approval_receipts_path.replace(
                self.approval_receipts_path.with_suffix(".previous.jsonl")
            )
        fd = os.open(self.approval_receipts_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def _cancel_pending_permissions(self) -> None:

        assert self.conn is not None
        # Silence is intentional: even cleanup must never answer a stale or
        # foreign permission. Cancellation is a separate, scoped operation.
        self._pending_perms.clear()

    # ------------------------------------------------------------------
    def build_outbound(self, message_id: str, body: str, sender=None) -> str:
        sender = sender or self.cfg.sender
        if sender not in self.cfg.agent_names():
            raise DaemonError("sender_invalid_or_reserved")
        validate_body(body, self.cfg.max_body_bytes)
        prefix = sender + ": "
        if self.cfg.auth_mode == "hmac":
            if self._hmac_key is None:
                raise DaemonError("hmac_key_not_loaded")
            return sign_text(
                self._hmac_key,
                prefix=prefix,
                sender=sender,
                session_id=self.cfg.session_id,
                message_id=message_id,
                body=body,
            )
        return prefix + body

    def run_turn(self, turn: Turn) -> dict:
        """agent-a origin contract, plus atomic admission; timeout retains ownership."""
        assert self.conn is not None
        with self._own_turn_lock:
            if not self.ready() or not self.dispatch_allowed(turn):
                raise BusyRefused("dispatch_closed_busy_or_unknown")
            self._own_turn = turn
            self._running_turn_id = None
            self._origin = {
                "turnId": turn.turn_id,
                "initiator": "firefly-bridge",
                "messageId": turn.message_id,
                "sender": turn.sender,
                "nonce": secrets.token_hex(16),
                "incarnation": self.incarnation,
            }
            self._reply_chunks = []
            self._reply_bytes = 0
            self._reply_seq = 0
            self._reply_gap = False
            self._reply_parse_failed = False
            self._malformed_baseline = getattr(self.conn, "malformed_lines", 0)
            self._terminal_cache = None
            self._answered_permissions.clear()
            self.observation_expired = False
            self._stock_prompt_id = None
            self._stock_turn_running = self.cfg.adapter_mode == "stock_grok"
            self._stock_msg_parts.clear()
            self._stock_last_chunk_id = None
            self._stock_stop_reason = None
            self._stock_started_at = time.time()
            # fsync claim before any write; failure is not permission to resend.
            try:
                self.persist_claim(turn, self._origin)
            except PreSendRejected:
                # The durable no-write refusal is different from an ambiguous
                # claim/transport exception. No remote terminal exists to wait for.
                self.clear_terminal()
                raise
            if not self._authority_ok(turn):
                raise DaemonError("authority_not_held_after_claim")
            revision = self.revision
            self.remote_state = "unknown"
            prompt_params: dict = {
                "sessionId": self.cfg.session_id,
                "prompt": [{"type": "text", "text": turn.outbound_text}],
            }
            if self.cfg.adapter_mode != "stock_grok" or self.turn_attestation_supported:
                prompt_params["_meta"] = {
                    "agentBridge": {**self._origin, "admissionRevision": revision}
                }
            self.active_call = self.conn.request(
                "session/prompt",
                prompt_params,
                rpc_id=turn.message_id,
            )
        remaining = max(0, (turn.deadline or time.monotonic()) - time.monotonic())
        if not self.active_call.wait(remaining):
            self.observation_expired = True
            self.remote_state = "unknown"
            raise TurnTimeout("observation_timeout_no_cancel")
        return self.terminal_result()

    def terminal_result(self):
        with self._own_turn_lock:
            if self._terminal_cache is not None:
                return dict(self._terminal_cache)
            call = self.active_call
            if call is None or not call.done():
                return None
            if call.closed:
                self.remote_state = "unknown"
                raise ConnectionClosed("closed_during_turn")
            result = call.result
            if self.cfg.adapter_mode == "stock_grok" and not self.turn_attestation_supported:
                if not isinstance(result, dict):
                    self.remote_state = "unknown"
                    raise TurnTimeout("terminal_unverified")
                self._flush_stock_msg()
                reason = result.get("stopReason") or self._stock_stop_reason
                if reason not in ("end_turn", "cancelled", "max_tokens", "refusal"):
                    raise TurnTimeout("terminal_reason_unverified")
                r_meta = result.get("_meta") if isinstance(result.get("_meta"), dict) else {}
                if not self._stock_prompt_id and isinstance(r_meta.get("promptId"), str):
                    self._stock_prompt_id = r_meta["promptId"]
                raw_reply = (
                    "\n\n".join(self._reply_chunks)
                    if len(self._reply_chunks) > 1
                    else "".join(self._reply_chunks)
                )
                recovery_status = "captured" if raw_reply else "reply_recovery_unavailable"
                if not raw_reply and self.cfg.updates_jsonl_path and self._own_turn is not None:
                    from firefly_bridge.channel import recover_reply_from_updates_jsonl

                    rec = recover_reply_from_updates_jsonl(
                        self.cfg.updates_jsonl_path,
                        outbound_text=self._own_turn.outbound_text,
                        prompt_id=self._stock_prompt_id,
                        min_timestamp=self._stock_started_at,
                    )
                    if rec and rec.get("reply_text"):
                        raw_reply = rec["reply_text"]
                        recovery_status = "updates_jsonl_recovery"
                        if not self._stock_prompt_id and rec.get("prompt_id"):
                            self._stock_prompt_id = rec["prompt_id"]
                reply, rendered = render_content(raw_reply)
                verified = bool(raw_reply.strip()) and rendered and not self._reply_parse_failed
                self._terminal_cache = {
                    "stop_reason": reason,
                    "prompt_id": self._stock_prompt_id,
                    "reply_redacted": reply if rendered else "[REDACTION_FAILED]",
                    "reply_verified": verified,
                    "reply_origin_verified": True,
                    "reply_stream_contiguous": verified,
                    "reply_complete": verified and reason == "end_turn",
                    "reply_recovery": recovery_status if verified else "reply_recovery_unavailable",
                }
                return dict(self._terminal_cache)
            # A JSON-RPC id alone is not terminal ownership proof.
            if not isinstance(result, dict) or not self._matches_origin(
                {"sessionId": result.get("sessionId"), "_meta": result.get("_meta")}
            ):
                self.remote_state = "unknown"
                raise TurnTimeout("terminal_unverified")
            reason = result.get("stopReason")
            if reason not in ("end_turn", "cancelled", "max_tokens", "refusal"):
                raise TurnTimeout("terminal_reason_unverified")
            reply, rendered = render_content("".join(self._reply_chunks))
            parse_failed = (
                self._reply_parse_failed
                or getattr(self.conn, "malformed_lines", 0) > self._malformed_baseline
            )
            terminal_meta = result.get("_meta", {}).get("agentBridge", {})
            expected_count = terminal_meta.get("chunkCount")
            if "chunkCount" in terminal_meta and (
                type(expected_count) is not int
                or expected_count < 0
                or expected_count != self._reply_seq
            ):
                parse_failed = True
            verified = bool(self._reply_chunks) and rendered and not parse_failed
            complete = (
                verified and type(expected_count) is int and expected_count == self._reply_seq
            )
            recovery_status = "captured" if verified else "reply_recovery_unavailable"
            if not verified:
                # Ownership/terminal are already proved above. History cannot be
                # used to fabricate ownership, terminal ACKs or permission authority.
                origin = self._origin
                locator = ReplyLocator(
                    session_id=self.cfg.session_id,
                    incarnation=origin["incarnation"],
                    turn_id=origin["turnId"],
                    initiator=origin["initiator"],
                    message_id=origin["messageId"],
                    sender=origin["sender"],
                    nonce=origin["nonce"],
                    max_bytes=self.cfg.max_reply_bytes,
                )
                recovered = recover_reply(self.chat_history, locator)
                reply = "[REDACTION_FAILED]" if not rendered else ""
                if recovered is not None:
                    reply, rendered = render_content(recovered)
                    verified = rendered
                    complete = rendered  # trusted history adapter returns the full logical reply
                    recovery_status = "recovered_chat_history" if rendered else "redaction_failed"
            self._terminal_cache = {
                "stop_reason": reason,
                "reply_redacted": reply,
                "reply_verified": verified,
                "reply_origin_verified": True,
                "reply_stream_contiguous": bool(self._reply_chunks) and not parse_failed,
                "reply_complete": complete,
                "reply_recovery": recovery_status,
            }
            return dict(self._terminal_cache)

    def clear_terminal(self):
        with self._own_turn_lock:
            self._cancel_pending_permissions()
            self.active_call = None
            self._own_turn = None
            self._origin = None
            self._running_turn_id = None
            self._terminal_cache = None
            self._stock_prompt_id = None
            self._stock_turn_running = False
            self._stock_msg_parts.clear()
            self._stock_last_chunk_id = None
            self._stock_stop_reason = None
            if self.cfg.adapter_mode == "stock_grok" and not self.turn_attestation_supported:
                self.remote_state = "idle"
                self.state_observed_at = time.monotonic()
            else:
                self.remote_state = "unknown"  # need NEW idle proof before next write
                self.revision = None

    def _send_cancel(self, turn: Turn, *, actor=None) -> None:
        with self._own_turn_lock:
            if actor not in ("human", "recipient"):
                raise DaemonError("active_cancel_authority_required")
            if (
                not self.cfg.live_send
                or self._own_turn is not turn
                or not self._origin
                or self._running_turn_id != self._origin["turnId"]
                or not self.scoped_cancel_supported
                or self.conn is None
                or self.conn.closed.is_set()
            ):
                raise DaemonError("scoped_cancel_unavailable_or_ownership_unknown")
            # Extension MUST enforce turn-scoped atomic cancellation. Without negotiated
            # support no session/cancel is emitted at all. A write is NOT an ACK.
            self.conn.notify(
                "session/cancel",
                {"sessionId": self.cfg.session_id, "_meta": {"agentBridge": dict(self._origin)}},
            )
            turn.state = "cancel_requested"
            turn.reason = "awaiting_correlated_terminal"
            self.observation_expired = True

    def close(self) -> None:
        if self.conn is not None:
            self.conn._mark_closed()  # noqa: SLF001
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    self.proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        self.proc = None
        self.conn = None


class Daemon:
    """One dispatch/permission authority per pinned target; durable acceptance."""

    def __init__(self, cfg: BridgeConfig, session: AcpSession | None = None) -> None:
        self.cfg = cfg.validate(require_target=True)
        self.session = session or AcpSession(cfg)
        self.state_dir = Path(cfg.state_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.receipts_path = self.state_dir / "receipts.jsonl"
        self.status_path = self.state_dir / "status.json"
        self.pid_path = self.state_dir / "daemon.pid"
        if not (self.state_dir / "broker.sqlite3").exists() and any(
            p.exists() and p.stat().st_size
            for p in (self.receipts_path, self.state_dir / "receipts.json")
        ):
            raise DaemonError("legacy_state_migration_required")
        self._authority = None
        self._authority_lease = None
        self.acquire_authority()
        try:
            self.store = BrokerStore(
                self.state_dir / "broker.sqlite3",
                cfg.session_id + "|" + os.path.realpath(cfg.socket_path),
                senders=cfg.agent_names(),
            )
        except BaseException:
            self._authority_lease.close()
            self._authority = None
            raise
        self._ingress_lock = threading.RLock()
        self.ipc = None
        self.replies = {}
        self._stop = threading.Event()
        self.outbox = Outbox(
            self._runner,
            turn_timeout_s=cfg.turn_timeout_s,
            busy_wait_s=cfg.busy_wait_s,
            busy_policy=cfg.busy_policy,
            max_outbox=cfg.max_outbox,
            on_receipt=self._on_receipt,
            dispatch_gate=self._dispatch_gate,
            state_path=load_queue_state_path(cfg.config_path),
            sign_outbound=self._sign_outbound,
        )
        self.session.authority_dirs = self._authority_lease.directories
        self.session.authority_files = self._authority_lease.paths
        for policy in (self.session.protection, *self.session.policies.values()):
            policy.protected_dirs += self.session.authority_dirs
            policy.protected_files += self.session.authority_files
        self.session.authority_allowed = self._permission_authority
        self.session.authority_respond = self._authority_respond
        self.session.approval_receipts_path = self.state_dir / "auto-approvals.jsonl"
        self.session.auto_allowed = lambda sender: cfg.live_send and self.store.consent(sender)
        self.session.dispatch_allowed = lambda turn: (
            self.authority_held()
            and self.store.consent(turn.sender)
            and turn.generation == self.store.consent()["generation"]
            and self.store.interval_ready(turn.sender, cfg)
        )
        self.session.persist_claim = self._persist_claim
        self.session.permission_claim = self.store.permission_once
        self.session.record_permission = self.store.record_permission
        self.session.on_control = self.control
        self.session.on_orphan_terminal = self.store.reconcile_terminal

    def acquire_authority(self):
        if self._authority_lease is not None:
            if not self.authority_held():
                raise DaemonError("authority_lost_restart_required")
            return
        try:
            self._authority_lease = TargetAuthority(self.cfg.session_id, self.cfg.socket_path)
        except (OSError, AuthorityError) as exc:
            raise DaemonError(
                str(exc) if isinstance(exc, AuthorityError) else "authority_unavailable"
            ) from None
        self._authority = self._authority_lease.runtime_fd

    def authority_held(self):
        lease = self._authority_lease
        return bool(
            lease is not None
            and self._authority == lease.runtime_fd
            and lease.target == canonical_target(self.cfg.session_id, self.cfg.socket_path)
            and lease.target
            == canonical_target(self.session.cfg.session_id, self.session.cfg.socket_path)
            and lease.held()
        )

    def _permission_authority(self, turn):
        return bool(
            self.authority_held()
            and turn is self.session._own_turn
            and turn is self.outbox._in_flight
            and self.store.owns_claim(turn, self.session._origin)
        )

    def _authority_respond(self, turn, rid, result):
        with self._authority_lease.lock:
            if not self._permission_authority(turn) or not self.store.consent(turn.sender):
                return False
            self.session.conn.respond(rid, result)
            return True

    def _persist_claim(self, turn, origin):
        with self._authority_lease.lock:
            if not self.authority_held():
                raise DaemonError("authority_not_held")
            self.store.claim(turn, origin, self.cfg)

    def _dispatch_gate(self, turn):
        return bool(
            self.authority_held()
            and self.session.ready()
            and self.store.can_dispatch(turn.sender)
            and self.store.interval_ready(turn.sender, self.cfg)
            and turn.generation == self.store.consent()["generation"]
        )

    def _sign_outbound(self, turn):
        """Re-sign on dispatch so a restart never sends a persisted empty prompt."""
        return self.session.build_outbound(turn.message_id, turn.body, turn.sender)

    def _runner(self, turn):
        return self.session.run_turn(turn)

    def _on_receipt(self, turn, event):
        self.store.update(turn, event)
        extra = {}
        if getattr(turn, "pending_card", None):
            extra["pending_card"] = turn.pending_card
        extra["wake_origin"] = bool(getattr(turn, "wake_origin", False))
        if isinstance(turn.result, dict):
            res_copy = dict(turn.result)
            res_copy.update(extra)
            if self.cfg.wake_dir and turn.state in ("delivered", "cancelled"):
                from firefly_bridge.channel import write_wake_artifacts

                wake = write_wake_artifacts(
                    self.cfg.wake_dir,
                    message_id=turn.message_id,
                    prompt_id=res_copy.get("prompt_id"),
                    stop_reason=res_copy.get("stop_reason"),
                    reply_text=str(res_copy.get("reply_redacted") or ""),
                    source_kind="daemon_turn",
                )
                res_copy["wake_artifacts"] = wake
            self.replies[turn.message_id] = safe(res_copy)
            while len(self.replies) > 32:
                self.replies.pop(next(iter(self.replies)))
        elif extra.get("pending_card") or extra.get("wake_origin"):
            current = dict(self.replies.get(turn.message_id) or {})
            current.update(extra)
            self.replies[turn.message_id] = safe(current)
        # Compact durable SQLite receipts replace unbounded raw JSONL logging.

    def snapshot(self, principal="human"):
        privileged = principal in ("human", "recipient")
        pending = self.outbox._all()
        payload = {
            "pid": os.getpid(),
            "adapter_mode": self.cfg.adapter_mode,
            "live_send": self.cfg.live_send,
            "requested_session_id": self.cfg.session_id,
            "verified_session_id": self.session.loaded_session_id,
            "incarnation_verified": bool(self.session.incarnation),
            "permission_profiles": [
                {"sender": s, "permission_mode": self.cfg.permission_mode_for(s)}
                for s in self.cfg.agent_names()
            ],
            "authority": self.authority_held(),
            "remote_state": self.session.remote_state,
            "admission_ready": self.session.ready(),
            "unresolved_attempt": self.store.unresolved(),
            "pacing": {
                "minimums_enabled": self.cfg.pacing_minimums_enabled,
                "quiet_now": self.cfg.quiet_now(self.store.now()),
                "quiet_hours_timezone": self.cfg.quiet_hours_timezone,
                "quiet_hours_start": self.cfg.quiet_hours_start,
                "quiet_hours_end": self.cfg.quiet_hours_end,
                "post_turn_interval_s": self.cfg.post_turn_interval_s,
                "target_interval_s": self.cfg.target_interval_s,
            },
            "consent": self.store.consent() if privileged else self.store.consent(principal),
            "control_history": self.store.audit_history(principal, controls_only=True),
            "outbox": [
                self.store.lookup(t.message_id, t.sender)
                for t in pending
                if privileged or t.sender == principal
            ],
            "reply_recovery": "chat_history_interface_stub"
            if not self.session.chat_history.proven_read_only
            else "proven_read_only_adapter",
            "scheduler": {"state": "unknown", "expiry": "unknown", "source": "unavailable"},
            "laws": {
                **LAWS,
                "enforced": self.cfg.protected_tools_enabled,
                "scope": "received_acp_permission_requests",
                "authority_required": True,
            },
        }
        if privileged:
            payload["alerts"] = self.session.alerts[-20:]
        return safe(payload)

    def _write_status(self):
        payload = self.snapshot()
        temporary = self.status_path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        temporary.replace(self.status_path)

    def enqueue(self, message_id, body, *, sender=None, wake_origin=False):
        sender = sender or self.cfg.sender
        if sender not in self.cfg.agent_names():
            raise StoreError("sender_invalid_or_reserved")
        if not isinstance(message_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,128}", message_id
        ):
            raise StoreError("message_id_invalid")
        validate_body(body, self.cfg.max_body_bytes)
        if not self.cfg.live_send:
            return {
                "message_id": message_id,
                "queue_state": "refused",
                "reason": "live_send_disabled",
            }
        with self._ingress_lock:
            # Check ID before capacity/consent so retransmission returns original receipt.
            existing = self.store.lookup(message_id)
            if existing:
                receipt, _ = self.store.accept(message_id, sender, body, "", self.cfg)
                return receipt
            queued = self.outbox._all()
            if sum(t.sender == sender for t in queued) >= self.cfg.per_sender_pending:
                raise StoreError("sender_pending_quota")
            if len(queued) >= self.cfg.max_outbox:
                raise StoreError("max_outbox_reached")
            if (
                sum(len(t.body.encode()) for t in queued) + len(body.encode())
                > self.cfg.max_queue_bytes
            ):
                raise StoreError("queue_bytes_exceeded")
            if self.cfg.busy_policy == "fail" and queued:
                raise StoreError("slot_busy_fail_policy")
            receipt, new = self.store.accept(
                message_id, sender, body, secrets.token_hex(16), self.cfg
            )
            if not new:
                return receipt
            try:
                turn = self.outbox.enqueue(
                    message_id,
                    self.cfg.session_id,
                    body,
                    self.session.build_outbound(message_id, body, sender),
                    sender=sender,
                    turn_id=receipt["turn_id"],
                    generation=receipt["generation"],
                    wake_origin=bool(wake_origin) or body_marks_wake_origin(body),
                )
            except Exception:
                # Accepted ID is consumed even if later presentation/enqueue fails.
                # Restart closes it; do not silently issue another attempt.
                raise
            return self.store.lookup(turn.message_id, sender)

    def control(self, actor, op, senders=None, *, control_seq=None, incarnation=None):
        if senders is None:
            senders = self.cfg.agent_names()
        with self.session._own_turn_lock:
            with self._ingress_lock:
                result = self.store.control(
                    actor, op, senders, control_seq=control_seq, incarnation=incarnation
                )
                if op != "opt_in":
                    for turn in list(self.outbox._pending):
                        self.outbox.cancel(turn.message_id, reason="channel_revoked_no_revival")
                return result

    def cancel(self, message_id, *, actor=None):
        actor = actor or self.cfg.sender
        receipt = self.store.lookup(message_id, actor)
        if receipt is None:
            return {"queue_state": "unknown", "reason": "not_found"}
        with self.session._own_turn_lock:
            active = self.outbox._in_flight
            if active and active.message_id == message_id:
                self.session._send_cancel(active, actor=actor)
                self.store.update(active, "cancel_requested")
                return self.store.lookup(active.message_id, actor)
            if actor in self.cfg.agent_names() and receipt["sender"] != actor:
                raise StoreError("sender_not_owner")
            turn = self.outbox.cancel(message_id)
            return self.store.lookup(turn.message_id, actor) if turn else receipt

    def receipt(self, principal, mid):
        receipt = self.store.lookup(mid, principal)
        if receipt and mid in self.replies:
            receipt.update(self.replies[mid])
        if receipt and self.session._own_turn and self.session._own_turn.message_id == mid:
            try:
                terminal = self.session.terminal_result()
            except (ConnectionClosed, TurnTimeout):
                terminal = None
            if terminal:
                receipt.update(terminal)
        return safe(receipt) if receipt else {"error": "not_found"}

    def handle_ipc(self, principal, op, args):
        if not isinstance(args, dict):
            raise StoreError("ipc_args_invalid")
        if op == "enqueue" and principal in self.cfg.agent_names():
            wake = args.get("wake_origin") is True
            return self.enqueue(
                args["message_id"],
                args["body"],
                sender=principal,
                wake_origin=wake,
            )
        if op == "cancel":
            return self.cancel(args["message_id"], actor=principal)
        if op == "status":
            return self.snapshot(principal)
        if op == "receipt":
            return self.receipt(principal, args["message_id"])
        if op in ("basta", "pause", "revoke", "opt_in"):
            return self.control(principal, op, args.get("senders", list(self.cfg.agent_names())))
        raise StoreError("ipc_operation_forbidden")

    def pump_once(self):
        if self.outbox._in_flight:
            turn = self.outbox._in_flight
            try:
                terminal = self.session.terminal_result()
            except (TurnTimeout, ConnectionClosed):
                terminal = None
            if terminal:
                self.outbox.reconcile(turn, terminal)
                self.session.clear_terminal()
                return turn
        turn = self.outbox.pump_once()
        if turn and turn.state in ("delivered", "cancelled", "failed"):
            self.session.clear_terminal()
        return turn

    def serve(self):
        try:
            self.acquire_authority()
            self.ipc = IpcServer(self.state_dir / "broker.sock", self)
            self.session.start()
            self.ipc.start()
            self.pid_path.write_text(str(os.getpid()) + "\n")
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: self._stop.set())
            while not self._stop.is_set():
                self.pump_once()
                self._write_status()
                self._stop.wait(self.cfg.poll_interval_s)
            return 0
        finally:
            self.close()

    def close(self):
        # No session/cancel and no pending permission responses on shutdown.
        if self.ipc:
            self.ipc.close()
            self.ipc = None
        self.session.close()
        self._authority_lease.close()
        self._authority = None
        self.store.close()


def run_daemon(cfg: BridgeConfig) -> int:
    daemon = Daemon(cfg)
    return daemon.serve()


def load_or_exit(path: str | None, *, require_target: bool = True) -> BridgeConfig:
    try:
        return load_config(path, require_target=require_target)
    except (ConfigError, KeyFileError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(2) from exc
