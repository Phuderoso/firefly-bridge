"""P0 acceptance tests. All ACP peers are synthetic; no Mac, network or grok."""

import io
import json
import secrets
import threading
import time
from unittest.mock import patch

import pytest

from firefly_bridge.broker_store import BrokerStore, StoreError
from firefly_bridge.config import BridgeConfig, ConfigError
from firefly_bridge.daemon import Daemon, DaemonError
from firefly_bridge.doctor import doctor
from firefly_bridge.envelope import generate_key_file, load_key
from firefly_bridge.ipc import Authenticator, IpcServer, ipc_call, signed_request
from firefly_bridge.permissions import PermissionPolicy
from firefly_bridge.privacy import safe
from firefly_bridge.rpc import JsonRpcConnection, PendingCall


class Peer:
    def __init__(self, session, *, terminal=False):
        self.session = session
        self.terminal = terminal
        self.closed = threading.Event()
        self.calls = []
        self.notifications = []
        self.responses = []
        self.call = None

    def request(self, method, params, rpc_id=None):
        self.calls.append((method, params))
        self.call = PendingCall(rpc_id)
        if method == "session/prompt":
            self.session._on_notification(
                {
                    "method": "session/update",
                    "params": {
                        "sessionId": params["sessionId"],
                        "_meta": params["_meta"],
                        "update": {"sessionUpdate": "turn_started"},
                    },
                }
            )
            if self.terminal:
                self.finish()
        return self.call

    def finish(self, reason="end_turn", *, meta=None):
        self.call._resolve(
            {
                "result": {
                    "stopReason": reason,
                    "sessionId": self.session.cfg.session_id,
                    "_meta": {"agentBridge": meta or dict(self.session._origin)},
                }
            }
        )

    def notify(self, method, params):
        self.notifications.append((method, params))

    def respond(self, rid, result):
        self.responses.append((rid, result))

    def _mark_closed(self):
        self.closed.set()


def ready(s):
    s.loaded_session_id = s.cfg.session_id
    s.incarnation = "synthetic-incarnation"
    s.turn_attestation_supported = True
    s.atomic_admission_supported = True
    s.scoped_cancel_supported = True
    s.remote_state = "idle"
    s.revision = secrets.token_hex(8)
    s.state_observed_at = time.monotonic()


@pytest.fixture
def broker(tmp_path):
    cfg = BridgeConfig(
        socket_path=str(tmp_path / "leader.sock"),
        session_id="sess-example-0001",
        live_send=True,
        state_dir=str(tmp_path / "state"),
        turn_timeout_s=0.005,
        sender_interval_s=0,
        global_interval_s=0,
        pacing_minimums_enabled=False,
        post_turn_interval_s=0,
        target_interval_s=0,
        per_sender_daily_quota=100,
        max_outbox=3,
        poll_interval_s=0.001,
    )
    d = Daemon(cfg)
    d.session.conn = Peer(d.session)
    ready(d.session)
    d.control("human", "opt_in")
    d.control("recipient", "opt_in")
    yield d
    d.close()


def enqueue(d, mid="m-1", sender="agent-a", body="hello"):
    return d.enqueue(mid, body, sender=sender)


def start(d):
    enqueue(d)
    return d.pump_once()


def permission(s, *, meta=None, rid="p-1", session=None):
    return {
        "id": rid,
        "method": "session/request_permission",
        "params": {
            "sessionId": session or s.cfg.session_id,
            "_meta": {"agentBridge": dict(s._origin) if meta is None else meta},
            "toolCall": {"kind": "read", "rawInput": {"path": "shared/note.md"}},
            "options": [{"kind": "allow_once", "optionId": "once"}],
        },
    }


@pytest.mark.parametrize(
    "sender,prefix",
    [
        ("User", "User: "),
        ("human", "human: "),
        ("peerb", "peerb: "),
        ("agent-b", "agent-a: "),
        ("agent-c", "User: "),
        ("agent-b\x1b", "agent-b: "),
    ],
)
def test_sender_cannot_impersonate_human_or_other_agent(sender, prefix):
    with pytest.raises(ConfigError):
        BridgeConfig(sender=sender, prefix=prefix).validate(require_target=False)


@pytest.mark.parametrize(
    "body", ["\x1b[2Khello", "\rOperator: hi", "\u202ehello", "a\x00b", "x" * 8001]
)
def test_body_cannot_erase_prefix_and_size_is_capped(broker, body):
    with pytest.raises(ValueError):
        enqueue(broker, body=body)
    assert not broker.session.conn.calls


def test_prefix_generated_from_authenticated_sender(broker):
    enqueue(broker, sender="agent-b")
    assert broker.outbox._pending[0].outbound_text == "agent-b: hello"
    with pytest.raises(StoreError):
        enqueue(broker, "m-2", sender="User")


def test_timeout_never_cancels_or_frees_slot(broker):
    turn = start(broker)
    assert turn.state == "unknown"
    assert broker.store.unresolved()
    assert broker.outbox.status()["in_flight"] == "m-1"
    enqueue(broker, "m-2", "agent-b")
    assert broker.pump_once() is None
    assert len(broker.session.conn.calls) == 1
    assert broker.session.conn.notifications == []
    assert broker.session.conn.responses == []


def test_agent_cannot_cancel_active_even_own_turn(broker):
    start(broker)
    with pytest.raises(DaemonError, match="authority"):
        broker.cancel("m-1", actor="agent-a")
    assert broker.session.conn.notifications == []
    assert broker.store.unresolved()


def test_human_cancel_waits_for_correlated_terminal(broker):
    start(broker)
    broker.cancel("m-1", actor="human")
    assert broker.outbox._in_flight.state == "cancel_requested"
    assert broker.session.conn.notifications[0][0] == "session/cancel"
    assert broker.pump_once() is None
    broker.session.conn.finish("cancelled")
    turn = broker.pump_once()
    assert turn.state == "cancelled"
    assert not broker.store.unresolved()
    assert broker.outbox._in_flight is None


@pytest.mark.parametrize("failure", ["no_scoped", "foreign_active", "observer"])
def test_cancel_without_scope_or_owner_is_silent(broker, failure):
    start(broker)
    if failure == "no_scoped":
        broker.session.scoped_cancel_supported = False
    elif failure == "observer":
        broker.cfg.live_send = False
    else:
        broker.session._running_turn_id = "human-turn"
    with pytest.raises(DaemonError):
        broker.cancel("m-1", actor="recipient")
    assert broker.session.conn.notifications == []


def test_agent_only_withdraws_own_queued_message(broker):
    enqueue(broker)
    assert broker.cancel("m-1", actor="agent-c")["reason"] == "not_found"
    assert broker.cancel("m-1", actor="agent-a")["queue_state"] == "cancelled"
    assert enqueue(broker)["queue_state"] == "cancelled"
    assert not broker.session.conn.calls


@pytest.mark.parametrize(
    "state", ["busy", "unknown", "stale", "unverified", "no_atomic", "no_attestation", "no_optin"]
)
def test_dispatch_fails_closed(broker, state):
    if state in ("busy", "unknown"):
        broker.session.remote_state = state
    elif state == "stale":
        broker.session.state_observed_at = 0
    elif state == "unverified":
        broker.session.loaded_session_id = None
    elif state == "no_atomic":
        broker.session.atomic_admission_supported = False
    elif state == "no_attestation":
        broker.session.turn_attestation_supported = False
    elif state == "no_optin":
        broker.control("human", "pause")
    if state == "no_optin":
        with pytest.raises(StoreError, match="optin"):
            enqueue(broker)
    else:
        enqueue(broker)
        assert broker.pump_once() is None
    assert broker.session.conn.calls == []


def test_optin_is_both_parties_scoped_and_revocable(broker):
    broker.control("human", "pause")
    broker.control("human", "opt_in", ["agent-b"])
    with pytest.raises(StoreError):
        enqueue(broker, sender="agent-b")
    broker.control("recipient", "opt_in", ["agent-b"])
    enqueue(broker, sender="agent-b")
    with pytest.raises(StoreError):
        enqueue(broker, "m-2", sender="agent-c")
    broker.control("recipient", "basta")
    assert broker.store.lookup("m-1")["queue_state"] == "cancelled"
    broker.control("human", "opt_in")
    assert not broker.store.consent("agent-b")
    broker.control("recipient", "opt_in")
    assert broker.outbox.status()["pending_count"] == 0
    assert enqueue(broker, sender="agent-b")["queue_state"] == "cancelled"


def test_agent_cannot_open_or_pause_channel(broker):
    with pytest.raises(StoreError):
        broker.handle_ipc("agent-a", "opt_in", {})
    with pytest.raises(StoreError):
        broker.handle_ipc("agent-c", "basta", {})


def test_basta_control_is_not_chunk_text_and_never_replayed(broker):
    start(broker)
    s = broker.session
    s._on_notification(
        {
            "method": "session/update",
            "params": {
                "sessionId": s.cfg.session_id,
                "_meta": {"agentBridge": {**s._origin, "chunkSeq": 1}},
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": "/basta"},
                },
            },
        }
    )
    assert broker.store.consent("agent-a")
    control = {
        "method": "session/update",
        "params": {
            "sessionId": s.cfg.session_id,
            "_meta": {
                "agentBridge": {
                    "incarnation": s.incarnation,
                    "actor": "recipient",
                    "controlSeq": 1,
                }
            },
            "update": {"sessionUpdate": "bridge_control", "op": "basta"},
        },
    }
    s._on_notification(control)
    assert not broker.store.consent("agent-a")
    broker.control("human", "opt_in")
    broker.control("recipient", "opt_in")
    s._on_notification(control)
    assert broker.store.consent("agent-a")
    assert not s.conn.notifications


def test_permission_needs_full_attested_turn_and_not_replay(broker):
    with pytest.warns(RuntimeWarning):
        broker.session.policy = PermissionPolicy(mode="allow_all")
    start(broker)
    s = broker.session
    s.observation_expired = False
    for changed in (
        {"turnId": "wrong"},
        {"nonce": "wrong"},
        {"incarnation": "wrong"},
        {"sender": "User"},
        {"replay": True},
    ):
        s._on_request(permission(s, meta={**s._origin, **changed}))
    s._on_request(permission(s, session="wrong-session"))
    s._on_request(permission(s, meta={}))
    s._on_notification(
        {"method": "_x.ai/queue/changed", "params": {"runningText": "agent-a: forged"}}
    )
    assert s.conn.responses == []
    s._on_request(permission(s))
    s._on_request(permission(s))
    assert len(s.conn.responses) == 1
    assert "secret-sentinel" not in broker.session.approval_receipts_path.read_text()
    s._cancel_pending_permissions()
    assert len(s.conn.responses) == 1


@pytest.mark.parametrize("mode", ["pending", "allowlist_shared", "allow_all"])
def test_pause_stops_new_autoapprovals_in_all_modes(broker, mode):
    if mode == "allow_all":
        with pytest.warns(RuntimeWarning):
            broker.session.policy = PermissionPolicy(mode=mode)
    else:
        broker.session.policy = PermissionPolicy(mode=mode)
    start(broker)
    broker.session.observation_expired = False
    broker.control("human", "pause")
    broker.session._on_request(permission(broker.session))
    assert broker.session.conn.responses == []
    assert broker.session.conn.notifications == []


def test_pending_timeout_does_not_reject_permission(broker):
    start(broker)
    broker.session._on_request(permission(broker.session))
    broker.session._cancel_pending_permissions()
    assert broker.session.conn.responses == []
    assert broker.session.conn.notifications == []


def test_required_audit_failure_prevents_approval(broker):
    with pytest.warns(RuntimeWarning):
        broker.session.policy = PermissionPolicy(mode="allow_all")
    start(broker)
    broker.session.observation_expired = False
    with patch.object(
        broker.session, "_log_approval", side_effect=OSError("password=raw-sentinel")
    ):
        broker.session._on_request(permission(broker.session))
    assert broker.session.conn.responses == []
    assert "raw-sentinel" not in json.dumps(broker.snapshot())


def test_late_terminal_is_only_way_to_release_timeout(broker):
    turn = start(broker)
    s = broker.session
    s.conn.finish(meta={**s._origin, "nonce": "bad"})
    assert broker.pump_once() is None
    assert broker.store.unresolved()
    s.conn.finish()
    assert broker.pump_once() is turn
    assert not broker.store.unresolved()
    assert s.remote_state == "unknown"


def test_successful_claim_precedes_write_and_replay_never_reexecutes(broker):
    original = broker.session.conn.request

    def check_claim(method, params, rpc_id=None):
        assert broker.store.db.execute(
            "SELECT attempted FROM messages WHERE id=?", (rpc_id,)
        ).fetchone()[0]
        return original(method, params, rpc_id)

    broker.session.conn.request = check_claim
    broker.session.conn.terminal = True
    enqueue(broker)
    assert broker.pump_once().state == "delivered"
    assert enqueue(broker)["queue_state"] == "delivered"
    assert len(broker.session.conn.calls) == 1
    with pytest.raises(StoreError, match="conflicting"):
        enqueue(broker, body="different")


def test_restart_preserves_claim_veto_quota_and_closes_old_queue(tmp_path):
    cfg = BridgeConfig(
        socket_path=str(tmp_path / "socket"),
        session_id="sess-example-0001",
        live_send=True,
        state_dir=str(tmp_path / "state"),
        sender_interval_s=0,
        global_interval_s=0,
        pacing_minimums_enabled=False,
        post_turn_interval_s=0,
        target_interval_s=0,
        per_sender_daily_quota=2,
        turn_timeout_s=0.001,
    )
    first = Daemon(cfg)
    first.session.conn = Peer(first.session)
    ready(first.session)
    first.control("human", "opt_in")
    first.control("recipient", "opt_in")
    first.enqueue("active", "hello")
    first.enqueue("waiting", "hi", sender="agent-b")
    first.pump_once()
    first.control("recipient", "basta")
    first.close()
    second = Daemon(cfg)
    try:
        second.session.conn = Peer(second.session)
        ready(second.session)
        assert not second.store.consent("agent-a")
        assert second.enqueue("active", "hello")["queue_state"] == "unknown"
        assert second.enqueue("waiting", "hi", sender="agent-b")["queue_state"] == "cancelled"
        assert second.store.unresolved()
        second.control("human", "opt_in")
        second.control("recipient", "opt_in")
        second.enqueue("new", "hello")
        assert second.pump_once() is None
        assert second.session.conn.calls == []
        with pytest.raises(StoreError, match="pending_quota"):
            second.enqueue("new2", "hello")
    finally:
        second.close()


def test_queued_message_is_not_auto_rehydrated_after_restart(tmp_path):
    cfg = BridgeConfig(
        socket_path=str(tmp_path / "socket"),
        session_id="sess-example-0001",
        live_send=True,
        state_dir=str(tmp_path / "state"),
    )
    d = Daemon(cfg)
    d.control("human", "opt_in")
    d.control("recipient", "opt_in")
    d.enqueue("queued", "do not resurrect")
    d.close()
    d = Daemon(cfg)
    try:
        assert d.enqueue("queued", "do not resurrect")["queue_state"] == "closed"
        assert d.outbox.status()["pending_count"] == 0
    finally:
        d.close()


def test_sender_global_and_bytes_quotas(broker):
    enqueue(broker)
    with pytest.raises(StoreError, match="sender_pending"):
        enqueue(broker, "m-2")
    enqueue(broker, "m-2", "agent-b")
    enqueue(broker, "m-3", "agent-c")
    broker.cfg.per_sender_pending = 2
    with pytest.raises(StoreError, match="max_outbox"):
        enqueue(broker, "m-4")
    broker.control("human", "pause")
    broker.control("human", "opt_in")
    broker.control("recipient", "opt_in")
    broker.cfg.max_queue_bytes = 3
    with pytest.raises(StoreError, match="queue_bytes"):
        enqueue(broker, "m-5")


def test_daily_quota_persistent_and_cooldown_blocks(broker):
    broker.cfg.per_sender_daily_quota = 1
    broker.session.conn.terminal = True
    enqueue(broker)
    broker.pump_once()
    with pytest.raises(StoreError, match="daily_quota"):
        enqueue(broker, "m-2")
    broker.cfg.global_interval_s = 600
    ready(broker.session)
    enqueue(broker, "m-3", "agent-b")
    assert broker.pump_once().sender == "agent-b"


def test_three_clients_are_serialized_and_all_advance(broker):
    broker.session.conn.terminal = True
    for n, sender in enumerate(("agent-a", "agent-b", "agent-c")):
        enqueue(broker, f"m-{n}", sender)
    assert broker.pump_once().sender == "agent-a"
    assert broker.pump_once() is None  # no new idle proof
    ready(broker.session)
    assert broker.pump_once().sender == "agent-b"
    ready(broker.session)
    assert broker.pump_once().sender == "agent-c"
    assert len(broker.session.conn.calls) == 3


def test_target_binding_and_single_authority_even_other_state_dir(broker, tmp_path):
    other = BridgeConfig(**{**vars(broker.cfg), "state_dir": str(tmp_path / "other")})
    with pytest.raises(DaemonError, match="already_held"):
        Daemon(other)
    with pytest.raises(StoreError, match="target_mismatch"):
        BrokerStore(broker.state_dir / "broker.sqlite3", "other-target")


def test_old_receipts_require_migration_not_empty_new_ledger(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "receipts.jsonl").write_text('{"message_id":"old"}\n')
    cfg = BridgeConfig(
        state_dir=str(state), session_id="sess-example-0001", socket_path="/tmp/example.sock"
    )
    with pytest.raises(DaemonError, match="migration"):
        Daemon(cfg)


def keyset(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    for p in ("agent-a", "agent-b", "agent-c", "human", "recipient"):
        generate_key_file(keys / (p + ".key"))
    return keys


def test_ipc_auth_binds_identity_target_operation_and_nonce(broker, tmp_path):
    keys = keyset(tmp_path)
    auth = Authenticator(str(keys), broker.store, broker.cfg.session_id)
    request = signed_request(load_key(keys / "agent-b.key"), "agent-b", broker.cfg.session_id, "status")
    for bad in (
        {**request, "principal": "human"},
        {**request, "op": "opt_in"},
        {**request, "session_id": "wrong"},
    ):
        with pytest.raises(StoreError, match="auth_failed"):
            auth.verify(bad)
    assert auth.verify(request) == "agent-b"
    with pytest.raises(StoreError, match="replay"):
        auth.verify(request)
    # Replay is durable, not an in-memory set.
    again = Authenticator(str(keys), broker.store, broker.cfg.session_id)
    with pytest.raises(StoreError, match="replay"):
        again.verify(request)


def test_ipc_nonce_survives_store_reopen(tmp_path):
    path = tmp_path / "state" / "broker.sqlite3"
    first = BrokerStore(path, "test-target")
    first.accept_nonce("agent-c", "n" * 16, time.time())
    first.close()
    second = BrokerStore(path, "test-target")
    try:
        with pytest.raises(StoreError, match="replay"):
            second.accept_nonce("agent-c", "n" * 16, time.time())
    finally:
        second.close()


def test_real_local_ipc_roundtrip_and_owner_only_receipts(broker, tmp_path):
    keys = keyset(tmp_path)
    broker.cfg.ipc_keys_dir = str(keys)
    server = IpcServer(broker.state_dir / "broker.sock", broker)
    server.start()
    try:
        cfg = BridgeConfig(
            **{**vars(broker.cfg), "ipc_principal": "agent-b", "ipc_key_file": str(keys / "agent-b.key")}
        )
        result = ipc_call(cfg, "enqueue", {"message_id": "agent-b-1", "body": "hello"})
        assert result["sender"] == "agent-b"
        assert ipc_call(cfg, "status")["outbox"][0]["sender"] == "agent-b"
        cfg.ipc_principal = "agent-c"
        cfg.ipc_key_file = str(keys / "agent-c.key")
        assert ipc_call(cfg, "receipt", {"message_id": "agent-b-1"}) == {"error": "not_found"}
        assert ipc_call(cfg, "status")["outbox"] == []
        assert "error" in ipc_call(cfg, "opt_in")
        assert (broker.state_dir / "broker.sock").stat().st_mode & 0o777 == 0o600
    finally:
        server.close()


def test_ipc_refuses_duplicate_credentials(broker, tmp_path):
    keys = keyset(tmp_path)
    (keys / "agent-c.key").write_bytes((keys / "agent-b.key").read_bytes())
    with pytest.raises(StoreError, match="distinct"):
        Authenticator(str(keys), broker.store, broker.cfg.session_id)


def test_redaction_on_all_audit_and_discard_paths(broker):
    sensitive = "Bearer abcdefghijkl token=hidden-secret password=not-for-log sk-abcdefghijklmnop"
    enqueue(broker, body=sensitive)
    broker.pump_once()
    s = broker.session
    s._on_request(permission(s))
    s._on_notification(
        {
            "method": "session/update",
            "params": {
                "sessionId": s.cfg.session_id,
                "_meta": {"agentBridge": s._origin},
                "update": {
                    "sessionUpdate": "agent_thought_chunk",
                    "content": {"type": "text", "text": sensitive},
                },
            },
        }
    )
    broker._write_status()
    all_audits = (
        broker.status_path.read_text() + json.dumps(s.permission_log) + json.dumps(s.alerts)
    )
    assert "hidden-secret" not in all_audits
    assert "not-for-log" not in all_audits
    assert "abcdefghijklmnop" not in all_audits
    assert sensitive.encode() not in (broker.state_dir / "broker.sqlite3").read_bytes()
    assert safe({"discard": sensitive, "command": "opaque secret"}) == {
        "discard": "Bearer [REDACTED] [REDACTED] [REDACTED] [REDACTED]",
        "command": "[OMITTED]",
    }


def test_redactor_failure_never_returns_raw():
    with patch("firefly_bridge.privacy.redact_text", side_effect=ValueError("regex failure")):
        assert safe("do not leak me") == "[REDACTION_FAILED]"
        assert safe({"discard": "do not leak me"}) == {"discard": "[REDACTION_FAILED]"}


def test_only_correlated_agent_chunks_become_reply_and_capture_survives_terminal(broker):
    start(broker)
    s = broker.session
    for update_kind, meta, text in (
        ("agent_message_chunk", {**s._origin, "chunkSeq": 1}, "hello token=secret"),
        ("agent_message_chunk", {**s._origin, "chunkSeq": 1}, "duplicate"),
        ("agent_message_chunk", {**s._origin, "chunkSeq": 2, "replay": True}, "replay"),
        ("agent_thought_chunk", {**s._origin, "chunkSeq": 3}, "thought"),
        ("agent_message_chunk", {**s._origin, "chunkSeq": 4, "nonce": "bad"}, "foreign"),
    ):
        s._on_notification(
            {
                "method": "session/update",
                "params": {
                    "sessionId": s.cfg.session_id,
                    "_meta": {"agentBridge": meta},
                    "update": {
                        "sessionUpdate": update_kind,
                        "content": {"type": "text", "text": text},
                    },
                },
            }
        )
    s.conn.finish()
    broker.pump_once()
    receipt = broker.receipt("agent-a", "m-1")
    assert receipt["reply_verified"]
    assert receipt["reply_redacted"] == "hello [REDACTED]"
    assert broker.receipt("agent-c", "m-1")["error"] == "not_found"
    assert b"hello token" not in (broker.state_dir / "broker.sqlite3").read_bytes()


def test_reply_limit_discards_safely(broker):
    start(broker)
    s = broker.session
    s.cfg.max_reply_bytes = 1
    s._on_notification(
        {
            "method": "session/update",
            "params": {
                "sessionId": s.cfg.session_id,
                "_meta": {"agentBridge": {**s._origin, "chunkSeq": 1}},
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": "password=discard-sentinel"},
                },
            },
        }
    )
    assert not s._reply_chunks
    assert "discard-sentinel" not in json.dumps(s.alerts)


def test_doctor_never_contacts_grok_or_writes_files(broker):
    broker._write_status()
    before = {p.name: p.stat().st_mtime_ns for p in broker.state_dir.iterdir()}
    with patch("subprocess.Popen", side_effect=AssertionError("must not attach")):
        result = doctor(broker.cfg)
    after = {p.name: p.stat().st_mtime_ns for p in broker.state_dir.iterdir()}
    assert before == after
    assert result["remote_state"] == "unknown"
    assert result["scheduler"]["state"] == "unknown"


def test_rpc_frame_bound_fails_closed():
    from firefly_bridge.rpc import MAX_RPC_FRAME

    conn = JsonRpcConnection(io.BytesIO(b"x" * 131073 + b"\n"), io.BytesIO(), max_frame=131072)
    conn._read_loop()
    assert conn.closed.is_set()
    large = (
        b'{"jsonrpc":"2.0","method":"session/update","params":{"pad":"' + (b"a" * 200000) + b'"}}\n'
    )
    conn2 = JsonRpcConnection(io.BytesIO(large), io.BytesIO())
    conn2._read_loop()
    assert conn2.malformed_lines == 0
    assert MAX_RPC_FRAME >= 16 * 1024 * 1024


def test_control_sequence_and_veto_are_atomic_and_durable(tmp_path):
    path = tmp_path / "state" / "broker.sqlite3"
    store = BrokerStore(path, "target")
    store.control("human", "opt_in")
    store.control("recipient", "opt_in")
    store.control("recipient", "basta", control_seq=7, incarnation="inc")
    store.close()
    store = BrokerStore(path, "target")
    try:
        assert not store.consent("agent-a")
        with pytest.raises(StoreError, match="replay"):
            store.control("recipient", "opt_in", control_seq=6, incarnation="inc")
        assert not store.consent("agent-a")
    finally:
        store.close()


def test_orphan_terminal_needs_exact_durable_proof_after_restart(tmp_path):
    cfg = BridgeConfig(
        socket_path=str(tmp_path / "socket"),
        session_id="sess-example-0001",
        state_dir=str(tmp_path / "state"),
        live_send=True,
        turn_timeout_s=0.001,
    )
    d = Daemon(cfg)
    d.session.conn = Peer(d.session)
    ready(d.session)
    d.control("human", "opt_in")
    d.control("recipient", "opt_in")
    d.enqueue("orphan", "hello")
    d.pump_once()
    origin = dict(d.session._origin)
    d.close()
    d = Daemon(cfg)
    d.session.conn = Peer(d.session)
    ready(d.session)
    try:
        update = {
            "method": "session/update",
            "params": {
                "sessionId": cfg.session_id,
                "_meta": {"agentBridge": {**origin, "nonce": "forged"}},
                "update": {"sessionUpdate": "turn_ended", "stopReason": "end_turn"},
            },
        }
        d.session._on_notification(update)
        assert d.store.unresolved()
        update["params"]["_meta"]["agentBridge"] = {**origin, "replay": True}
        d.session._on_notification(update)
        assert d.store.unresolved()
        update["params"]["_meta"]["agentBridge"] = origin
        d.session._on_notification(update)
        assert not d.store.unresolved()
        assert d.enqueue("orphan", "hello")["queue_state"] == "delivered"
        assert d.session.conn.calls == []
    finally:
        d.close()


@pytest.mark.parametrize(
    "text,expected",
    [
        ("token=abc123", "[REDACTED]"),
        ("password: hunter2", "[REDACTED]"),
        ("Authorization Bearer abcdefghijklmnop", "Authorization Bearer [REDACTED]"),
        ("upload with pypi-" + "A" * 24, "upload with pypi-[REDACTED]"),
        ("see /Users/example/secret/file.txt please", "see [REDACTED-PATH] please"),
        ("safe text", "safe text"),
        ("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----", "[PRIVATE_KEY]"),
    ],
)
def test_original_redaction_regressions_and_private_key(text, expected):
    assert safe(text) == expected


def test_permission_mode_default_alias_and_loud_warning():
    assert PermissionPolicy().mode == "pending"
    assert PermissionPolicy(mode="allowlist_shared").mode == "allowlist"
    with pytest.warns(RuntimeWarning, match="DANGER.*ELIGIBLE TOOLS"):
        PermissionPolicy(mode="allow_all")


def test_human_optin_does_not_turn_recipient_no_into_yes(broker):
    broker.control("recipient", "revoke")
    broker.control("human", "opt_in")
    with pytest.raises(StoreError, match="optin"):
        enqueue(broker)
    assert broker.session.conn.calls == []


def test_doctor_cli_and_ipc_client_error_are_safe(tmp_path, capsys):
    from firefly_bridge.cli import main

    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[bridge]\nstate_dir="{tmp_path / "state"}"\n')
    assert main(["doctor", "--config", str(cfg)]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "read_only_local_snapshot"
    assert main(["enqueue", "--config", str(cfg), "--text", "example"]) == 2
    assert "error" in json.loads(capsys.readouterr().out)


def test_allow_all_config_prints_loud_warning(capsys):
    from firefly_bridge.daemon import AcpSession

    with pytest.warns(RuntimeWarning):
        AcpSession(BridgeConfig(agent_a_permission_mode="allow_all_own_turns"))
    assert "!!! DANGER" in capsys.readouterr().err


def _authority_worker(values, results):
    try:
        d = Daemon(BridgeConfig(**values))
    except DaemonError as exc:
        results.put(str(exc))
    else:
        d.close()
        results.put("unexpected_second_authority")


def test_target_authority_is_exclusive_across_processes(broker):
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(target=_authority_worker, args=(vars(broker.cfg), results))
    process.start()
    process.join(10)
    assert not process.is_alive()
    assert process.exitcode == 0
    assert results.get(timeout=1) == "dispatch_authority_already_held"


def test_crash_after_claim_before_write_still_consumes_id(broker):
    from firefly_bridge.rpc import ConnectionClosed

    enqueue(broker)
    with patch.object(
        broker.session.conn, "request", side_effect=ConnectionClosed("synthetic crash")
    ):
        turn = broker.pump_once()
    assert turn.state == "unknown"
    assert broker.store.unresolved()
    assert enqueue(broker)["queue_state"] == "unknown"
    assert broker.pump_once() is None
    assert broker.session.conn.calls == []
