"""RC2 review regressions, fake peers/history only. No Grok API or Mac calls."""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from test_v030 import Peer, permission, ready

from firefly_bridge.config import BridgeConfig, ConfigError, load_config
from firefly_bridge.daemon import Daemon
from firefly_bridge.privacy import redact_text
from firefly_bridge.recovery import HistoryReply, RecoveryUnavailable, UnavailableChatHistory


@pytest.fixture
def make_broker(tmp_path):
    opened = []

    def create(**overrides):
        saved = overrides.pop("_cfg", None)
        defaults = overrides.pop("_defaults", False)
        values = dict(
            socket_path=str(tmp_path / f"leader-{len(opened)}.sock"),
            session_id="sess-example-0001",
            live_send=True,
            state_dir=str(tmp_path / f"state-{len(opened)}"),
            turn_timeout_s=0.001,
            per_sender_daily_quota=100,
        )
        if not defaults:
            values.update(
                sender_interval_s=0,
                global_interval_s=0,
                pacing_minimums_enabled=False,
                post_turn_interval_s=0,
                target_interval_s=0,
            )
        cfg = saved or BridgeConfig(**{**values, **overrides})
        d = Daemon(cfg)
        d.session.conn = Peer(d.session)
        ready(d.session)
        d.control("human", "opt_in")
        d.control("recipient", "opt_in")
        opened.append(d)
        return d

    yield create
    for d in opened:
        d.close()


def begin(d, sender="agent-a", mid="message-1"):
    d.enqueue(mid, "synthetic message", sender=sender)
    return d.pump_once()


def chunk(session, text="captured", seq=1, **changes):
    content = {"type": "text", "text": text}
    content.update(changes)
    session._on_notification(
        {
            "method": "session/update",
            "params": {
                "sessionId": session.cfg.session_id,
                "_meta": {"agentBridge": {**session._origin, "chunkSeq": seq}},
                "update": {"sessionUpdate": "agent_message_chunk", "content": content},
            },
        }
    )


class ProvenSyntheticHistory:
    """Only a fixture; NOT evidence of a documented real Grok history API."""

    proven_read_only = True

    def __init__(self, *, mismatch=False, failure=False, oversized=False):
        self.calls = []
        self.mismatch = mismatch
        self.failure = failure
        self.oversized = oversized

    def recover_reply(self, locator):
        self.calls.append(locator)
        if self.failure:
            raise ValueError("password=never-log-this")
        proof = replace(locator, sender="agent-c") if self.mismatch else locator
        text = (
            "x" * (locator.max_bytes + 1) if self.oversized else "recovered token=private-fixture"
        )
        return HistoryReply(proof, text)


def test_public_defaults_and_one_line_sender_config(tmp_path):
    cfg = BridgeConfig().validate(require_target=False)
    assert [cfg.permission_mode_for(s) for s in ("agent-a", "agent-b", "agent-c")] == ["pending"] * 3
    path = tmp_path / "one-line.toml"
    path.write_text('agent_a_permission_mode="allow_all_own_turns"\n')
    cfg = load_config(path, env={}, require_target=False)
    assert cfg.agent_a_permission_mode == "allow_all_own_turns"
    assert cfg.agent_b_permission_mode == cfg.agent_c_permission_mode == "pending"
    cfg = load_config(
        path, env={"FIREFLY_BRIDGE_AGENT_C_PERMISSION_MODE": "pending"}, require_target=False
    )
    assert cfg.agent_c_permission_mode == "pending"


def test_legacy_global_autoapproval_is_rejected_not_inherited():
    with pytest.raises(ConfigError, match="per_sender"):
        BridgeConfig(permission_mode="allow_all").validate(require_target=False)


def test_mixed_profiles_share_broker_without_policy_leak(make_broker, capsys):
    with pytest.warns(RuntimeWarning, match="allow_all_own_turns"):
        d = make_broker(agent_a_permission_mode="allow_all_own_turns")
    assert "agent-a allow_all_own_turns" in capsys.readouterr().err
    s = d.session
    for index, sender in enumerate(("agent-a", "agent-b", "agent-c")):
        ready(s)
        begin(d, sender, f"message-{index}")
        s.observation_expired = False  # keep this synthetic request inside observed window
        request = permission(s, rid=f"permission-{sender}")
        # Waiting, prefix or wrong nonce never suffices, even for broad mode.
        wrong = {**s._origin, "nonce": "another-client"}
        s._on_request(permission(s, rid=f"foreign-{sender}", meta=wrong))
        s._on_request(request)
        assert len(s.conn.responses) == 1  # only the first (agent-a) was approved
        s.conn.finish()
        assert d.pump_once().state == "delivered"
    assert d.session.policies["agent-b"].mode == d.session.policies["agent-c"].mode == "pending"


def test_deployment_example_is_pending_and_offline(make_broker, capsys):
    path = Path(__file__).parents[1] / "config" / "example.toml"
    cfg = load_config(path, env={})
    assert not cfg.live_send
    assert cfg.permission_mode == "pending"
    assert all(
        cfg.permission_mode_for(s) == "pending" for s in ("agent-a", "agent-b", "agent-c")
    )
    # The opt-in is explicit in the test, not in the shipped example.
    with pytest.warns(RuntimeWarning) as warnings:
        d = make_broker(
            agent_a_permission_mode="allow_all_own_turns",
            agent_b_permission_mode="allow_all_own_turns",
            agent_c_permission_mode="allow_all_own_turns",
        )
    assert len(warnings) == 3
    warning = capsys.readouterr().err
    for sender in ("agent-a", "agent-b", "agent-c"):
        assert f"{sender} allow_all_own_turns" in warning
        ready(d.session)
        begin(d, sender, sender + "-message")
        d.session.observation_expired = False
        before = len(d.session.conn.responses)
        d.session._on_request(permission(d.session, meta={}))
        assert len(d.session.conn.responses) == before
        d.session._on_request(permission(d.session, rid=sender + "-permission"))
        assert len(d.session.conn.responses) == before + 1
        d.session.conn.finish()
        d.pump_once()


def test_custom_agent_stays_pending_until_override(tmp_path):
    path = tmp_path / "agents.toml"
    path.write_text(
        "[bridge]\n"
        'agents = ["role-1"]\n'
        'sender = "role-1"\n'
        'prefix = "role-1: "\n'
        'ipc_principal = "role-1"\n'
        "\n"
        "[bridge.permission_mode_overrides]\n"
        'role-1 = "pending"\n',
        encoding="utf-8",
    )
    cfg = load_config(path, env={}, require_target=False)
    assert cfg.agent_names() == ("role-1",)
    assert cfg.permission_mode_for("role-1") == "pending"


def test_public_example_keeps_agent_b_and_agent_c_pending():
    cfg = load_config(Path(__file__).parents[1] / "examples" / "config.example.toml", env={})
    assert (
        cfg.agent_a_permission_mode
        == cfg.agent_b_permission_mode
        == cfg.agent_c_permission_mode
        == "pending"
    )


def test_reply_recovers_after_captured_text_redaction_failure(make_broker):
    d = make_broker()
    history = ProvenSyntheticHistory()
    d.session.chat_history = history
    begin(d)
    chunk(d.session)
    d.session.conn.finish()
    actual_redact = redact_text

    def fails_only_on_capture(text):
        if text == "captured":
            raise ValueError("synthetic redactor failure")
        return actual_redact(text)

    with patch("firefly_bridge.privacy.redact_text", side_effect=fails_only_on_capture):
        assert d.pump_once().state == "delivered"
    r = d.receipt("agent-a", "message-1")
    assert r["reply_verified"] is True
    assert r["reply_recovery"] == "recovered_chat_history"
    assert r["reply_redacted"] == "recovered [REDACTED]"
    assert len(history.calls) == 1
    assert history.calls[0].message_id == "message-1"
    assert history.calls[0].turn_id == r["turn_id"]
    assert b"private-fixture" not in (d.state_dir / "broker.sqlite3").read_bytes()
    assert len(d.session.conn.calls) == 1  # never use another prompt for recovery


@pytest.mark.parametrize("parse_failure", ["chunk_shape", "json_frame", "invalid_unicode"])
def test_reply_recovers_after_parse_failure(make_broker, parse_failure):
    d = make_broker()
    history = ProvenSyntheticHistory()
    d.session.chat_history = history
    begin(d)
    chunk(d.session, "partial")
    if parse_failure == "chunk_shape":
        chunk(d.session, seq=2, text={"not": "text"})
    elif parse_failure == "invalid_unicode":
        chunk(d.session, seq=2, text="\ud800")
    else:
        d.session.conn.malformed_lines = 1
    d.session.conn.finish()
    d.pump_once()
    r = d.receipt("agent-a", "message-1")
    assert r["reply_recovery"] == "recovered_chat_history"
    assert r["reply_verified"]
    assert "partial" not in r["reply_redacted"]
    assert len(history.calls) == 1


@pytest.mark.parametrize("failure", ["mismatch", "failure", "oversized"])
def test_history_recovery_wrong_origin_errors_and_limits_fail_closed(make_broker, failure):
    d = make_broker()
    d.session.chat_history = ProvenSyntheticHistory(**{failure: True})
    begin(d)
    d.session.conn.finish()
    assert d.pump_once().state == "delivered"
    r = d.receipt("agent-a", "message-1")
    assert not r["reply_verified"]
    assert r["reply_recovery"] == "reply_recovery_unavailable"
    assert "never-log-this" not in json.dumps(r)
    assert len(d.session.conn.calls) == 1


def test_shipping_chat_history_adapter_is_fail_closed_stub(make_broker):
    history = UnavailableChatHistory()
    assert not history.proven_read_only
    with pytest.raises(RecoveryUnavailable, match="no_proven"):
        history.recover_reply(None)
    d = make_broker()
    begin(d)
    chunk(d.session, text={"bad": "shape"})
    d.session.conn.finish()
    d.pump_once()
    r = d.receipt("agent-a", "message-1")
    assert r["queue_state"] == "delivered"
    assert r["reply_recovery"] == "reply_recovery_unavailable"
    assert not r["reply_verified"]
    assert len(d.session.conn.calls) == 1


def test_redactor_failure_preserves_ids_terminal_and_claim_after_restart(make_broker):
    d = make_broker()
    begin(d)
    chunk(d.session, "private captured output")
    d.session.conn.finish()
    with patch("firefly_bridge.privacy.redact_text", side_effect=ValueError("synthetic")):
        assert d.pump_once().state == "delivered"
        r = d.receipt("agent-a", "message-1")
        assert r["message_id"] == "message-1"
        assert r["queue_state"] == "delivered"
        assert r["attempt_committed"]
        assert r["sender"] == "agent-a"
        assert r["reply_redacted"] == "[REDACTION_FAILED]"
        assert not r["reply_verified"]
        assert r["stop_reason"] == "end_turn"
        cfg = d.cfg
        d.close()
        second = make_broker(_cfg=cfg)
        again = second.receipt("agent-a", "message-1")
        assert again["message_id"] == "message-1"
        assert again["queue_state"] == "delivered"
        assert again["attempt_committed"]
        assert again["sender"] == "agent-a"
        assert not second.store.unresolved()
        assert second.enqueue("message-1", "synthetic message")["queue_state"] == "delivered"
        assert not second.session.conn.calls


def test_old_rc1_marker_receipt_is_reconstructed_from_typed_columns(make_broker):
    d = make_broker()
    d.session.conn.terminal = True
    begin(d)
    with d.store.tx():
        d.store.db.execute(
            "UPDATE messages SET receipt=? WHERE id='message-1'",
            (
                json.dumps(
                    {
                        "message_id": "[REDACTION_FAILED]",
                        "queue_state": "[REDACTION_FAILED]",
                        "sender": "[REDACTION_FAILED]",
                    }
                ),
            ),
        )
    with patch("firefly_bridge.privacy.redact_text", side_effect=ValueError("synthetic")):
        r = d.receipt("agent-a", "message-1")
    assert r["message_id"] == "message-1"
    assert r["queue_state"] == "delivered"
    assert r["sender"] == "agent-a"
    assert r["attempt_committed"]


def test_default_three_senders_advance_without_cross_client_cooldown(make_broker):
    d = make_broker(_defaults=True)
    assert d.cfg.sender_interval_s == 1800
    assert d.cfg.busy_wait_s == 1800
    assert d.cfg.global_interval_s == 0
    elapsed = [0.0]
    d.store.now = lambda: 1800000000 + elapsed[0]
    d.outbox._now = lambda: 1000 + elapsed[0]
    d.session.conn.terminal = True
    for sender in ("agent-a", "agent-b", "agent-c"):
        d.enqueue(sender + "-message", "hello", sender=sender)
    assert d.pump_once().sender == "agent-a"
    elapsed[0] = 121  # still inside the new target-wide pacing floor
    ready(d.session)
    assert d.pump_once() is None
    elapsed[0] = 600
    ready(d.session)
    assert d.pump_once().sender == "agent-b"
    elapsed[0] = 1200
    ready(d.session)
    assert d.pump_once().sender == "agent-c"
    assert len(d.session.conn.calls) == 3


def test_ttl_equals_sender_cooldown_is_eligible_at_boundary(make_broker):
    d = make_broker(_defaults=True)
    elapsed = [0.0]
    d.store.now = lambda: 1800000000 + elapsed[0]
    d.outbox._now = lambda: 1000 + elapsed[0]
    d.session.conn.terminal = True
    begin(d, mid="first")
    d.enqueue("second", "hello")
    ready(d.session)
    elapsed[0] = 1799
    assert d.pump_once() is None
    elapsed[0] = 1800
    ready(d.session)
    assert d.pump_once().message_id == "second"
    assert len(d.session.conn.calls) == 2


@pytest.mark.parametrize(
    "values",
    [
        {"busy_wait_s": 120},
        {"busy_wait_s": 599, "sender_interval_s": 600},
        {"busy_wait_s": 1199, "sender_interval_s": 600, "global_interval_s": 1200},
        {"busy_wait_s": float("nan")},
        {"sender_interval_s": float("inf")},
    ],
)
def test_incompatible_ttl_cooldown_config_is_refused(values):
    with pytest.raises(ConfigError):
        BridgeConfig(**values).validate(require_target=False)


def test_legacy_global_field_is_per_sender_floor_not_cross_sender_timer(make_broker):
    d = make_broker(sender_interval_s=600, global_interval_s=1200, busy_wait_s=1200)
    assert d.cfg.applicable_cooldown_s == 1200
    d.session.conn.terminal = True
    begin(d, mid="first")
    ready(d.session)
    d.enqueue("agent-b", "hello", sender="agent-b")
    assert d.pump_once().sender == "agent-b"
    assert not d.store.interval_ready("agent-a", d.cfg)


def test_history_never_substitutes_for_unverified_terminal(make_broker):
    d = make_broker()
    history = ProvenSyntheticHistory()
    d.session.chat_history = history
    begin(d)
    d.session.conn.finish(meta={**d.session._origin, "nonce": "not-this-turn"})
    assert d.pump_once() is None
    assert d.store.unresolved()
    assert history.calls == []


def test_unproven_history_adapter_is_not_invoked(make_broker):
    d = make_broker()
    history = ProvenSyntheticHistory()
    history.proven_read_only = False
    d.session.chat_history = history
    begin(d)
    d.session.conn.finish()
    d.pump_once()
    assert history.calls == []
    assert d.receipt("agent-a", "message-1")["reply_recovery"] == "reply_recovery_unavailable"


def test_already_redacted_reply_is_not_reparsed_as_free_text(make_broker):
    d = make_broker()
    begin(d)
    chunk(d.session, "hello token=private-fixture")
    d.session.conn.finish()
    d.pump_once()
    with patch("firefly_bridge.privacy.redact_text", side_effect=ValueError("later failure")):
        r = d.receipt("agent-a", "message-1")
    assert r["reply_redacted"] == "hello [REDACTED]"
    assert r["reply_verified"]
    assert r["message_id"] == "message-1"
    assert r["queue_state"] == "delivered"


def test_standalone_session_also_rejects_legacy_global_approval():
    from firefly_bridge.daemon import AcpSession

    with pytest.raises(ConfigError, match="per_sender"):
        AcpSession(BridgeConfig(permission_mode="allow_all"))
