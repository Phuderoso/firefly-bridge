"""Admission/claim boundary, crash and restart. Synthetic clocks/peer only."""

import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from test_rc2 import make_broker as make_broker
from test_v030 import ready

from firefly_bridge.audit import local_time
from firefly_bridge.broker_store import BrokerStore
from firefly_bridge.errors import PreSendRejected


def cross_during_claim(d):
    clock = [datetime(2026, 11, 9, 21, 59, 59, tzinfo=ZoneInfo("UTC")).timestamp()]
    d.store.now = lambda: clock[0]
    original = d.store.interval_ready
    calls = [0]

    def cross(sender, cfg):
        calls[0] += 1
        if calls[0] == 3:
            clock[0] += 2
        return original(sender, cfg)

    d.store.interval_ready = cross
    return clock


def test_boundary_refusal_is_durable_terminal_local_with_no_remote_lease(make_broker):
    d = make_broker(quiet_hours_start="22:00", quiet_hours_end="08:00")
    clock = cross_during_claim(d)
    d.enqueue("boundary", "synthetic message")
    turn = d.pump_once()
    receipt = d.receipt("agent-a", "boundary")
    assert (turn.state, turn.reason) == ("failed", "rejected_quiet_hours")
    assert not d.store.unresolved() and d.outbox._in_flight is None
    assert d.session._own_turn is d.session._origin is d.session.active_call is None
    assert d.session.conn.calls == [] and d.session.conn.notifications == []
    assert receipt["attempted_at"] is None and not receipt["attempt_committed"]
    assert receipt["rejected_at_local"] == local_time(clock[0])
    assert receipt["terminal_at"] is None  # local refusal is NOT a remote terminal
    d.enqueue("boundary", "synthetic message")  # consumed ID, no retry
    assert d.pump_once() is None and d.session.conn.calls == []
    cfg = d.cfg
    d.close()
    reopened = BrokerStore(
        Path(cfg.state_dir) / "broker.sqlite3",
        cfg.session_id + "|" + str(Path(cfg.socket_path).resolve()),
    )
    assert reopened.lookup("boundary")["reason"] == "rejected_quiet_hours"
    assert not reopened.unresolved()
    reopened.close()


def test_no_claim_before_quiet_refusal_and_no_revival_after_new_window(make_broker):
    d = make_broker(quiet_hours_start="22:00", quiet_hours_end="08:00")
    clock = cross_during_claim(d)
    d.enqueue("first", "hello")
    d.pump_once()
    clock[0] += 10 * 3600
    ready(d.session)
    d.session.conn.terminal = True
    d.enqueue("second", "hello")
    assert d.pump_once().state == "delivered"
    assert [call[0] for call in d.session.conn.calls] == ["session/prompt"]
    assert d.store.lookup("first")["attempted_at"] is None


def test_crash_after_durable_refusal_before_queue_settle_is_already_failed(make_broker):
    d = make_broker(quiet_hours_start="22:00", quiet_hours_end="08:00")
    clock = cross_during_claim(d)
    d.enqueue("crash-window", "hello")
    original = d.session.persist_claim
    seen = []

    def observe(turn, proof):
        try:
            return original(turn, proof)
        except PreSendRejected:
            r = d.store.lookup(turn.message_id)
            seen.append((r["queue_state"], r["reason"], r["attempted_at"], d.store.unresolved()))
            raise

    d.session.persist_claim = observe
    d.pump_once()
    assert seen == [("failed", "rejected_quiet_hours", None, False)]
    assert d.receipt("agent-a", "crash-window")["rejected_at_local"] == local_time(clock[0])


def test_legacy_unattempted_unknown_reconciles_but_real_attempt_stays_blocked(tmp_path):
    path = tmp_path / "state" / "broker.sqlite3"
    store = BrokerStore(path, "synthetic-target", now=lambda: 1000)
    for mid, attempted, proof in [("old-prewrite", None, None), ("actually-ambiguous", 999, "{}")]:
        store.db.execute(
            "INSERT INTO messages(id,sender,digest,turn_id,generation,accepted,attempted,state,receipt,proof) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                mid,
                "agent-a",
                "digest",
                mid,
                0,
                998,
                attempted,
                "unknown",
                json.dumps({"reason": "runner_error:StoreError"}),
                proof,
            ),
        )
    store.close()
    store = BrokerStore(path, "synthetic-target", now=lambda: 1100)
    assert store.lookup("old-prewrite")["reason"] == "reconciled_pre_send_rejection"
    assert store.lookup("old-prewrite")["queue_state"] == "failed"
    assert store.lookup("old-prewrite")["rejected_at_local"] == local_time(1100)
    assert store.lookup("actually-ambiguous")["queue_state"] == "unknown"
    assert store.unresolved()
    store.close()


def test_generic_preclaim_io_error_is_not_misclassified_as_safe_refusal(make_broker):
    d = make_broker()
    d.enqueue("io-uncertain", "hello")

    def fail(*args):
        raise OSError("synthetic failure")

    d.session.persist_claim = fail
    assert d.pump_once().state == "unknown"
    assert d.store.unresolved()
    assert d.session.conn.calls == []


def test_exception_after_committed_claim_remains_ambiguous_across_restart(make_broker):
    d = make_broker()
    d.enqueue("committed-uncertain", "hello")
    original = d.session.persist_claim

    def fail_after_commit(turn, proof):
        original(turn, proof)
        raise OSError("synthetic uncertainty after commit")

    d.session.persist_claim = fail_after_commit
    assert d.pump_once().state == "unknown"
    assert d.store.lookup("committed-uncertain")["attempt_committed"]
    cfg = d.cfg
    d.close()
    store = BrokerStore(
        Path(cfg.state_dir) / "broker.sqlite3",
        cfg.session_id + "|" + str(Path(cfg.socket_path).resolve()),
    )
    assert store.lookup("committed-uncertain")["queue_state"] == "unknown"
    assert store.unresolved()
    store.close()
