"""Wake-origin deny hardening (on top of the P0 IPC deny). Offline, fake Peer only.

1. _deny_wake_origin respects permission_claim: one response per request id.
2. Pending card: unique tmp write; daemon/stdio report a write failure.
3. Receipts: approvals_n counts real allows; perm_seen_n counts requests.
4. dry_run reports the real permission handler.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from test_rc2 import make_broker as make_broker  # noqa: F401  (fixture)
from test_v030 import Peer
from test_wake_vs_tool import _write_perm_mock

import firefly_bridge.channel as channel
import firefly_bridge.ipc as ipc_mod
from firefly_bridge.channel import ChannelConfig, run_channel_turn
from firefly_bridge.wake_envelope import (
    count_permission_requests,
    count_real_approvals,
    write_pending_card,
)

SID = "sess-example-0001"
ALLOW = {"kind": "allow_once", "optionId": "yes"}
REJECT = {"kind": "reject_once", "optionId": "no"}


class AgentPeer(Peer):
    """Fake leader: while our prompt runs, asks for the given tools, then finishes."""

    def __init__(self, session, tools):
        super().__init__(session)
        self.tools = tools

    def request(self, method, params, rpc_id=None):
        call = super().request(method, params, rpc_id)
        if method == "session/prompt":
            for rid, tool, options in self.tools:
                self.session._on_request(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "method": "session/request_permission",
                        "params": {
                            "sessionId": params["sessionId"],
                            "_meta": {"agentBridge": dict(self.session._origin)},
                            "toolCall": tool,
                            "options": list(options),
                        },
                    }
                )
            self.finish()
        return call


def edit(path):
    return {"kind": "edit", "name": "edit_file", "title": "synthetic edit", "rawInput": {"path": str(path)}}


def deployment(make_broker, tmp_path, tools):
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            agent_a_permission_mode="allow_all_own_turns", session_cwd=str(tmp_path), shared_dir=str(tmp_path)
        )
    d.session.conn = AgentPeer(d.session, list(tools))
    return d


def run_turn(d, mid, *, wake):
    d.handle_ipc("agent-a", "enqueue", {"message_id": mid, "body": "synthetic", **({"wake_origin": True} if wake else {})})
    d.pump_once()
    d.pump_once()


def responses(d, rid):
    return [res for r, res in d.session.conn.responses if r == rid]


# 1. one response per request id ----------------------------------------------------


def test_wake_deny_does_not_answer_a_request_already_claimed(make_broker, tmp_path):
    d = deployment(make_broker, tmp_path, [("p1", edit(tmp_path / "a.md"), [ALLOW, REJECT])])
    d.session.permission_claim = lambda turn_id, rid: False  # another authority got it first
    run_turn(d, "w-claimed", wake=True)
    assert responses(d, "p1") == []
    assert any(a.get("kind") == "wake_origin_already_claimed" for a in d.session.alerts)


def test_wake_deny_still_answers_when_claim_is_ours(make_broker, tmp_path):
    d = deployment(make_broker, tmp_path, [("p1", edit(tmp_path / "a.md"), [ALLOW, REJECT])])
    run_turn(d, "w-ours", wake=True)
    assert responses(d, "p1") == [{"outcome": {"outcome": "selected", "optionId": "no"}}]


# 2. pending card ---------------------------------------------------------------


def test_pending_card_write_uses_a_unique_tmp(tmp_path):
    target = tmp_path / "cards" / "pending_card.json"
    target.parent.mkdir()
    (target.parent / "pending_card.json.tmp").mkdir()  # the old fixed tmp name is taken
    write_pending_card(target, {"status": "denied", "n": 1})
    write_pending_card(target, {"status": "denied", "n": 2})
    assert json.loads(target.read_text(encoding="utf-8"))["n"] == 2
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    leftovers = sorted(p.name for p in target.parent.iterdir() if p.name != "pending_card.json.tmp")
    assert leftovers == ["pending_card.json"]


def test_daemon_reports_pending_card_write_failure_and_still_denies(make_broker, tmp_path):
    d = deployment(make_broker, tmp_path, [("p1", edit(tmp_path / "a.md"), [ALLOW, REJECT])])
    (Path(d.cfg.state_dir) / "pending_card.json").mkdir()  # card target is unwritable
    run_turn(d, "w-card", wake=True)
    assert responses(d, "p1") == [{"outcome": {"outcome": "selected", "optionId": "no"}}]
    assert any(a.get("kind") == "pending_card_write_failed" for a in d.session.alerts)


def test_stdio_reports_pending_card_write_failure(tmp_path):
    mock = _write_perm_mock(tmp_path, SID)
    (tmp_path / "card_dir").mkdir()
    cfg = ChannelConfig(
        socket_path=str(tmp_path / "unused.sock"),
        session_id=SID,
        session_cwd=str(tmp_path),
        ledger_path=str(tmp_path / "ledger.json"),
        wake_dir=str(tmp_path / "wake-notes"),
        pending_card_path=str(tmp_path / "card_dir"),  # a directory: os.replace fails
        hold_pid_file=str(tmp_path / "missing.pid"),
        use_daemon_ipc=False,
        turn_timeout_s=5.0,
        connect_timeout_s=2.0,
        load_timeout_s=2.0,
    )
    res = run_channel_turn(cfg, "recado", message_id="id_cardfail01", spawn_cmd=[sys.executable, str(mock)], write_wake=False)
    assert res["wake_origin_denied_n"] == 1
    assert res["pending_card_error"]


# 3. receipt counters --------------------------------------------------------------


def test_receipt_counters_count_real_allows_and_distinct_requests(make_broker, tmp_path):
    d = deployment(
        make_broker,
        tmp_path,
        [("p1", edit(tmp_path / "a.md"), [ALLOW, REJECT]), ("p2", edit(tmp_path / "b.md"), [ALLOW, REJECT])],
    )
    run_turn(d, "n-allow", wake=False)  # normal deployment turn: both allowed
    events = d.handle_ipc("agent-a", "receipt", {"message_id": "n-allow"})["permission_events"]
    assert [r for _, r in d.session.conn.responses] == [{"outcome": {"outcome": "selected", "optionId": "yes"}}] * 2
    assert count_real_approvals(events) == 2
    assert count_permission_requests(events) == 2
    legacy = [{"phase": "response_sent", "action": "allow_once"}, {"phase": "decision_intent", "action": "allow_once"}]
    assert count_real_approvals(legacy) == 1
    assert count_permission_requests(legacy) == 1


def test_ipc_wake_receipt_perm_seen_counts_requests(make_broker, tmp_path, monkeypatch):
    d = deployment(
        make_broker,
        tmp_path,
        [("p1", edit(tmp_path / "a.md"), [ALLOW, REJECT]), ("p2", edit(tmp_path / "b.md"), [ALLOW, REJECT])],
    )

    def fake_ipc_call(cfg, op, args):
        rec = d.handle_ipc("agent-a", op, dict(args or {}))
        if op.startswith("enqueue"):
            d.pump_once()
            d.pump_once()
        return rec

    monkeypatch.setattr(ipc_mod, "ipc_call", fake_ipc_call)
    monkeypatch.setattr(channel, "_daemon_ipc_ready", lambda cfg: True)
    cfg = ChannelConfig(
        socket_path=str(tmp_path / "unused.sock"),
        session_id=SID,
        state_dir=str(tmp_path / "channel-state"),
        ledger_path=str(tmp_path / "ledger.json"),
        wake_dir=str(tmp_path / "wake-notes"),
        hold_pid_file=str(tmp_path / "missing.pid"),
        turn_timeout_s=0.3,
    )
    res = run_channel_turn(cfg, "recado", message_id="w-count", write_wake=False)
    assert res["perm_seen_n"] == 2
    assert res["wake_origin_denied_n"] == 2
    assert res["approvals_n"] == 0


# 4. dry_run handler ----------------------------------------------------------------


def _dry_cfg(tmp_path, **kw):
    return ChannelConfig(
        socket_path=str(tmp_path / "missing.sock"),
        session_id=SID,
        ledger_path=str(tmp_path / "ledger.json"),
        wake_dir=str(tmp_path / "wake-notes"),
        pending_card_path=str(tmp_path / "pending_card.json"),
        **kw,
    )


def test_dry_run_reports_real_handler_not_stale_policy(tmp_path, monkeypatch):
    hold = tmp_path / "hold.pid"
    hold.write_text(str(os.getpid()), encoding="utf-8")  # a live pid
    cfg = _dry_cfg(tmp_path, hold_pid_file=str(hold), answer_permissions=True, permission_mode="allow_all_own_turns")
    dry = run_channel_turn(cfg, "Oi", dry_run=True)
    assert dry["permission_handler"] == "leader_stdio_wake_deny"
    assert dry["hold_race"] is True
    assert dry["ready_for_live"] is False  # no private leader socket

    cfg = _dry_cfg(tmp_path, hold_pid_file=str(tmp_path / "missing.pid"))
    assert run_channel_turn(cfg, "Oi", dry_run=True)["hold_race"] is False

    monkeypatch.setattr(channel, "_daemon_ipc_ready", lambda cfg: True)
    dry = run_channel_turn(_dry_cfg(tmp_path, hold_pid_file=str(hold)), "Oi", dry_run=True)
    assert dry["permission_handler"] == "wake_origin_deny"
    assert dry["hold_race"] is False
    assert dry["ready_for_live"] is True


def _store_down(*_a, **_k):
    raise RuntimeError("store down")


def test_wake_deny_is_sent_even_when_claim_store_or_receipt_log_fails(make_broker, tmp_path):
    # af2ef57 returned silently here, leaving the request open on the leader's TUI.
    d = deployment(make_broker, tmp_path, [("p1", edit(tmp_path / "a.md"), [ALLOW, REJECT])])
    d.session.approval_receipts_path = None  # receipt log unavailable
    run_turn(d, "w-audit", wake=True)
    assert responses(d, "p1") == [{"outcome": {"outcome": "selected", "optionId": "no"}}]

    d = deployment(make_broker, tmp_path, [("p1", edit(tmp_path / "b.md"), [ALLOW, REJECT])])
    d.session.permission_claim = _store_down
    run_turn(d, "w-claim", wake=True)
    assert responses(d, "p1") == [{"outcome": {"outcome": "selected", "optionId": "no"}}]
    assert any(a.get("kind") == "permission_audit_unavailable" for a in d.session.alerts)
