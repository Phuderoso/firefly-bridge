"""agent-b’s RC3 probes retained as regressions; no real keys, sockets, sessions or sends."""

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from test_rc2 import make_broker as make_broker
from test_v030 import permission


def test_guard_blocks_its_ipc_human_key(make_broker, tmp_path):
    # Filename only: no credential is created, opened or read.
    key_dir = tmp_path / "keys"
    with pytest.warns(RuntimeWarning):
        d = make_broker(ipc_keys_dir=str(key_dir), agent_a_permission_mode="allow_all_own_turns")
    d.enqueue("probe-key", "synthetic message")
    d.pump_once()
    s = d.session
    s.observation_expired = False
    request = permission(s)
    request["params"]["toolCall"] = {
        "kind": "read",
        "name": "read_file",
        "rawInput": {"path": str(key_dir / "human.key")},
    }
    request["params"]["options"].append({"kind": "reject_once", "optionId": "no"})
    s._on_request(request)
    print(
        "key-classification",
        s.permission_log[-1]["action"],
        s.permission_log[-1]["reason"],
        s.conn.responses,
    )
    assert not any(result["outcome"].get("optionId") == "once" for _, result in s.conn.responses)


def test_quiet_boundary_before_claim_does_not_poison_remote_lease(make_broker):
    zone = ZoneInfo("UTC")
    before = datetime(2026, 11, 9, 21, 59, 59, tzinfo=zone).timestamp()
    clock = [before]
    d = make_broker(quiet_hours_start="22:00", quiet_hours_end="08:00")
    d.store.now = lambda: clock[0]
    d.enqueue("probe-boundary", "synthetic message")
    original = d.store.interval_ready
    calls = [0]

    def cross_at_claim(sender, cfg):
        calls[0] += 1
        if calls[0] == 3:  # dispatch gate, run_turn gate, then durable claim recheck
            clock[0] += 2
        return original(sender, cfg)

    d.store.interval_ready = cross_at_claim
    turn = d.pump_once()
    receipt = d.store.lookup(turn.message_id)
    print(
        "boundary-state",
        turn.state,
        turn.reason,
        "rpc_calls",
        d.session.conn.calls,
        "attempted",
        receipt["attempted_at"],
        "unresolved",
        d.store.unresolved(),
    )
    assert d.session.conn.calls == []
    assert turn.state != "unknown", (
        "Known pre-send quiet denial must not wait for an impossible remote terminal"
    )
    assert not d.store.unresolved()


def test_rc2_package_exports_are_preserved():
    from firefly_bridge import Bridge, Receipt

    assert Bridge is not None and Receipt is not None
