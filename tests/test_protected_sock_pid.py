"""Sock/pid files vs protected_resources in a NORMAL (non-wake) deployment turn.

Policy is pending owner's decision, so the sock/pid cases are strict xfail: they
document today's gap (allow_all_own_turns approves edits to the leader socket and
hold pid/lock files) and turn red the moment the policy lands, forcing the marker
off. The guards below prove the harness really allows and really protects.
Offline, fake Peer only; nothing touches a real socket.
"""

from __future__ import annotations

import pytest
from test_deny_hardening import ALLOW, REJECT, deployment, edit, responses, run_turn
from test_rc2 import make_broker as make_broker  # noqa: F401  (fixture)

ALLOWED = [{"outcome": {"outcome": "selected", "optionId": "yes"}}]
DENIED = [{"outcome": {"outcome": "selected", "optionId": "no"}}]
PENDING = pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="policy pending owner decision: sock/pid not in protected_resources"
)


def answer_for(make_broker, tmp_path, target, **overrides):
    d = deployment(make_broker, tmp_path, [("p1", edit(target), [ALLOW, REJECT])])
    for key, value in overrides.items():
        setattr(d.cfg, key, value)
    run_turn(d, "normal-1", wake=False)
    return d, responses(d, "p1")


# guards (must pass today) -----------------------------------------------------------


def test_guard_normal_turn_allows_an_ordinary_edit(make_broker, tmp_path):
    _, res = answer_for(make_broker, tmp_path, tmp_path / "notes.md")
    assert res == ALLOWED


def test_guard_normal_turn_denies_edit_inside_state_dir(make_broker, tmp_path):
    # make_broker numbers state dirs per daemon: the next one is state-0 here.
    _, res = answer_for(make_broker, tmp_path, tmp_path / "state-0" / "bridge_state.json")
    assert res == DENIED, res


# pending policy ---------------------------------------------------------------------


@PENDING
def test_normal_turn_denies_edit_to_leader_peerb_bridge_sock_in_cwd(make_broker, tmp_path):
    _, res = answer_for(make_broker, tmp_path, tmp_path / "leader-peerb-bridge.sock")
    assert res == DENIED, res


@PENDING
def test_normal_turn_denies_edit_to_any_dot_sock(make_broker, tmp_path):
    _, res = answer_for(make_broker, tmp_path, tmp_path / "run" / "other-agent.sock")
    assert res == DENIED, res


@PENDING
def test_normal_turn_denies_edit_to_daemon_own_socket_path(make_broker, tmp_path):
    d, res = answer_for(make_broker, tmp_path, tmp_path / "leader-0.sock")
    assert d.cfg.socket_path == str(tmp_path / "leader-0.sock")  # the daemon's own socket
    assert res == DENIED, res


@PENDING
def test_normal_turn_denies_edit_to_hold_pid_file(make_broker, tmp_path):
    _, res = answer_for(make_broker, tmp_path, tmp_path / "run" / "bridge_hold_4242.pid")
    assert res == DENIED, res


@PENDING
def test_normal_turn_denies_edit_to_hold_lock_file(make_broker, tmp_path):
    _, res = answer_for(make_broker, tmp_path, tmp_path / "run" / "bridge_hold_4242.lock")
    assert res == DENIED, res


@PENDING
def test_normal_turn_denies_edit_to_configured_hold_pid_file(make_broker, tmp_path):
    pid = str(tmp_path / "hold" / "channel_hold.pid")
    _, res = answer_for(make_broker, tmp_path, pid, hold_pid_file=pid)
    assert res == DENIED, res
