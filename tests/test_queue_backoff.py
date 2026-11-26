"""Queue backoff for presence-deferred wakes (user decision 4): the queue is the ONE re-tryer.

Injected clock only (no sleep), fake presence sources, Popen/socket blocked: no process, no socket."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import queue as q
from firefly_bridge import speaker as sp
from firefly_bridge.queue import BusyRefused, Outbox
from tests.hmac_fixtures import make_keyring, signed_body

ROOT = Path(__file__).resolve().parents[1]
OWNER = "owner"
ROSTER = ["agent-a", "agent-b", "agent-c", "agent-d", OWNER, "peerx"]
EPOCH = 1_763_130_000.0


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _isolated():
    sp.use_config(ROOT / "examples" / "config.example.toml")
    with (
        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("spawn")),
        mock.patch.object(socket, "socket", side_effect=AssertionError("socket")),
        mock.patch("time.sleep", side_effect=AssertionError("real sleep")),
    ):
        yield
    sp.use_config(None)


class Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, turn):
        self.calls.append(turn.message_id)
        return {"stop_reason": "end_turn"}


class Scripted:
    """presence_gate returning a scripted sequence of actions (last one repeats)."""

    def __init__(self, *actions: str) -> None:
        self.actions = list(actions)
        self.calls = 0

    def __call__(self, turn):
        self.calls += 1
        return self.actions.pop(0) if len(self.actions) > 1 else self.actions[0]


def _box(gate, clock, runner=None, **kw):
    return Outbox(runner or Runner(), busy_wait_s=120, now=clock, presence_gate=gate, **kw)


# --- schedule -------------------------------------------------------------------------------


def test_busy_reschedules_with_backoff_and_only_due_items_are_retried() -> None:
    clock, runner, gate = Clock(), Runner(), Scripted("deferred_busy")
    box = _box(gate, clock, runner)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert (t.state, t.attempts, t.next_attempt_at) == (q.DEFERRED, 1, 1030.0)
    assert box.next_due_at() == 1030.0
    clock.t = 1029.9
    assert box.pump_once() is None and gate.calls == 1  # not due: presence not even read
    clock.t = 1030.0
    box.pump_once()
    assert (t.attempts, t.next_attempt_at) == (2, 1090.0)  # 30 -> 60
    clock.t = 1090.0
    box.pump_once()
    assert (t.attempts, t.next_attempt_at) == (3, 1210.0)  # -> 120
    assert runner.calls == []


def test_backoff_doubles_to_cap_then_expires_to_inbox() -> None:
    clock, gate = Clock(0.0), Scripted("deferred_busy")
    box = _box(gate, clock, max_deferred_attempts=8)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    delays = []
    while t.state not in (q.DEFERRED_EXPIRED, q.DELIVERED):
        before = clock.t
        box.pump_once()
        if t.next_attempt_at is not None:
            delays.append(t.next_attempt_at - before)
            clock.t = t.next_attempt_at  # jump the injected clock, never sleep
    assert delays == [30, 60, 120, 240, 480, 600, 600]
    assert (t.state, t.attempts, t.route) == (q.DEFERRED_EXPIRED, 8, q.ROUTE_INBOX)
    assert "deferred_busy" in t.reason and "attempts=8" in t.reason
    assert box.status()["pending"] == [] and box.next_due_at() is None
    rec = t.to_receipt_dict()
    assert (rec["queue_state"], rec["route"], rec["attempts"]) == ("deferred_expired", "inbox", 8)
    assert box.journal[-1]["event"] == q.DEFERRED_EXPIRED  # recorded, not silently dropped


def test_unknown_also_retries_then_wakes_when_idle() -> None:
    clock, runner = Clock(), Runner()
    gate = Scripted("deferred_unknown", "deferred_busy", "wake")
    box = _box(gate, clock, runner)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert (t.state, t.presence_action) == (q.DEFERRED, "deferred_unknown")
    clock.t = t.next_attempt_at
    box.pump_once()
    assert t.attempts == 2
    clock.t = t.next_attempt_at
    box.pump_once()
    assert (t.state, runner.calls, t.attempts) == (q.DELIVERED, ["m1"], 2)


def test_absent_never_enters_retry_loop() -> None:
    clock, runner, gate = Clock(), Runner(), Scripted("deferred_absent")
    box = _box(gate, clock, runner)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert (t.state, t.route, t.attempts, t.next_attempt_at) == (
        q.DEFERRED_ABSENT,
        "inbox",
        0,
        None,
    )
    clock.t += 10_000
    assert box.pump_once() is None and gate.calls == 1 and runner.calls == []


@pytest.mark.parametrize("action", ["gated_non_vip", "suppressed_self_echo", "bogus"])
def test_gated_or_invalid_actions_are_terminal(action: str) -> None:
    clock, runner = Clock(), Runner()
    box = _box(Scripted(action), clock, runner)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert t.state == q.FAILED and t.attempts == 0 and runner.calls == []
    assert t.route == q.ROUTE_INBOX  # never lost: back to the PR/inbox, just no wake
    assert box.status()["pending"] == []


def test_gate_error_fails_closed_as_unknown_retry() -> None:
    clock, runner = Clock(), Runner()
    box = _box(mock.Mock(side_effect=OSError("disk")), clock, runner)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert (t.state, t.presence_action, t.attempts) == (q.DEFERRED, "deferred_unknown", 1)
    assert runner.calls == []


def test_runner_busy_refused_uses_same_backoff_when_presence_on() -> None:
    clock = Clock()
    calls = []

    def runner(turn):
        calls.append(turn.message_id)
        if len(calls) == 1:
            raise BusyRefused("dispatch_closed_busy_or_unknown")
        return {"stop_reason": "end_turn"}

    box = _box(Scripted("wake"), clock, runner)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert (t.state, t.attempts, t.next_attempt_at) == (q.DEFERRED, 1, 1030.0)
    assert box.status()["in_flight"] is None and box.status()["pending"] == ["m1"]
    box.pump_once()
    assert calls == ["m1"]  # not due yet: no second dispatch
    clock.t = 1030.0
    box.pump_once()
    assert (t.state, calls) == (q.DELIVERED, ["m1", "m1"])


def test_deferred_item_does_not_block_others_and_is_exempt_from_busy_wait() -> None:
    clock, runner = Clock(), Runner()

    def gate(turn):
        return "deferred_busy" if turn.message_id == "m1" else "wake"

    box = _box(gate, clock, runner)
    t1 = box.enqueue("m1", "s", "a", "agent-a: a")
    box.enqueue("m2", "s", "b", "agent-b: b", sender="agent-b")
    box.drain()
    assert runner.calls == ["m2"] and t1.state == q.DEFERRED
    clock.t += 500  # > busy_wait_s=120: a deferred item is bounded by attempts, not busy_wait
    box.pump_once()
    assert t1.state == q.DEFERRED and t1.reason != "slot_busy_wait_exceeded" and t1.attempts == 2


def test_cancel_withdraws_deferred_item() -> None:
    clock = Clock()
    box = _box(Scripted("deferred_busy"), clock)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert box.cancel("m1") is t and t.state == q.CANCELLED and box.next_due_at() is None


def test_no_retry_loop_inside_the_queue() -> None:
    """Re-try is scheduled (next_attempt_at); one pump = at most one presence read per item."""
    clock, gate = Clock(), Scripted("deferred_busy")
    box = _box(gate, clock)
    box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.drain(max_turns=50)
    assert gate.calls == 1


# --- presence off => unchanged ----------------------------------------------------------------


def test_without_presence_gate_queue_is_unchanged() -> None:
    clock = Clock()
    calls = []

    def runner(turn):
        calls.append(turn.message_id)
        raise BusyRefused("dispatch_closed_busy_or_unknown")

    box = Outbox(runner, busy_wait_s=120, now=clock)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert (t.state, t.reason) == (q.FAILED, "peer_busy_not_sent:dispatch_closed_busy_or_unknown")
    assert (t.attempts, t.next_attempt_at, t.route) == (0, None, "")
    assert box.next_due_at() is None and "deferred" not in box.status()
    t2 = box.enqueue("m2", "s", "x", "agent-a: x")
    clock.t += 121
    box.pump_once()
    assert (t2.state, t2.reason) == (q.FAILED, "slot_busy_wait_exceeded")  # old busy-wait intact


def test_unconfigured_presence_gives_no_gate_and_no_kwargs() -> None:
    cfg = pr.PresenceConfig()  # no terminals
    gate = pr.queue_gate(
        target="peerb", own_aliases=["peerb"], roster=ROSTER, sources=[], cfg=cfg, now=Clock()
    )
    assert gate is None and pr.queue_kwargs(cfg, gate) == {}
    assert pr.queue_kwargs(None, None) == {}
    box = Outbox(Runner(), **pr.queue_kwargs(cfg, gate))
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert t.state == q.DELIVERED and t.presence_action == ""


# --- real presence decisions through the gate -----------------------------------------------


def _fake(state: str, age: float = 5.0):
    return lambda name: pr.PresenceRecord(name, EPOCH - age, state)


@pytest.mark.parametrize(
    "state,expected",
    [("idle", q.DELIVERED), ("busy", q.DEFERRED), ("absent", q.DEFERRED_ABSENT)],
)
def test_queue_gate_with_presence_config(tmp_path: Path, state: str, expected: str) -> None:
    cfg = pr.PresenceConfig(
        terminals={"peerb": "/nao/existe.json"},
        max_deferred_attempts=3,
        backoff_base_s=10,
        backoff_cap_s=15,
    )
    ring = make_keyring(tmp_path)
    gate = pr.queue_gate(
        target="peerb",
        own_aliases=["peerb"],
        roster=ROSTER,
        sources=[_fake(state)],
        cfg=cfg,
        now=lambda: EPOCH,
        keyring=ring["ring"],
    )
    clock, runner = Clock(), Runner()
    box = Outbox(runner, now=clock, **pr.queue_kwargs(cfg, gate))
    t = box.enqueue("m1", "s", "oi", signed_body(ring, "agent-a", "oi"))
    box.pump_once()
    assert t.state == expected
    if state == "busy":
        assert t.next_attempt_at == clock.t + 10
        clock.t = t.next_attempt_at
        box.pump_once()
        assert t.next_attempt_at == clock.t + 15  # cap from config
        clock.t = t.next_attempt_at
        box.pump_once()
        assert (t.state, t.route, t.attempts) == (q.DEFERRED_EXPIRED, "inbox", 3)
        assert runner.calls == []


def test_owner_busy_is_deferred_not_forced(tmp_path: Path) -> None:
    cfg = pr.PresenceConfig(terminals={"peerb": "/x.json"})
    ring = make_keyring(tmp_path)
    gate = pr.queue_gate(
        target="peerb",
        own_aliases=["peerb"],
        roster=ROSTER,
        sources=[_fake("busy")],
        cfg=cfg,
        now=lambda: EPOCH,
        keyring=ring["ring"],
    )
    box = Outbox(Runner(), now=Clock(), **pr.queue_kwargs(cfg, gate))
    t = box.enqueue("m1", "s", "oi", signed_body(ring, "agent-a", "oi"), sender="agent-a")
    box.pump_once()
    assert t.presence_action == pr.DEFERRED_BUSY


# --- config ---------------------------------------------------------------------------------


def test_config_parses_backoff_knobs_and_defaults() -> None:
    cfg = pr.parse_presence_config_text("[channel_presence]\n")
    assert (cfg.max_deferred_attempts, cfg.backoff_base_s, cfg.backoff_cap_s) == (8, 30.0, 600.0)
    cfg = pr.parse_presence_config_text(
        "[channel_presence]\nmax_deferred_attempts = 3\nbackoff_base_s = 5\nbackoff_cap_s = 40\n"
    )
    assert (cfg.max_deferred_attempts, cfg.backoff_base_s, cfg.backoff_cap_s) == (3, 5.0, 40.0)


@pytest.mark.parametrize(
    "body",
    [
        "max_deferred_attempts = 0",
        "max_deferred_attempts = true",
        "max_deferred_attempts = 1.5",
        "backoff_base_s = 0",
        "backoff_cap_s = -1",
        "backoff_base_s = 60\nbackoff_cap_s = 30",
    ],
)
def test_config_rejects_bad_backoff_knobs(body: str) -> None:
    with pytest.raises(ValueError):
        pr.parse_presence_config_text("[channel_presence]\n" + body + "\n")


def test_shipped_examples_parse_with_backoff_defaults() -> None:
    for rel in ("examples/config.example.toml", "config/example.toml"):
        cfg = pr.load_presence_config(ROOT / rel)
        assert cfg.max_deferred_attempts == 8


# --- single owner -----------------------------------------------------------------------------


def test_only_the_queue_uses_the_backoff() -> None:
    users = []
    for path in [*(ROOT / "firefly_bridge").glob("*.py"), *(ROOT / "scripts").iterdir()]:
        if path.is_file() and path.name != "presence.py":
            if "deferred_backoff_s" in path.read_text(encoding="utf-8", errors="replace"):
                users.append(path.name)
    assert users == ["queue.py"]


def test_queue_module_spawns_nothing() -> None:
    src = (ROOT / "firefly_bridge" / "queue.py").read_text(encoding="utf-8")
    for bad in ("subprocess", "socket", "tmux", "Popen", "sleep(", "--live", ".sock"):
        assert bad not in src, bad
