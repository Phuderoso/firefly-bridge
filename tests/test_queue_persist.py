"""Outbox disk persistence: restart-safe queue state, no sleep, no process, no socket."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from firefly_bridge import queue as q
from firefly_bridge.config import BridgeConfig
from firefly_bridge.daemon import AcpSession, Daemon
from firefly_bridge.envelope import generate_key_file, load_key, verify_text
from firefly_bridge.queue import Outbox
from firefly_bridge.queue_store import (
    QUEUE_STATE_VERSION,
    QueueStore,
    is_state_tmp,
    load_queue_state_path,
    parse_queue_config_text,
)

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _isolated():
    with (
        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("spawn")),
        mock.patch.object(socket, "socket", side_effect=AssertionError("socket")),
        mock.patch("time.sleep", side_effect=AssertionError("real sleep")),
    ):
        yield


class Runner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, turn):
        self.calls.append(turn.message_id)
        return {"stop_reason": "end_turn"}


class Scripted:
    def __init__(self, *actions: str) -> None:
        self.actions = list(actions)
        self.calls = 0

    def __call__(self, turn):
        self.calls += 1
        return self.actions.pop(0) if len(self.actions) > 1 else self.actions[0]


def _path(tmp_path: Path) -> Path:
    return tmp_path / "outbox.json"


def _box(clock, tmp_path, runner=None, gate=None, logs=None, **kw) -> Outbox:
    kw.setdefault("sign_outbound", lambda turn: f"{turn.sender}: {turn.body}")
    return Outbox(
        runner or Runner(),
        busy_wait_s=120,
        now=clock,
        presence_gate=gate,
        state_path=_path(tmp_path),
        on_store_log=None if logs is None else logs.append,
        **kw,
    )


def _enqueue(box: Outbox, mid="m1", body="oi", outbound=None):
    return box.enqueue(mid, "s", body, outbound or f"agent-a: {body}")


# --- roundtrip / restart ---------------------------------------------------------------------


def test_roundtrip_pending_survives_restart(tmp_path: Path) -> None:
    clock, runner = Clock(), Runner()
    first = _box(clock, tmp_path, runner)
    t = _enqueue(first)
    assert t.state == q.QUEUED
    assert _path(tmp_path).is_file()

    second = _box(clock, tmp_path, runner)
    assert [x.message_id for x in second._pending] == ["m1"]
    loaded = second._pending[0]
    assert (loaded.body, loaded.state) == ("oi", q.QUEUED)
    assert loaded.outbound_text == ""  # signatures are not persisted; re-sign on send
    assert loaded.enqueued_at == t.enqueued_at
    assert second.next_due_at() is None
    signed = []
    second._sign_outbound = lambda turn: signed.append(turn.message_id) or f"signed:{turn.body}"
    second.pump_once()
    assert runner.calls == ["m1"] and signed == ["m1"]
    assert loaded.state == q.DELIVERED


def test_restart_mid_backoff_restores_remaining_and_does_not_send_early(tmp_path: Path) -> None:
    clock, wall, runner, gate = Clock(), Clock(t=9_000.0), Runner(), Scripted("deferred_busy", "wake")
    first = _box(clock, tmp_path, runner, gate, wall=wall)
    t = _enqueue(first)
    first.pump_once()
    assert (t.state, t.attempts, t.next_attempt_at) == (q.DEFERRED, 1, 1030.0)
    assert first.next_due_at() == 1030.0
    assert runner.calls == []
    clock.t = 1010.0  # 20 s remaining; checkpoint as a crash mid-backoff would
    first._persist()
    # New monotonic epoch (now < saved_at): remaining 20 s is applied to the new clock.
    # Frozen wall (same as save) isolates this from time.time() jitter; wall elapsed is tested separately.
    reboot = Clock(t=5.0)
    second = _box(reboot, tmp_path, runner, gate, wall=wall)
    assert len(second._pending) == 1
    loaded = second._pending[0]
    assert (loaded.state, loaded.attempts) == (q.DEFERRED, 1)
    assert second.next_due_at() == 25.0
    reboot.t = 24.9
    second.pump_once()
    assert runner.calls == []
    reboot.t = 25.0
    second.pump_once()
    assert runner.calls == ["m1"]
    assert loaded.state == q.DELIVERED


def test_terminal_ids_idempotent_after_restart(tmp_path: Path) -> None:
    clock, runner = Clock(), Runner()
    first = _box(clock, tmp_path, runner)
    _enqueue(first, "delivered", body="oi")
    first.pump_once()

    expired_gate = Scripted("deferred_busy")
    box = _box(clock, tmp_path, runner, expired_gate, max_deferred_attempts=1)
    box.enqueue("expired", "s", "exp", "agent-a: exp")
    box.pump_once()
    assert box._completed["expired"].state == q.DEFERRED_EXPIRED

    box2 = _box(clock, tmp_path, runner, Scripted("deferred_absent"))
    box2.enqueue("absent", "s", "abs", "agent-a: abs")
    box2.pump_once()
    assert box2._completed["absent"].state == q.DEFERRED_ABSENT

    reboot_runner = Runner()
    reboot = _box(Clock(), tmp_path, reboot_runner)
    assert reboot._pending == []
    got = {
        mid: reboot.enqueue(mid, "s", body, f"agent-a: {body}")
        for mid, body in (("delivered", "oi"), ("expired", "exp"), ("absent", "abs"))
    }
    assert got["delivered"].state == q.DELIVERED
    assert got["expired"].state == q.DEFERRED_EXPIRED
    assert got["absent"].state == q.DEFERRED_ABSENT
    reboot.drain()
    assert reboot_runner.calls == []


def test_enqueue_idempotent_same_id_and_conflict(tmp_path: Path) -> None:
    clock = Clock()
    box = _box(clock, tmp_path)
    a = _enqueue(box, "m1")
    b = _enqueue(box, "m1")
    assert a is b
    assert len(box._pending) == 1
    with pytest.raises(ValueError, match="conflicting_message_id"):
        box.enqueue("m1", "s", "outra", "agent-a: outra")

    box.pump_once()
    reboot = _box(Clock(), tmp_path)
    again = reboot.enqueue("m1", "s", "oi", "agent-a: oi")
    assert again.state == q.DELIVERED
    with pytest.raises(ValueError, match="conflicting_message_id"):
        reboot.enqueue("m1", "s", "outra", "agent-a: outra")


def test_in_flight_at_restart_is_not_resent(tmp_path: Path) -> None:
    clock = Clock()
    # Synthetic checkpoint: a crash mid-dispatch leaves in_flight on disk.
    rec = {
        "message_id": "m-fly",
        "session_id": "s",
        "body": "oi",
        "outbound_text": "agent-a: oi",
        "sender": "agent-a",
        "state": q.IN_FLIGHT,
        "attempts": 0,
        "enqueued_at": 0.0,
        "next_attempt_at": None,
        "started_at": 1.0,
        "deadline": 601.0,
    }
    QueueStore(_path(tmp_path), now=clock).save(pending=[], completed=[], in_flight=rec, clock_now=clock())
    runner = Runner()
    box = _box(clock, tmp_path, runner)
    assert box._in_flight is None
    assert box._pending == []
    held = box._completed["m-fly"]
    assert held.state == q.TIMED_OUT
    assert "in_flight_at_restart" in (held.reason or "")
    box.drain()
    assert runner.calls == []
    again = box.enqueue("m-fly", "s", "oi", "agent-a: oi")
    assert again.state == q.TIMED_OUT


# --- corrupt / leftover tmp / permissions ----------------------------------------------------


def test_corrupt_file_is_renamed_not_deleted_and_queue_starts_empty(tmp_path: Path) -> None:
    clock = Clock(t=1763130000.0)
    dest = _path(tmp_path)
    dest.write_text("{not json", encoding="utf-8")
    logs: list[str] = []
    box = _box(clock, tmp_path, logs=logs)
    assert box._pending == []
    assert box._completed == {}
    assert not dest.exists()
    quarantined = Path(str(dest) + ".corrupt-1763130000")
    assert quarantined.is_file()
    assert quarantined.read_text(encoding="utf-8") == "{not json"
    assert logs and "outbox_state_corrupt" in logs[0]
    assert "queue_state_invalid_json" in logs[0]


def test_unknown_schema_version_is_quarantined(tmp_path: Path) -> None:
    clock = Clock(t=42)
    dest = _path(tmp_path)
    dest.write_text(json.dumps({"v": 99, "saved_at": 0, "pending": [], "completed": []}), encoding="utf-8")
    logs: list[str] = []
    box = _box(clock, tmp_path, logs=logs)
    assert box._pending == []
    assert Path(str(dest) + ".corrupt-42").is_file()
    assert "queue_state_schema_invalid" in logs[0]


def test_orphan_state_tmps_older_than_current_are_removed(tmp_path: Path) -> None:
    clock, runner = Clock(), Runner()
    first = _box(clock, tmp_path, runner)
    _enqueue(first, "keep")
    dest = _path(tmp_path)
    leftover = dest.parent / f".{dest.name}.interrupted.tmp"
    leftover.write_text("PARTIAL", encoding="utf-8")
    # mtime older than the current state file
    os.utime(leftover, (dest.stat().st_mtime - 10, dest.stat().st_mtime - 10))
    stray = dest.parent / "random.tmp"
    stray.write_text("nope", encoding="utf-8")
    link = dest.parent / f".{dest.name}.symlink.tmp"
    link.symlink_to(leftover)
    newer = dest.parent / f".{dest.name}.newer.tmp"
    newer.write_text("INPROGRESS", encoding="utf-8")
    os.utime(newer, (dest.stat().st_mtime + 10, dest.stat().st_mtime + 10))

    assert is_state_tmp(leftover, dest) and is_state_tmp(newer, dest)
    assert not is_state_tmp(stray, dest)

    second = _box(clock, tmp_path, runner)
    assert [t.message_id for t in second._pending] == ["keep"]
    assert not leftover.exists()  # exact-pattern leftover older than dest is unlinked
    assert stray.is_file() and stray.read_text(encoding="utf-8") == "nope"
    assert link.is_symlink()  # non-regular is left alone
    assert newer.is_file() and newer.read_text(encoding="utf-8") == "INPROGRESS"

    # dest missing: matching leftovers are stale and cleaned; unmatched stays
    dest.unlink()
    leftover.write_text("PARTIAL", encoding="utf-8")
    third = _box(Clock(), tmp_path, Runner())
    assert third._pending == []
    assert not leftover.exists()
    assert stray.is_file()


def test_state_and_lock_are_mode_0600(tmp_path: Path) -> None:
    box = _box(Clock(), tmp_path)
    _enqueue(box)
    dest = _path(tmp_path)
    lock = Path(str(dest) + ".lock")
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert lock.is_file()
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_secret_keys_never_appear_in_state_file(tmp_path: Path) -> None:
    box = _box(Clock(), tmp_path)
    signed = "agent-a: oi\n[msgsig v=1 mac=abc123deadbeef]"
    box.enqueue("m1", "s", "oi", signed)
    raw = _path(tmp_path).read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["v"] == QUEUE_STATE_VERSION
    blob = json.dumps(data)
    for secret in ("hmac_key", "hmac_key_file", "token", "api_key", "password", "authorization", "cookie"):
        assert secret not in blob
    # unsigned body only; signature / outbound_text stay out of the file
    rec = data["pending"][0]
    assert rec["body"] == "oi"
    assert "outbound_text" not in rec
    assert "mac=" not in blob
    assert "msgsig" not in blob
    assert "channel-sig" not in blob
    assert "mac" not in data
    assert "key" not in data
    assert "token" not in rec


def test_tampered_secret_field_is_quarantined(tmp_path: Path) -> None:
    clock = Clock(t=7)
    dest = _path(tmp_path)
    payload = {
        "v": 1,
        "saved_at": 0,
        "pending": [
            {"message_id": "m1", "state": "queued", "body": "oi", "token": "sekrit"},
        ],
        "completed": [],
        "in_flight": None,
    }
    dest.write_text(json.dumps(payload), encoding="utf-8")
    logs: list[str] = []
    box = _box(clock, tmp_path, logs=logs)
    assert box._pending == []
    assert Path(str(dest) + ".corrupt-7").is_file()
    assert "queue_state_schema_invalid" in logs[0]


# --- no config = legacy ----------------------------------------------------------------------


def test_without_state_path_behaviour_is_memory_only(tmp_path: Path) -> None:
    clock, runner = Clock(), Runner()
    box = Outbox(runner, busy_wait_s=120, now=clock)
    t = box.enqueue("m1", "s", "oi", "agent-a: oi")
    box.pump_once()
    assert t.state == q.DELIVERED
    assert list(tmp_path.iterdir()) == []
    # Legacy: after delivery, the same id can be enqueued again in this process.
    again = box.enqueue("m1", "s", "oi", "agent-a: oi")
    assert again is not t
    assert again.state == q.QUEUED
    # A new Outbox without a path starts empty (nothing to load).
    other = Outbox(Runner(), busy_wait_s=120, now=Clock())
    assert other._pending == []
    assert other.next_due_at() is None


def test_parse_queue_config_and_load_path(tmp_path: Path) -> None:
    assert parse_queue_config_text("") is None
    assert parse_queue_config_text("[channel_presence]\nmax_age_s = 120\n") is None
    assert parse_queue_config_text("[channel_queue]\n") is None
    assert parse_queue_config_text('[channel_queue]\nstate_path = ""\n') is None
    raw = parse_queue_config_text('[channel_queue]\nstate_path = "~/outbox.json"\n')
    assert raw == os.path.expanduser("~/outbox.json")
    cfg = tmp_path / "cfg.toml"
    cfg.write_text('[channel_queue]\nstate_path = "/var/tmp/q.json"\n', encoding="utf-8")
    assert load_queue_state_path(cfg) == "/var/tmp/q.json"
    assert load_queue_state_path(tmp_path / "missing.toml") is None
    # example configs stay commented (memory-only) so copying them does not enable persist
    example = (ROOT / "examples" / "config.example.toml").read_text(encoding="utf-8")
    assert parse_queue_config_text(example) is None
    deployment = (ROOT / "config" / "example.toml").read_text(encoding="utf-8")
    assert parse_queue_config_text(deployment) is None


def test_same_clock_restart_keeps_absolute_due(tmp_path: Path) -> None:
    clock, runner, gate = Clock(), Runner(), Scripted("deferred_busy")
    first = _box(clock, tmp_path, runner, gate)
    _enqueue(first)
    first.pump_once()
    clock.t = 1010.0
    second = _box(clock, tmp_path, runner, gate)
    assert second.next_due_at() == 1030.0


def test_clock_reset_subtracts_wall_elapsed(tmp_path: Path) -> None:
    queue_clock, wall, runner, gate = Clock(), Clock(t=10_000.0), Runner(), Scripted("deferred_busy", "wake")
    first = _box(queue_clock, tmp_path, runner, gate, wall=wall)
    _enqueue(first)
    first.pump_once()
    assert first.next_due_at() == 1030.0
    wall.t = 10_010.0  # 10 s of real time passed; monotonic will reset
    reboot_q, reboot_wall = Clock(t=0.0), Clock(t=10_010.0)
    second = _box(reboot_q, tmp_path, runner, gate, wall=reboot_wall)
    assert second.next_due_at() == 20.0
    reboot_q.t = 19.9
    second.pump_once()
    assert runner.calls == []
    reboot_q.t = 20.0
    second.pump_once()
    assert runner.calls == ["m1"]


def test_completed_is_slim_and_two_thousand_messages_stay_under_cap(tmp_path: Path) -> None:
    clock, runner = Clock(), Runner()
    box = _box(clock, tmp_path, runner, max_outbox=8)
    body = "y" * 1200
    for i in range(2001):
        box.enqueue(f"m{i}", "s", body, "agent-a: " + body)
        box.pump_once()
        clock.t += 1
    dest = _path(tmp_path)
    size = dest.stat().st_size
    assert size < 1_048_576
    data = json.loads(dest.read_text(encoding="utf-8"))
    assert all("body" not in c and "outbound_text" not in c for c in data["completed"])
    assert all(set(c) <= {"message_id", "state", "settled_at", "body_sha256",
                           *()} or "message_id" in c for c in data["completed"])
    sample = data["completed"][0]
    assert set(sample) == {"message_id", "state", "settled_at", "body_sha256"}
    assert sample["state"] == q.DELIVERED
    assert len(sample["body_sha256"]) == 64
    # cap keeps the newest 1024 ids; the first ones were trimmed
    ids = {c["message_id"] for c in data["completed"]}
    assert "m0" not in ids and "m2000" in ids
    assert box.enqueue("m2000", "s", body, "x").state == q.DELIVERED
    with pytest.raises(ValueError, match="conflicting_message_id"):
        box.enqueue("m2000", "s", "other", "x")


def test_save_error_does_not_wedge_the_in_memory_queue(tmp_path: Path) -> None:
    logs: list[str] = []
    clock, runner = Clock(), Runner()
    box = _box(clock, tmp_path, runner, logs=logs)
    _enqueue(box, "ok")
    # next persist cannot replace the file: parent is temporarily not writable via a raising hook
    def boom(*_a, **_k):
        raise OSError("disk_full")

    box._store.save = boom  # type: ignore[method-assign]
    t = _enqueue(box, "still-in-memory", body="two")
    assert t.state == q.QUEUED
    assert [x.message_id for x in box._pending] == ["ok", "still-in-memory"]
    assert any("outbox_state_save_failed" in line for line in logs)
    # memory continues to work
    box.pump_once()
    assert runner.calls == ["ok"]


def test_expired_deadline_after_monotonic_reset_is_floored_to_backoff_base(tmp_path: Path) -> None:
    queue_clock, wall, runner, gate = Clock(), Clock(t=10_000.0), Runner(), Scripted("deferred_busy", "wake")
    first = _box(queue_clock, tmp_path, runner, gate, wall=wall, backoff=lambda _a: 30)
    _enqueue(first)
    first.pump_once()
    assert first.next_due_at() == 1030.0
    wall.t = 10_000.0 + 120.0  # backoff fully elapsed during downtime
    reboot_q, reboot_wall = Clock(t=0.0), Clock(t=wall.t)
    second = _box(reboot_q, tmp_path, runner, gate, wall=reboot_wall, backoff=lambda _a: 30)
    # not due immediately; floored to now + backoff_base
    assert second.next_due_at() == 30.0
    second.pump_once()
    assert runner.calls == []
    reboot_q.t = 30.0
    second.pump_once()
    assert runner.calls == ["m1"]


def test_empty_outbound_after_restart_fails_closed_and_never_hits_runner(tmp_path: Path) -> None:
    clock, runner = Clock(), Runner()
    first = _box(clock, tmp_path, runner, sign_outbound=None)
    _enqueue(first, "m1")
    # Reload without a hook: persisted outbound_text is empty → fail closed, no send.
    second = _box(clock, tmp_path, runner, sign_outbound=None)
    turn = second.pump_once()
    assert turn is not None
    assert (turn.state, turn.reason) == (q.FAILED, "outbound_sign_missing")
    assert runner.calls == []

    def empty(_turn):
        return ""

    sub = tmp_path / "emptyhook"
    sub.mkdir()
    clock2, runner2 = Clock(), Runner()
    first2 = _box(clock2, sub, runner2)
    _enqueue(first2, "m2")
    third = _box(clock2, sub, runner2, sign_outbound=empty)
    turn = third.pump_once()
    assert (turn.state, turn.reason) == (q.FAILED, "outbound_text_empty")
    assert runner2.calls == []

    def boom(_turn):
        raise RuntimeError("no_key")

    sub2 = tmp_path / "boom"
    sub2.mkdir()
    fourth = _box(Clock(), sub2, Runner(), sign_outbound=boom)
    _enqueue(fourth, "m3")
    # first pump already has enqueue outbound, but hook runs and raises
    turn = fourth.pump_once()
    assert turn.state == q.FAILED
    assert turn.reason == "outbound_sign_failed:RuntimeError"


def test_restart_after_busy_resigns_with_session_build_outbound(tmp_path: Path) -> None:
    """End-to-end: defer on busy, reboot, runner gets a non-empty HMAC-valid prompt."""
    key_path = tmp_path / "hmac.key"
    generate_key_file(key_path)
    cfg = BridgeConfig(
        socket_path=str(tmp_path / "x.sock"),
        session_id="sess-example-0001",
        auth_mode="hmac",
        hmac_key_file=str(key_path),
        state_dir=str(tmp_path / "state"),
    ).validate()
    session = AcpSession(cfg)
    session._hmac_key = load_key(key_path)  # noqa: SLF001

    def sign(turn):
        return session.build_outbound(turn.message_id, turn.body, turn.sender)

    seen: list[str] = []

    class Capturing:
        def __call__(self, turn):
            seen.append(turn.outbound_text)
            return {"stop_reason": "end_turn"}

    clock, wall, runner, gate = Clock(), Clock(t=9_000.0), Capturing(), Scripted("deferred_busy", "wake")
    first = _box(clock, tmp_path, runner, gate, wall=wall, sign_outbound=sign)
    first.enqueue("id_deadbeefcafe01", "sess-example-0001", "hello body", "", sender="agent-a")
    first.pump_once()
    assert first._pending[0].state == q.DEFERRED
    assert seen == []

    clock.t = 1010.0
    first._persist()
    reboot = Clock(t=5.0)
    second = _box(reboot, tmp_path, runner, gate, wall=wall, sign_outbound=sign)
    assert second._pending[0].outbound_text == ""
    reboot.t = second.next_due_at()
    second.pump_once()
    assert seen and seen[0]
    assert seen[0].startswith("agent-a: hello body")
    assert "[msgsig " in seen[0] and "mac=" in seen[0]
    check = verify_text(load_key(key_path), seen[0], max_age_s=None)
    assert check.valid, check.reason
    assert second._pending == []
    assert second._completed["id_deadbeefcafe01"].state == q.DELIVERED


def test_daemon_wires_sign_outbound_to_session_build_outbound(tmp_path: Path) -> None:
    key_path = tmp_path / "hmac.key"
    generate_key_file(key_path)
    cfg = BridgeConfig(
        socket_path=str(tmp_path / "x.sock"),
        session_id="sess-example-0001",
        auth_mode="hmac",
        hmac_key_file=str(key_path),
        state_dir=str(tmp_path / "state"),
        live_send=False,
    ).validate()
    session = AcpSession(cfg)
    session._hmac_key = load_key(key_path)  # noqa: SLF001
    daemon = Daemon(cfg, session=session)
    try:
        assert daemon.outbox._sign_outbound == daemon._sign_outbound
        turn = q.Turn(
            message_id="id_deadbeefcafe01",
            session_id=cfg.session_id,
            body="ping",
            outbound_text="",
            enqueued_at=0.0,
            sender="agent-a",
        )
        text = daemon.outbox._sign_outbound(turn)
        assert text and "agent-a: ping" in text and "[msgsig " in text
        check = verify_text(load_key(key_path), text, max_age_s=None)
        assert check.valid, check.reason
        assert daemon.outbox._sign_outbound.__func__ is Daemon._sign_outbound
    finally:
        daemon.close()
