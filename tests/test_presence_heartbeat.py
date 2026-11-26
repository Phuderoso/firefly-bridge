"""Heartbeat writer hooks: injectable clock only (no sleep), no process, no network.

The terminal declares busy/idle/absent from a local turn marker. presence() still reads
only the .json heartbeat; missing or stale files stay unknown (not absent). After leave,
tick/begin/end refuse to resurrect absent; only start_session reopens.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import presence_heartbeat as hb
from firefly_bridge import speaker as sp

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_763_130_000.0
NAME = "peerb"


class Clock:
    def __init__(self, t: float = NOW) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def _isolated():
    sp.use_config(ROOT / "examples" / "config.example.toml")
    hb._before_tick = None
    with (
        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("spawn")),
        mock.patch.object(socket, "socket", side_effect=AssertionError("socket")),
        mock.patch("time.sleep", side_effect=AssertionError("real sleep")),
    ):
        yield
    hb._before_tick = None
    sp.use_config(None)


def _cfg(path: Path) -> pr.PresenceConfig:
    return pr.PresenceConfig(max_age_s=120, future_skew_s=30, terminals={"peerb": str(path)})


def _presence(tmp_path: Path, now: float) -> pr.Presence:
    path = hb.heartbeat_path(tmp_path, NAME)
    cfg = _cfg(path)
    return pr.presence(NAME, now, [pr.state_file_source(cfg)], cfg)


def _json_and_maybe_lock(tmp_path: Path) -> None:
    names = sorted(p.name for p in tmp_path.iterdir())
    assert "peerb.json" in names
    assert not any(n.endswith(".tmp") or n.endswith(".turn") for n in names)


def test_start_session_clears_orphan_marker_and_declares_idle(tmp_path: Path) -> None:
    hb.write_turn_marker(tmp_path, NAME, now=NOW - 9_000, task="leftover")
    path = hb.start_session(tmp_path, NAME, now=NOW)
    assert path == tmp_path / "peerb.json"
    assert not hb.turn_marker_path(tmp_path, NAME).exists()
    assert _presence(tmp_path, NOW + 1).state == pr.IDLE


def test_begin_tick_end_roundtrip(tmp_path: Path) -> None:
    clock = Clock()
    hb.start_session(tmp_path, NAME, now=clock())
    busy = hb.begin_turn(tmp_path, NAME, now=clock(), task="draft notes")
    marker = hb.turn_marker_path(tmp_path, NAME)
    assert json.loads(busy.read_text(encoding="utf-8"))["state"] == pr.BUSY
    assert marker.stat().st_mode & 0o777 == 0o600
    assert _presence(tmp_path, clock()).state == pr.BUSY
    assert _presence(tmp_path, clock()).task == "draft notes"

    clock.t = NOW + 30
    ticked = hb.tick_heartbeat(tmp_path, NAME, now=clock())
    obj = json.loads(ticked.read_text(encoding="utf-8"))
    assert obj == {"name": NAME, "ts": clock.t, "state": pr.BUSY, "task": "draft notes", "v": 1}
    assert _presence(tmp_path, clock.t + 4).state == pr.BUSY

    clock.t = NOW + 60
    hb.end_turn(tmp_path, NAME, now=clock())
    assert not marker.exists()
    assert _presence(tmp_path, clock()).state == pr.IDLE
    _json_and_maybe_lock(tmp_path)


def test_tick_without_marker_is_idle(tmp_path: Path) -> None:
    path = hb.tick_heartbeat(tmp_path, NAME, now=NOW)
    assert json.loads(path.read_text(encoding="utf-8"))["state"] == pr.IDLE
    assert _presence(tmp_path, NOW + 1).state == pr.IDLE


def test_leave_writes_fresh_absent_and_tick_does_not_resurrect(tmp_path: Path) -> None:
    hb.begin_turn(tmp_path, NAME, now=NOW, task="x")
    hb.leave(tmp_path, NAME, now=NOW + 5)
    assert not hb.turn_marker_path(tmp_path, NAME).exists()
    p = _presence(tmp_path, NOW + 6)
    assert (p.state, p.reason) == (pr.ABSENT, "fresh")
    with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
        hb.tick_heartbeat(tmp_path, NAME, now=NOW + 10)
    assert _presence(tmp_path, NOW + 11).state == pr.ABSENT
    # only start_session reopens
    hb.start_session(tmp_path, NAME, now=NOW + 20)
    assert _presence(tmp_path, NOW + 21).state == pr.IDLE


def test_stale_or_missing_is_unknown_not_absent(tmp_path: Path) -> None:
    cfg_missing = pr.PresenceConfig(max_age_s=120, terminals={"peerb": str(tmp_path / "peerb.json")})
    missing = pr.presence(NAME, NOW, [pr.state_file_source(cfg_missing)], cfg_missing)
    assert missing.state == pr.UNKNOWN

    hb.start_session(tmp_path, NAME, now=NOW)
    assert _presence(tmp_path, NOW + 120).state == pr.IDLE
    stale = _presence(tmp_path, NOW + 120.001)
    assert stale.state == pr.UNKNOWN
    assert stale.reason == "stale"


def test_future_skew_is_unknown(tmp_path: Path) -> None:
    hb.start_session(tmp_path, NAME, now=NOW + 30)
    assert _presence(tmp_path, NOW).state == pr.IDLE  # age == -30, within future_skew_s
    hb.start_session(tmp_path, NAME, now=NOW + 30.001)
    future = _presence(tmp_path, NOW)
    assert future.state == pr.UNKNOWN
    assert future.reason == "future_ts"


def test_corrupt_regular_marker_is_busy_when_heartbeat_is_missing(tmp_path: Path) -> None:
    (tmp_path / "peerb.turn").write_text("{not json", encoding="utf-8")
    assert hb.interpret_turn_marker(tmp_path, NAME) == (pr.BUSY, "")
    hb.tick_heartbeat(tmp_path, NAME, now=NOW)
    assert _presence(tmp_path, NOW + 1).state == pr.BUSY


def test_symlink_turn_is_refused_before_any_idle_or_busy_decision(tmp_path: Path) -> None:
    hb.start_session(tmp_path, NAME, now=NOW)
    real = tmp_path / "other.turn"
    real.write_text("x", encoding="utf-8")
    link = hb.turn_marker_path(tmp_path, NAME)
    os.symlink(real, link)
    assert hb.interpret_turn_marker(tmp_path, NAME, now=NOW) == (pr.IDLE, "")
    assert hb._inspect_turn_marker(tmp_path, NAME, now=NOW)[0] == hb.MARKER_UNTRUSTED
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 1)
    assert _presence(tmp_path, NOW + 2).state == pr.IDLE
    hb.clear_turn_marker(tmp_path, NAME)  # must not follow or unlink the target
    assert link.is_symlink() and real.exists()


def test_marker_write_is_atomic_and_modes_are_tight(tmp_path: Path) -> None:
    with mock.patch.object(hb.os, "replace", wraps=os.replace) as rep:
        hb.write_turn_marker(tmp_path, NAME, now=NOW, task="x")
    (src, dst), _ = rep.call_args
    assert Path(src).parent == tmp_path and Path(src).name.endswith(".tmp")
    assert Path(dst) == tmp_path / "peerb.turn"
    json_path = hb.write_heartbeat(tmp_path, NAME, pr.IDLE, now=NOW)
    assert json_path.stat().st_mode & 0o777 == 0o644
    assert (tmp_path / "peerb.turn").stat().st_mode & 0o777 == 0o600


def test_hooks_refuse_missing_dir_and_do_not_create_it(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(FileNotFoundError):
        hb.start_session(missing, NAME, now=NOW)
    assert not missing.exists()


def test_cli_uses_injected_clock(tmp_path: Path) -> None:
    assert hb.main(["start", "--dir", str(tmp_path), "--name", NAME], now=NOW) == 0
    assert hb.main(["begin", "--dir", str(tmp_path), "--name", NAME, "--task", "notes"], now=NOW + 1) == 0
    assert _presence(tmp_path, NOW + 2).task == "notes"
    assert hb.main(["tick", "--dir", str(tmp_path), "--name", NAME], now=NOW + 30) == 0
    assert json.loads((tmp_path / "peerb.json").read_text(encoding="utf-8"))["ts"] == NOW + 30
    assert hb.main(["end", "--dir", str(tmp_path), "--name", NAME], now=NOW + 40) == 0
    assert _presence(tmp_path, NOW + 41).state == pr.IDLE
    assert hb.main(["leave", "--dir", str(tmp_path), "--name", NAME], now=NOW + 50) == 0
    assert _presence(tmp_path, NOW + 51).state == pr.ABSENT
    with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
        hb.main(["tick", "--dir", str(tmp_path), "--name", NAME], now=NOW + 60)
    assert _presence(tmp_path, NOW + 61).state == pr.ABSENT


def test_writer_has_no_loop_process_or_tui() -> None:
    body = (ROOT / "firefly_bridge" / "presence_heartbeat.py").read_text(encoding="utf-8").split('"""', 2)[2]
    for bad in ("while ", "subprocess", "socket", "tmux", "launchctl", "sleep(", "Popen", "os.kill", "thread"):
        assert bad not in body, bad


# --- agent-a review: lock, leftover .turn, directory fsync ------------------------------------


def test_leave_interleaved_before_tick_lock_keeps_absent(tmp_path: Path) -> None:
    """A tick already underway (hook before the lock) must not overwrite a just-written absent."""
    hb.start_session(tmp_path, NAME, now=NOW)

    def _leave_first() -> None:
        hb.leave(tmp_path, NAME, now=NOW + 5)

    hb._before_tick = _leave_first
    with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
        hb.tick_heartbeat(tmp_path, NAME, now=NOW + 10)
    assert _presence(tmp_path, NOW + 11).state == pr.ABSENT
    with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
        hb.begin_turn(tmp_path, NAME, now=NOW + 12, task="nope")
    with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
        hb.end_turn(tmp_path, NAME, now=NOW + 13)
    with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
        hb.write_heartbeat(tmp_path, NAME, pr.IDLE, now=NOW + 14)
    assert _presence(tmp_path, NOW + 15).state == pr.ABSENT
    hb.start_session(tmp_path, NAME, now=NOW + 20)
    assert _presence(tmp_path, NOW + 21).state == pr.IDLE


def test_compare_before_replace_still_refuses_when_flock_unavailable(tmp_path: Path) -> None:
    hb.start_session(tmp_path, NAME, now=NOW)
    hb.leave(tmp_path, NAME, now=NOW + 1)
    with mock.patch.object(hb, "_try_flock", return_value=False):
        with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
            hb.tick_heartbeat(tmp_path, NAME, now=NOW + 2)
        with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
            hb.begin_turn(tmp_path, NAME, now=NOW + 3)
    assert _presence(tmp_path, NOW + 4).state == pr.ABSENT


def test_leave_writes_absent_even_if_turn_unlink_fails(tmp_path: Path) -> None:
    hb.begin_turn(tmp_path, NAME, now=NOW, task="x")
    marker = hb.turn_marker_path(tmp_path, NAME)
    assert marker.is_file()

    def _fail_turn(path) -> None:
        if Path(path) == marker:
            raise OSError("unlink_denied")
        os.unlink(path)

    with mock.patch.object(hb, "_unlink", side_effect=_fail_turn):
        with pytest.raises(OSError, match="unlink_denied"):
            hb.leave(tmp_path, NAME, now=NOW + 5)
    assert marker.is_file()  # leftover .turn
    assert _presence(tmp_path, NOW + 6).state == pr.ABSENT
    with mock.patch.object(hb, "interpret_turn_marker", side_effect=AssertionError("must not read .turn")):
        with pytest.raises(ValueError, match=hb.SESSION_CLOSED):
            hb.tick_heartbeat(tmp_path, NAME, now=NOW + 10)
    assert _presence(tmp_path, NOW + 11).state == pr.ABSENT
    assert marker.is_file()


def test_clear_turn_marker_propagates_unlink_errors(tmp_path: Path) -> None:
    hb.write_turn_marker(tmp_path, NAME, now=NOW, task="x")

    def _boom(path) -> None:
        raise OSError("busy")

    with mock.patch.object(hb, "_unlink", side_effect=_boom):
        with pytest.raises(OSError, match="busy"):
            hb.clear_turn_marker(tmp_path, NAME)
    assert hb.turn_marker_path(tmp_path, NAME).is_file()
    hb.clear_turn_marker(tmp_path, NAME)  # FileNotFound is not required; a real unlink works
    assert not hb.turn_marker_path(tmp_path, NAME).exists()
    hb.clear_turn_marker(tmp_path, NAME)  # missing is fine


def test_atomic_write_fsyncs_directory_after_replace(tmp_path: Path) -> None:
    events: list[str] = []
    real_replace = os.replace
    real_fsync = os.fsync

    def rec_replace(src, dst):
        events.append("replace")
        return real_replace(src, dst)

    def rec_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            events.append("dir_fsync")
        return real_fsync(fd)

    with (
        mock.patch.object(hb.os, "replace", side_effect=rec_replace),
        mock.patch.object(hb.os, "fsync", side_effect=rec_fsync),
    ):
        hb.write_heartbeat(tmp_path, NAME, pr.IDLE, now=NOW)
    assert "replace" in events and "dir_fsync" in events
    assert events.index("replace") < events.index("dir_fsync")


def test_directory_fsync_failure_is_best_effort(tmp_path: Path) -> None:
    real_fsync = os.fsync

    def flaky(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("no dir fsync")
        return real_fsync(fd)

    with mock.patch.object(hb.os, "fsync", side_effect=flaky):
        path = hb.write_heartbeat(tmp_path, NAME, pr.IDLE, now=NOW)
    assert path.is_file()
    assert json.loads(path.read_text(encoding="utf-8"))["state"] == pr.IDLE
    assert _presence(tmp_path, NOW + 1).state == pr.IDLE


# --- agent-a review: leftover .turn after end_turn must not resurrect busy --------------------


def _fail_only_turn(marker: Path):
    def _fail(path) -> None:
        if Path(path) == marker:
            raise OSError("unlink_denied")
        os.unlink(path)

    return _fail


def test_end_turn_writes_idle_even_if_turn_unlink_fails(tmp_path: Path) -> None:
    hb.begin_turn(tmp_path, NAME, now=NOW, task="x")
    marker = hb.turn_marker_path(tmp_path, NAME)
    assert marker.is_file()
    with mock.patch.object(hb, "_unlink", side_effect=_fail_only_turn(marker)):
        with pytest.raises(OSError, match="unlink_denied"):
            hb.end_turn(tmp_path, NAME, now=NOW + 5)
    assert marker.is_file()
    assert _presence(tmp_path, NOW + 6).state == pr.IDLE
    # leftover .turn is older than the idle heartbeat; tick must stay idle, not go busy
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 10)
    assert _presence(tmp_path, NOW + 11).state == pr.IDLE
    assert json.loads((tmp_path / "peerb.json").read_text(encoding="utf-8"))["task"] == ""
    assert marker.is_file()


def test_tick_ignores_turn_ts_not_newer_than_last_idle(tmp_path: Path) -> None:
    hb.start_session(tmp_path, NAME, now=NOW + 5)
    hb.write_turn_marker(tmp_path, NAME, now=NOW, task="stale")  # ts older than idle
    assert hb.interpret_turn_marker(tmp_path, NAME, idle_ts=NOW + 5) == (pr.IDLE, "")
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 10)
    assert _presence(tmp_path, NOW + 11).state == pr.IDLE
    # equal ts is also ignored (not strictly older)
    hb.write_turn_marker(tmp_path, NAME, now=NOW + 5, task="same")
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 12)
    assert _presence(tmp_path, NOW + 13).state == pr.IDLE


def test_tick_ignores_turn_mtime_older_than_idle_when_ts_is_missing(tmp_path: Path) -> None:
    hb.start_session(tmp_path, NAME, now=NOW)
    marker = hb.turn_marker_path(tmp_path, NAME)
    marker.write_text("{not json", encoding="utf-8")
    os.utime(marker, (NOW - 10, NOW - 10))
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 1)
    assert _presence(tmp_path, NOW + 2).state == pr.IDLE
    # a marker without ts but with mtime newer than idle still counts as busy
    os.utime(marker, (NOW + 10, NOW + 10))
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 3)
    assert _presence(tmp_path, NOW + 4).state == pr.BUSY


def test_tick_keeps_busy_when_turn_is_newer_than_last_idle(tmp_path: Path) -> None:
    hb.start_session(tmp_path, NAME, now=NOW)
    hb.write_turn_marker(tmp_path, NAME, now=NOW + 5, task="fresh")
    hb.tick_heartbeat(tmp_path, NAME, now=NOW + 6)
    p = _presence(tmp_path, NOW + 7)
    assert (p.state, p.task) == (pr.BUSY, "fresh")


# --- agent-a review: future skew, symlink, unreadable idle JSON -------------------------------


def test_future_turn_ts_beyond_skew_does_not_resurrect_busy(tmp_path: Path) -> None:
    skew = hb.DEFAULT_FUTURE_SKEW_S
    hb.start_session(tmp_path, NAME, now=NOW)
    hb.write_turn_marker(tmp_path, NAME, now=NOW + skew + 0.001, task="from the future")
    assert hb.interpret_turn_marker(tmp_path, NAME, now=NOW, future_skew_s=skew) == (pr.IDLE, "")
    assert hb._inspect_turn_marker(tmp_path, NAME, now=NOW, future_skew_s=skew)[0] == hb.MARKER_UNTRUSTED
    hb.tick_heartbeat(tmp_path, NAME, now=NOW, future_skew_s=skew)
    assert _presence(tmp_path, NOW + 1).state == pr.IDLE
    # exactly at the skew boundary the marker is still accepted (same as presence: age < -skew)
    hb.write_turn_marker(tmp_path, NAME, now=NOW + skew, task="edge")
    hb.tick_heartbeat(tmp_path, NAME, now=NOW, future_skew_s=skew)
    assert _presence(tmp_path, NOW + 1).state == pr.BUSY


def test_clock_going_backward_does_not_let_old_turn_revive_busy(tmp_path: Path) -> None:
    skew = hb.DEFAULT_FUTURE_SKEW_S
    hb.begin_turn(tmp_path, NAME, now=NOW, task="x")
    assert _presence(tmp_path, NOW + 1).state == pr.BUSY
    # reader clock jumped back past the skew: presence already fail-closes to unknown
    assert _presence(tmp_path, NOW - skew - 1).state == pr.UNKNOWN
    # tick at the same rewound clock must not rewrite busy (or invent idle)
    dest = hb.tick_heartbeat(tmp_path, NAME, now=NOW - skew - 1, future_skew_s=skew)
    assert dest == tmp_path / "peerb.json"
    obj = json.loads(dest.read_text(encoding="utf-8"))
    assert obj["state"] == pr.BUSY and obj["ts"] == NOW  # file left alone
    assert _presence(tmp_path, NOW - skew - 1).state == pr.UNKNOWN


def test_unreadable_idle_json_does_not_let_leftover_turn_become_busy(tmp_path: Path) -> None:
    hb.begin_turn(tmp_path, NAME, now=NOW, task="x")
    hb.write_heartbeat(tmp_path, NAME, pr.IDLE, now=NOW + 5)
    marker = hb.turn_marker_path(tmp_path, NAME)
    assert marker.is_file()
    # scramble the idle heartbeat; leftover .turn remains
    (tmp_path / "peerb.json").write_text("{not json", encoding="utf-8")
    assert _presence(tmp_path, NOW + 6).state == pr.UNKNOWN
    dest = hb.tick_heartbeat(tmp_path, NAME, now=NOW + 10)
    assert dest.read_text(encoding="utf-8") == "{not json"
    assert marker.is_file()
    assert _presence(tmp_path, NOW + 11).state == pr.UNKNOWN
