"""Presence wiring (dry-run): heartbeat stub, retry ownership, out-of-roster targets, knock --presence."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import socket
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import presence_heartbeat as hb
from firefly_bridge import speaker as sp
from tests.hmac_fixtures import keyring_config_lines, make_keyring, signed_body, signed_kwargs

ROOT = Path(__file__).resolve().parents[1]
KNOCK = ROOT / "scripts" / "channel-knock"
_loader = importlib.machinery.SourceFileLoader("channel_knock_presence", str(KNOCK))
_spec = importlib.util.spec_from_loader("channel_knock_presence", _loader)
knock = importlib.util.module_from_spec(_spec)
_loader.exec_module(knock)

OWNER = "owner"
ROSTER = ["agent-a", "agent-b", "agent-c", "agent-d", OWNER, "peerx"]
NOW = 1_763_130_000.0


@pytest.fixture(autouse=True)
def _aliases():
    sp.use_config(ROOT / "examples" / "config.example.toml")
    yield
    sp.use_config(None)


def _cfg_for(tmp_path: Path, **terms: str) -> pr.PresenceConfig:
    return pr.PresenceConfig(terminals={sp.norm_name(k): str(v) for k, v in terms.items()})


# --- heartbeat stub ---------------------------------------------------------------------------


@pytest.mark.parametrize("state,task", [("idle", ""), ("busy", "draft notes"), ("absent", "")])
def test_stub_file_is_read_back_by_presence(tmp_path: Path, state: str, task: str) -> None:
    path = hb.write_heartbeat(tmp_path, "peerb", state, now=NOW, task=task)
    assert path == tmp_path / "peerb.json"
    cfg = _cfg_for(tmp_path, peerb=path)
    p = pr.presence("peerb", NOW + 30, [pr.state_file_source(cfg)], cfg)
    assert p.state == state
    assert p.task == task


def test_stub_is_atomic_and_leaves_no_tmp(tmp_path: Path) -> None:
    hb.write_heartbeat(tmp_path, "peerb", "busy", now=NOW, task="x")
    hb.write_heartbeat(tmp_path, "peerb", "idle", now=NOW + 30)  # replace in place
    assert sorted(p.name for p in tmp_path.iterdir()) == ["peerb.json"]
    obj = json.loads((tmp_path / "peerb.json").read_text(encoding="utf-8"))
    assert obj == {"name": "peerb", "ts": NOW + 30, "state": "idle", "task": "", "v": 1}
    assert (tmp_path / "peerb.json").stat().st_mode & 0o777 == 0o644


def test_stub_replace_goes_through_os_replace(tmp_path: Path) -> None:
    with mock.patch.object(hb.os, "replace", wraps=os.replace) as rep:
        hb.write_heartbeat(tmp_path, "agent-b", "idle", now=NOW)
    (src, dst), _ = rep.call_args
    assert Path(src).parent == tmp_path and Path(src).name.endswith(".tmp")
    assert Path(dst) == tmp_path / "agent-b.json"


def test_stub_failure_cleans_tmp(tmp_path: Path) -> None:
    with mock.patch.object(hb.os, "replace", side_effect=OSError("boom")):
        with pytest.raises(OSError):
            hb.write_heartbeat(tmp_path, "peerb", "idle", now=NOW)
    assert list(tmp_path.iterdir()) == []


def test_stub_rejects_bad_input(tmp_path: Path) -> None:
    for kwargs in ({"name": "", "state": "idle"}, {"name": "peerb", "state": "sleeping"},
                   {"name": "peerb", "state": "idle", "task": "t"}, {"name": "/", "state": "idle"}):
        with pytest.raises(ValueError):
            hb.write_heartbeat(tmp_path, now=NOW, **kwargs)
    with pytest.raises(FileNotFoundError):
        hb.write_heartbeat(tmp_path / "missing", "peerb", "idle", now=NOW)
    assert hb.heartbeat_path(tmp_path, "../../etc/peerb").parent == tmp_path  # no traversal


def test_stub_heartbeat_goes_stale_after_max_age(tmp_path: Path) -> None:
    path = hb.write_heartbeat(tmp_path, "peerb", "idle", now=NOW)
    cfg = pr.PresenceConfig(max_age_s=120, terminals={"peerb": str(path)})
    src = [pr.state_file_source(cfg)]
    assert pr.presence("peerb", NOW + 4 * pr.HEARTBEAT_CADENCE_S, src, cfg).state == pr.IDLE
    assert pr.presence("peerb", NOW + 121, src, cfg).state == pr.UNKNOWN


def test_stub_has_no_loop_process_or_tui() -> None:
    body = (ROOT / "firefly_bridge" / "presence_heartbeat.py").read_text(encoding="utf-8").split('"""', 2)[2]
    for bad in ("while ", "subprocess", "socket", "tmux", "launchctl", "sleep(", "Popen", "os.kill", "thread"):
        assert bad not in body, bad


# --- decisions 4 & 5 ----------------------------------------------------------------------------


def _ring(tmp_path: Path) -> dict:
    return make_keyring(tmp_path)


def _decide(sender: str, target: str, state: str | None, ring: dict, **kw):
    def src(n):
        if state is None:
            return None
        return pr.record_from_mapping({"name": target, "ts": NOW - 5, "state": state})

    signed = kw.pop("signed", True)
    extra = signed_kwargs(ring, sender) if signed else {}
    extra.update(kw)
    return pr.wake_decision(sender, target=target, own_aliases=[target], roster=ROSTER, now=NOW,
                            sources=[src], **extra)


def test_retry_owner_is_queue_never_watcher(tmp_path: Path) -> None:
    ring = _ring(tmp_path)
    assert _decide("agent-a", "peerb", "busy", ring).retry_owner == pr.RETRY_OWNER_QUEUE
    assert _decide("agent-a", "peerb", None, ring).retry_owner == pr.RETRY_OWNER_QUEUE
    assert _decide("agent-a", "peerb", "absent", ring).retry_owner == pr.RETRY_OWNER_INBOX
    assert _decide("agent-a", "peerb", "idle", ring).retry_owner == ""
    assert _decide("guest", "peerb", "idle", ring, signed=False).retry_owner == ""
    assert "watcher" not in {pr.RETRY_OWNER_QUEUE, pr.RETRY_OWNER_INBOX}


def test_backoff_is_monotonic_and_capped() -> None:
    vals = [pr.deferred_backoff_s(n) for n in range(10)]
    assert vals[:3] == [30.0, 60.0, 120.0]
    assert vals == sorted(vals) and max(vals) == 600.0
    assert pr.deferred_backoff_s(-3) == 30.0


def test_target_outside_roster_has_presence_sender_still_gated(tmp_path: Path) -> None:
    ring = _ring(tmp_path)
    assert "peerb" not in ROSTER
    assert _decide("agent-a", "peerb", "idle", ring).action == sp.WAKE  # target presence, sender VIP
    assert _decide("agent-a", "peerb", "busy", ring).action == pr.DEFERRED_BUSY
    d = _decide("guest", "peerb", "idle", ring, signed=False)  # non-VIP sender: gate first, never presence
    assert (d.action, d.presence) == (sp.GATED_NON_VIP, "")


# --- channel-knock --presence (dry-run) ------------------------------------------------------


def _cfg_file(tmp_path: Path, hb_path: Path, ring: dict | None = None) -> Path:
    cfg = tmp_path / "config.toml"
    roster = (ROOT / "examples" / "config.example.toml").read_text(encoding="utf-8")
    roster = roster.split("[channel_presence]")[0]
    extra = keyring_config_lines(ring) if ring is not None else ""
    cfg.write_text(
        roster + extra + "\n[channel_presence]\nmax_age_s = 120\n[channel_presence.terminals]\n"
        f'peerb = "{hb_path}"\n',
        encoding="utf-8",
    )
    return cfg


def test_knock_without_presence_is_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    with mock.patch.object(knock, "_presence_module", side_effect=AssertionError("presence loaded")):
        assert knock.main([]) == 0
    expected = knock.intended_sequence(knock.DEFAULT_SOCK, knock.DEFAULT_SESSION, "oi peerb")
    assert capsys.readouterr().out == expected + "\nlive: not requested (default dry-run)\n"


@pytest.mark.parametrize(
    "state,task,sender,action",
    [
        ("idle", "", "agent-a", "wake"),
        ("busy", "notes", "agent-a", "deferred_busy"),
        ("busy", "notes", "ownerlogin", "deferred_busy"),  # owner does not override busy
        ("absent", "", "agent-b", "deferred_absent"),
        ("idle", "", "guest", "gated_non_vip"),
    ],
)
def test_knock_presence_prints_decision_only(tmp_path, capsys, state, task, sender, action) -> None:
    hb_path = hb.write_heartbeat(tmp_path, "peerb", state, now=NOW, task=task)
    ring = _ring(tmp_path)
    cfg = _cfg_file(tmp_path, hb_path, ring)
    log = tmp_path / "decisions.jsonl"
    argv = ["--presence", "--from", sender, "--config", str(cfg), "--now", str(NOW + 10),
            "--presence-log", str(log)]
    if sender != "guest":
        argv.extend(["--body", signed_body(ring, sender)])
    with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("spawn")), \
         mock.patch.object(socket, "socket", side_effect=AssertionError("socket")):
        rc = knock.main(argv)
    out = capsys.readouterr().out
    assert rc == 0
    assert f"presence (dry-run): action={action} " in out
    assert ("session/prompt" in out) == (action == "wake")  # sequence shown only, never executed
    assert "live: not requested" in out
    rec = json.loads(log.read_text(encoding="utf-8").strip())
    assert rec["action"] == action and rec["mode"] == "dry_run"


def test_knock_presence_stale_fails_closed(tmp_path, capsys) -> None:
    hb_path = hb.write_heartbeat(tmp_path, "peerb", "idle", now=NOW)
    ring = _ring(tmp_path)
    cfg = _cfg_file(tmp_path, hb_path, ring)
    body = signed_body(ring, "agent-a", ts=int(NOW + 999))  # fresh body, stale heartbeat
    assert knock.main(["--presence", "--from", "agent-a", "--body", body,
                       "--config", str(cfg), "--now", str(NOW + 999)]) == 0
    out = capsys.readouterr().out
    assert "action=deferred_unknown" in out and "reason=stale" in out


def test_knock_presence_refuses_live(tmp_path, capsys) -> None:
    assert knock.main(["--presence", "--live", "--from", "agent-a"]) == 2
    assert "presence_refused" in capsys.readouterr().err
