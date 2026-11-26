"""P3 cleanup (#7, #8, #9, #10, #12, #15, #16): replay ledger and presence edge cases."""
from __future__ import annotations

import inspect
import json
import math
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import presence_nonces as pn
from firefly_bridge import speaker as sp
from tests.hmac_fixtures import SIG_TS, make_keyring, signed_body

NOW = float(SIG_TS)
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def channel(tmp_path):
    sp.use_config(ROOT / "examples/config.example.toml")
    ring = make_keyring(tmp_path)
    store = tmp_path / "state" / "nonces.json"
    store.parent.mkdir(mode=0o700)
    base = dict(
        target="peerb", own_aliases=["peerb"], roster=["agent-a", "agent-b"], now=NOW,
        sources=[lambda n: pr.PresenceRecord(n, NOW, "idle")],
        cfg=pr.PresenceConfig(terminals={"peerb": str(tmp_path / "hb.json")}),
        keyring=ring["ring"], nonce_store=store,
    )
    yield ring, base, store
    sp.use_config(None)


def _at(base, now, **kw):
    return dict(base, now=now, sources=[lambda n: pr.PresenceRecord(n, now, "idle")], **kw)


# --- #7 deeply nested JSON is nonce_store_corrupt, not RecursionError --------------------------

def test_deeply_nested_ledger_is_corrupt_not_recursion_error(channel):
    _, base, store = channel
    store.write_text("[" * 200_000 + "]" * 200_000)
    store.chmod(0o600)
    with pytest.raises(pn.NonceStoreError, match="^nonce_store_corrupt$"):
        with pn.nonce_transaction(store, NOW, write=False):
            pass
    ring = channel[0]
    d = pr.wake_decision("agent-a", **dict(base, body=signed_body(ring, "agent-a"), claim=True))
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "nonce_store_error")


# --- #8 non-finite receive time is a decision, not an exception --------------------------------

@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_now_is_gated_invalid_receive_time(channel, bad):
    ring, base, store = channel
    d = pr.wake_decision("agent-a", **dict(base, now=bad, body=signed_body(ring, "agent-a")))
    assert (d.action, d.reason, d.presence) == (sp.GATED_NON_VIP, "invalid_receive_time", "")
    assert not store.exists()


# --- #9 a pruned grant is not a wake again after a backward clock step --------------------------

@pytest.mark.parametrize("claim_last", [True, False])
def test_backward_clock_step_after_prune_does_not_replay(channel, claim_last):
    ring, base, store = channel
    body = signed_body(ring, "agent-a")
    assert pr.wake_decision("agent-a", **_at(base, NOW, body=body, claim=True)).action == sp.WAKE
    # much later: an unrelated claim prunes the row
    later = NOW + 1300
    other = signed_body(ring, "agent-b", ts=int(later))
    assert pr.wake_decision("agent-b", **_at(base, later, body=other, claim=True)).action == sp.WAKE
    saved = json.loads(store.read_text())
    assert saved["watermark"] == SIG_TS + sp.SIG_MAX_SKEW_S
    assert all(not k.startswith("agent\n") for k in saved["nonces"])
    # the clock steps back to NOW: the same body must not wake again
    d = pr.wake_decision("agent-a", **_at(base, NOW, body=body, claim=claim_last))
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "stale")


def test_watermark_never_decreases_and_is_validated(channel):
    _, _, store = channel
    with pn.nonce_transaction(store, NOW) as rec:
        rec.update(a=NOW + 10, b=NOW + 20)
    with pn.nonce_transaction(store, NOW + 15) as rec:
        assert rec.watermark == NOW + 10 and dict(rec) == {"b": NOW + 20}
    with pn.nonce_transaction(store, NOW) as rec:  # clock went back: watermark stays
        assert rec.watermark == NOW + 10 and rec.forgotten("a", NOW + 10)
        assert not rec.forgotten("b", NOW + 20) and not rec.forgotten("c", NOW + 11)
    for bad in ('"x"', "true", "NaN", "Infinity"):
        store.write_text('{"v": 1, "nonces": {}, "watermark": ' + bad + '}')
        with pytest.raises(pn.NonceStoreError, match="^nonce_store_corrupt$"):
            with pn.nonce_transaction(store, NOW, write=False):
                pass


def test_old_ledger_without_watermark_still_loads(channel):
    _, _, store = channel
    store.write_text(json.dumps({"v": 1, "nonces": {"k": NOW + 5}}))
    store.chmod(0o600)
    with pn.nonce_transaction(store, NOW, write=False) as rec:
        assert dict(rec) == {"k": NOW + 5} and rec.watermark == -math.inf


# --- #10 a symlinked ledger directory is refused ------------------------------------------------

def test_symlinked_ledger_directory_is_refused(channel, tmp_path):
    ring, base, _ = channel
    real = tmp_path / "real-state"
    real.mkdir(mode=0o700)
    link = tmp_path / "linked-state"
    link.symlink_to(real, target_is_directory=True)
    d = pr.wake_decision(
        "agent-a", **dict(base, body=signed_body(ring, "agent-a"), nonce_store=link / "n.json",
                          claim=True)
    )
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "nonce_store_error")
    assert list(real.iterdir()) == []


# --- #12 requires-python matches the code (datetime.UTC, tomllib) ------------------------------

def test_requires_python_is_311_or_newer():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert meta["requires-python"] == ">=3.11"
    assert "Programming Language :: Python :: 3.9" not in meta["classifiers"]


# --- #16 wake_decision is a dry run unless the caller claims ------------------------------------

def test_wake_decision_defaults_to_dry_run(channel):
    assert inspect.signature(pr.wake_decision).parameters["claim"].default is False
    ring, base, store = channel
    body = signed_body(ring, "agent-a")
    for _ in range(2):
        assert pr.wake_decision("agent-a", **dict(base, body=body)).action == sp.WAKE
    assert not store.exists()


# --- #15 knock --claim is not labelled dry-run -------------------------------------------------

def _knock(channel, body, *extra):
    ring, _, store = channel
    root = store.parent
    hb = root / "hb.json"
    hb.write_text(json.dumps(dict(name="peerb", ts=NOW, state="idle")))
    cfg = root / "config.toml"
    cfg.write_text(
        '[channel_roster]\nvip = ["agent-a"]\n'
        f'[channel_keyring]\ndir = "{ring["dir"]}"\n'
        f'[channel_presence.terminals]\nPeerb = "{hb}"\n'
    )
    log = root / "log.jsonl"
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts/channel-knock"), "--presence", "--from", "agent-a",
         "--config", str(cfg), "--now", str(NOW), "--body", body, "--nonce-store", str(store),
         "--presence-log", str(log), *extra],
        capture_output=True, text=True, cwd=ROOT, check=True,
        env=dict(os.environ, PYTHONPATH=str(ROOT)),
    ).stdout
    return out, json.loads(log.read_text().splitlines()[-1])


def test_knock_claim_output_matches_the_mode(channel):
    ring = channel[0]
    out, rec = _knock(channel, signed_body(ring, "agent-a"))
    assert "presence (dry-run): action=wake " in out and rec["mode"] == "dry_run"
    out, rec = _knock(channel, signed_body(ring, "agent-a"), "--claim")
    assert "presence (claim): action=wake " in out and "dry-run" not in out.split("\n")[0]
    assert rec["mode"] == "claim" and rec["ledger"] == "claimed"


