# ruff: noqa: F811  (pytest fixtures imported from test_canal_hmac)
"""Review of 965bc4b-on-e01edef (e9788d2): trusted_inbox / --wait / --mark-read in strict mode.

Offline: keys generated in tmp_path (fixture `ring`), gh is a fake, the clock is fake.
"""
from __future__ import annotations

import json
from pathlib import Path

from test_canal_hmac import (  # noqa: F401  (fixtures: ring, _example_roster autouse)
    FakeGh,
    _c,
    _canal_cfg,
    _example_roster,
    _forged,
    _iso_ts,
    _signed,
    _WaitClock,
    ring,
    tg,
)

CREATED = "2026-11-14T12:00:00Z"


def _strict(tmp_path: Path, ring: dict) -> Path:
    return _canal_cfg(tmp_path, f'\n[channel_keyring]\ndir = "{ring["dir"]}"\n')


def test_forged_spam_never_freezes_the_read_cursor(tmp_path: Path, ring, capsys) -> None:
    """Attacker floods unsigned/forged mail: it is shown (marked), never marks read, and never
    holds the cursor below it once a verified item is marked. No permanent freeze."""
    cfg, state = _strict(tmp_path, ring), tmp_path / "st"
    argv = ["--config", str(cfg), "inbox", "--for", "peerb", "--mark-read", "--state-dir", str(state)]
    cur = state / "last_seen_peerb.json"
    timeline = [_c(11, _forged(ring, "para: peerb\n\nforjado 11\n\n— agent-c\n", "agent-c", created=CREATED)),
                _c(12, "para: peerb\n\nsem sig 12\n\n— agent-c\n"),
                _c(13, _forged(ring, "para: peerb\n\nforjado 13\n\n— agent-c\n", "agent-c", created=CREATED))]
    for _ in range(3):  # repeated reads with only forged traffic: no crash, no cursor
        assert tg.main(argv, runner=FakeGh(timeline)) == 0
        out = capsys.readouterr().out
        assert "não verificado: bad_mac" in out and "não verificado: unsigned" in out
        assert tg.read_cursor(cur) is None
    timeline.append(_c(14, _signed(ring, "para: peerb\n\nassinado 14\n\n— agent-c\n", "agent-c")))
    assert tg.main(argv, runner=FakeGh(timeline)) == 0
    capsys.readouterr()
    assert tg.read_cursor(cur) == 14  # moved PAST the forged 11-13
    timeline.append(_c(15, _forged(ring, "para: peerb\n\nforjado 15\n\n— agent-c\n", "agent-c", created=CREATED)))
    timeline.append(_c(16, _signed(ring, "para: peerb\n\nassinado 16\n\n— agent-c\n", "agent-c")))
    assert tg.main(argv, runner=FakeGh(timeline)) == 0
    out = capsys.readouterr().out
    assert "FORJADO 15" in out and "assinado 16" in out  # 15 shown (marked) before being passed
    assert tg.read_cursor(cur) == 16


def test_wait_mark_read_never_silently_skips_unverified_mail(tmp_path: Path, ring, capsys, monkeypatch) -> None:
    """Cursor 9; unsigned #10 (e.g. a keyless terminal during rollout) is already unread; a signed
    #12 ends the wait. #10 must be shown (marked) in that output OR stay unread afterwards."""
    cfg, state = _strict(tmp_path, ring), tmp_path / "st"
    tg.write_cursor(state / "last_seen_peerb.json", 9)
    unsigned = _c(10, "para: peerb\n\nrecado legitimo sem sig\n\n— agent-b\n", "2026-11-14T12:00:00Z")
    good = _c(12, _signed(ring, "para: peerb\n\nassinado\n\n— agent-c\n", "agent-c", ts=_iso_ts("2026-11-14T12:00:40Z")),
              "2026-11-14T12:00:40Z")
    clock = _WaitClock(monkeypatch)
    argv = ["--config", str(cfg), "inbox", "--for", "peerb", "--wait", "60", "--mark-read", "--state-dir", str(state)]
    assert tg.main(argv, runner=clock.gh([(-60, unsigned), (40, good)])) == 0
    shown = capsys.readouterr().out
    assert "assinado" in shown
    if "recado legitimo sem sig" in shown:
        assert "não verificado: unsigned" in shown  # shown, marked: passing it is fine
        return
    # not shown => must still be unread for the next plain read
    assert tg.main(["--config", str(cfg), "inbox", "--for", "peerb", "--state-dir", str(state)],
                   runner=FakeGh([unsigned, good])) == 0
    assert "recado legitimo sem sig" in capsys.readouterr().out


def test_legacy_flag_never_trusts_an_invalid_signature(ring) -> None:
    forged = _c(2, _forged(ring, "para: peerb\n\nforjado\n\n— agent-c\n", "agent-c", created=CREATED))
    unsigned = _c(1, "para: peerb\n\nsem sig\n\n— agent-c\n")
    items = tg.addressed_inbox([unsigned, forged], ["peerb"], None, keyring=ring["ring"])
    trusted = tg.trusted_inbox(items, keyring=ring["ring"], legacy_unsigned=True)
    assert [i["id"] for i in trusted] == [1]  # unsigned ok in legacy; bad_mac never


def test_no_keyring_is_read_only_semantics_not_a_wake(tmp_path: Path) -> None:
    """No keyring: inbox --wait/--mark-read keep the pre-HMAC READ behaviour, but the wake gate
    (speaker.gate_comment, what wake_watch calls) still grants nothing to unsigned text."""
    from firefly_bridge import speaker as sp
    c = _c(1, "para: peerb\n\nacorda\n\n— agent-c\n")
    assert [i["id"] for i in tg.trusted_inbox(tg.addressed_inbox([c], ["peerb"], None, keyring=None),
                                              keyring=None, legacy_unsigned=False)] == [1]
    d = sp.gate_comment(c, own_aliases=["peerb"], roster=["agent-c"], keyring=None)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "signature_required")
    assert json.dumps(d.__dict__)
