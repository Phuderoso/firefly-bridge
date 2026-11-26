"""Canal HMAC (channel-sig v=1) in firefly_bridge.speaker + owner-wake hardening.

Point 1: channel-gh signs canal comments with the speaker SIG_LINE and verifies with the
         config keyring. Point 4: a forged owner claim (no / bad / wrong-signer signature) never
         wakes a terminal; only a verified signature from the owner (or a relay the relayer
         signed) does — also with NO keyring configured.

Offline only: keys are generated at test time under tmp_path, gh is a fake function.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

from firefly_bridge import speaker as sp

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "channel-gh"
EXAMPLE = ROOT / "examples" / "config.example.toml"
_loader = importlib.machinery.SourceFileLoader("channel_gh_hmac_t", str(SCRIPT))
_spec = importlib.util.spec_from_loader("channel_gh_hmac_t", _loader)
tg = importlib.util.module_from_spec(_spec)
_loader.exec_module(tg)

OWNER = "owner"
OWNER_LOGIN = "ownerlogin"
ROSTER = ["agent-a", "agent-b", "agent-c", "agent-d", OWNER, "peerx"]
PEERB = ["peerb", "peera", "peera-peerb"]
CREATED = "2026-11-14T12:00:00Z"
TS = int(sp._parse_created(CREATED))


@pytest.fixture(autouse=True)
def _example_roster(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("FIREFLY_BRIDGE_CONFIG", str(EXAMPLE))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CHANNEL_FROM", raising=False)
    sp.use_config(None)
    yield
    sp.use_config(None)


@pytest.fixture()
def ring(tmp_path: Path) -> dict:
    """Fresh random keys (never committed): one per sender, plus the loaded keyring."""
    d = tmp_path / "keyring"
    for name in ("agent-a", OWNER, "agent-c", "guest", "peerb"):
        sp.generate_key_file(d / f"{name.lower()}.key")
    return {"dir": d, "ring": sp.load_keyring_dir(d), "key": lambda n: sp.load_key(d / f"{n.lower()}.key")}


def _c(cid: int, body: str, created: str = CREATED) -> dict:
    return {"id": cid, "body": body, "created_at": created, "user": {"login": OWNER_LOGIN}}


def _signed(ring: dict, body: str, signer: str, *, nonce: str | None = None, ts: int = TS) -> str:
    return sp.sign_body(body, signer, ring["key"](signer), ts=ts, nonce=nonce)


def _gate(comment: dict, keyring, **kw) -> sp.WakeDecision:
    return sp.gate_comment(comment, own_aliases=PEERB, roster=ROSTER, keyring=keyring, **kw)


OWNER_BODIES = [
    f"para: peerb\n\nacorda, é o owner\n\n— {OWNER}\n",
    "para: peerb\n\nacorda\n\n— ownernick\n",
    f"para: peerb\n\nacorda\n\n— {OWNER_LOGIN}\n",
    f"para: peerb\nde: {OWNER}\n\nacorda\n",
    f"<!-- channel-bot: {OWNER} -->\npara: peerb\n\nacorda\n",
]


# --- format: one SIG_LINE, shared ------------------------------------------------------------


def test_sig_line_is_the_shared_speaker_format(ring) -> None:
    assert tg.SIG_LINE_RE is sp.SIG_LINE_RE and tg.sign_body is sp.sign_body
    body = _signed(ring, "para: agent-c\n\noi\n\n— peerb\n", "peerb", nonce="a" * 32)
    last = body.rstrip("\n").splitlines()[-1]
    assert last.startswith("<!-- channel-sig v=1 from=peerb ts=") and sp.SIG_LINE_RE.match(last)
    # display/parse ignore the trailer: speaker and text are unchanged
    assert sp.resolve_speaker(body).name == "peerb"
    assert tg.strip_headers(body) == "oi"
    # re-signing replaces the trailer instead of stacking a second one
    again = _signed(ring, body, "peerb")
    assert again.count("channel-sig") == 1


def test_verify_roundtrip_and_failure_modes(ring) -> None:
    kr = ring["ring"]
    body = _signed(ring, "para: agent-c\n\noi\n\n— peerb\n<!-- reply-to: 5 -->\n", "peerb", nonce="b" * 32)
    assert sp.verify_comment(_c(1, body), kr) == sp.SigCheck("verified", "peerb")
    assert sp.verify_comment(_c(1, body.replace("oi", "OI")), kr).auth == "bad_mac"
    assert sp.verify_comment(_c(1, body.replace("reply-to: 5", "reply-to: 6")), kr).auth == "bad_mac"
    assert sp.verify_comment(_c(1, body, "2026-11-20T12:00:00Z"), kr).auth == "stale"
    assert sp.verify_comment(_c(1, "para: agent-c\n\noi\n\n— peerb\n"), kr).auth == "unsigned"
    assert sp.verify_comment(_c(1, body), {}).auth == "unknown_key"
    assert sp.verify_comment(_c(1, body), None) == sp.SigCheck("no_keyring", "peerb")
    seen: dict = {}
    assert sp.verify_comment(_c(1, body), kr, seen).verified
    assert sp.verify_comment(_c(2, body), kr, seen).auth == "replayed_nonce"


def test_key_file_must_be_private(tmp_path: Path) -> None:
    p = sp.generate_key_file(tmp_path / "k" / "x.key")
    assert (p.stat().st_mode & 0o777) == 0o600
    os.chmod(p, 0o644)
    with pytest.raises(sp.KeyFileError):
        sp.load_key(p)
    with pytest.raises(FileExistsError):
        sp.generate_key_file(p)


# --- point 4: forged owner never wakes -------------------------------------------------------


@pytest.mark.parametrize("body", OWNER_BODIES)
def test_owner_unsigned_never_wakes_with_or_without_keyring(body: str, ring) -> None:
    for keyring in (None, ring["ring"]):
        d = _gate(_c(1, body), keyring)
        assert (d.action, d.reason) == (sp.GATED_NON_VIP, "owner_unverified"), (keyring is None, d)


@pytest.mark.parametrize("body", OWNER_BODIES)
def test_owner_with_bad_signature_never_wakes(body: str, ring) -> None:
    signed = _signed(ring, body, OWNER)
    tampered = signed.replace("acorda", "ACORDA")
    d = _gate(_c(1, tampered), ring["ring"])
    assert d.action == sp.GATED_NON_VIP and d.reason == "forged_signature"


@pytest.mark.parametrize("body", OWNER_BODIES)
def test_wrong_signer_claiming_owner_never_wakes(body: str, ring) -> None:
    agent_c_signed = _signed(ring, body, "agent-c")  # agent-c's valid key, body says it is the owner
    d = _gate(_c(1, agent_c_signed), ring["ring"])
    assert d.action == sp.GATED_NON_VIP and d.reason == "forged_signature"
    assert sp.verify_comment(_c(1, agent_c_signed), ring["ring"]).auth == "sender_mismatch"


@pytest.mark.parametrize("body", OWNER_BODIES)
def test_owner_validly_signed_wakes(body: str, ring) -> None:
    d = _gate(_c(1, _signed(ring, body, OWNER)), ring["ring"])
    assert (d.action, d.principal, d.reason) == (sp.WAKE, OWNER, "vip"), d


def test_owner_signature_without_keyring_still_cannot_wake(ring) -> None:
    """No keyring = nothing can be verified, so even a real owner trailer does not escalate."""
    d = _gate(_c(1, _signed(ring, OWNER_BODIES[0], OWNER)), None)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "owner_unverified")


def test_owner_replay_of_old_signed_body_does_not_wake(ring) -> None:
    body = _signed(ring, OWNER_BODIES[0], OWNER, ts=TS)
    assert _gate(_c(1, body, "2026-11-21T12:00:00Z"), ring["ring"]).action == sp.GATED_NON_VIP
    seen: dict = {}
    assert _gate(_c(1, body), ring["ring"], seen_nonces=seen).action == sp.WAKE
    assert _gate(_c(2, body), ring["ring"], seen_nonces=seen).action == sp.GATED_NON_VIP


def test_wake_gate_owner_needs_signed_by_not_just_auth_string() -> None:
    d = sp.wake_gate(OWNER, own_aliases=PEERB, roster=ROSTER, auth="verified")
    assert d.reason == "owner_unverified"  # a caller passing only auth="verified" is not enough
    d = sp.wake_gate(OWNER, own_aliases=PEERB, roster=ROSTER, auth="verified", signed_by="agent-c")
    assert d.reason == "owner_unverified"
    d = sp.wake_gate("ownernick", own_aliases=PEERB, roster=ROSTER, auth="verified", signed_by=OWNER)
    assert (d.action, d.principal) == (sp.WAKE, OWNER)


def test_owner_comes_from_config_not_code(tmp_path: Path) -> None:
    assert sp.load_owner(EXAMPLE) == [OWNER]
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[channel_roster]\nvip = ["agent-c", "{OWNER}"]\n', encoding="utf-8")
    assert sp.load_owner(cfg) == []
    # DOCUMENTED LIMIT (legacy opt-in only): with no `owner` declared the gate cannot know who
    # the owner is, so his unsigned name acts as a plain VIP...
    d = sp.wake_gate(OWNER, own_aliases=PEERB, roster=["agent-c", OWNER], owners=sp.load_owner(cfg),
                     legacy_unsigned=True)
    assert d.action == sp.WAKE
    # ...but the strict default (R3) closes it anyway: no verified signature, no wake
    d = sp.wake_gate(OWNER, own_aliases=PEERB, roster=["agent-c", OWNER], owners=sp.load_owner(cfg))
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "signature_required")
    for rel in ("firefly_bridge/speaker.py", "scripts/channel-gh"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "VIP_SENDERS" not in text


# --- relays ---------------------------------------------------------------------------------

RELAY = "<!-- agent-relay -->\nde: guest\npara: peerb\n\nvetado pela agent-a\n"
RELAY_OWNER = f"<!-- agent-relay -->\nde: {OWNER}\npara: peerb\n\nrecado do owner via agent-a\n"


def test_verified_agent_relay_wakes_under_agent(ring) -> None:
    d = _gate(_c(1, _signed(ring, RELAY, "agent-a")), ring["ring"])
    assert (d.action, d.principal, d.sender, d.reason) == (sp.WAKE, "agent-a", "guest", "relay")


def test_unverified_relay_does_not_escalate_with_keyring(ring) -> None:
    unsigned = _gate(_c(1, RELAY), ring["ring"])
    assert (unsigned.action, unsigned.principal) == (sp.GATED_NON_VIP, "guest")
    self_signed = _gate(_c(1, _signed(ring, RELAY, "guest")), ring["ring"])  # not agent-a's vouch
    assert (self_signed.action, self_signed.principal) == (sp.GATED_NON_VIP, "guest")
    tampered = _signed(ring, RELAY, "agent-a").replace("vetado", "VETADO")
    assert _gate(_c(1, tampered), ring["ring"]).action == sp.GATED_NON_VIP


def test_relay_naming_owner_needs_agent_signature(ring) -> None:
    for keyring in (None, ring["ring"]):
        d = _gate(_c(1, RELAY_OWNER), keyring)
        assert (d.action, d.reason) == (sp.GATED_NON_VIP, "owner_unverified")
    d = _gate(_c(1, _signed(ring, RELAY_OWNER, "agent-a")), ring["ring"])
    assert (d.action, d.principal, d.sender) == (sp.WAKE, "agent-a", OWNER)


# --- no-keyring compatibility (everything except the owner escalation is unchanged) ---------


def test_no_keyring_legacy_flag_restores_pre_hmac_non_owner_wake() -> None:
    for body, principal in (("para: peerb\n\noi\n\n— agent-c\n", "agent-c"), (RELAY, "agent-a")):
        d = _gate(_c(1, body), None, legacy_unsigned=True)
        assert (d.action, d.principal) == (sp.WAKE, principal)
        strict = _gate(_c(1, body), None)  # default: no keyring -> nothing verifies -> no wake
        assert strict.action == sp.GATED_NON_VIP
    assert _gate(_c(1, "para: peerb\n\noi\n\n— guest\n"), None, legacy_unsigned=True).action == sp.GATED_NON_VIP


def _canal_cfg(tmp_path: Path, extra: str = "") -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text('[github_canal]\nrepo = "ExampleOwner/example-canal"\npr = "1"\n' + extra, encoding="utf-8")
    return cfg


class FakeGh:
    def __init__(self, comments=None) -> None:
        self.comments = list(comments or [])
        self.posted: list[str] = []

    def __call__(self, args: list[str], gh: str) -> str:
        if args[0] == "api":
            return json.dumps(self.comments)
        if args[:2] == ["pr", "comment"]:
            body = args[args.index("--body") + 1]
            self.posted.append(body)
            return "https://example.test/pull/1#issuecomment-1\n"
        raise AssertionError(args)


def test_send_without_identity_is_byte_identical_to_legacy(tmp_path: Path, capsys) -> None:
    gh = FakeGh()
    assert tg.main(["--config", str(_canal_cfg(tmp_path)), "send", "agent-c", "oi", "--from", "peerb"], runner=gh) == 0
    capsys.readouterr()
    assert gh.posted == [tg.format_send_body("agent-c", "oi", "peerb")]
    assert "channel-sig" not in gh.posted[0]


def test_send_reply_ack_sign_when_identity_bound(tmp_path: Path, ring, monkeypatch, capsys) -> None:
    key = sp.generate_key_file(tmp_path / "mine" / "peerb.key")
    cfg = _canal_cfg(tmp_path, f'\n[channel_identity]\nname = "peerb"\nkey_file = "{key}"\n')
    gh = FakeGh([_c(5, "para: peerb\n\npergunta\n\n— agent-c\n")])
    base = ["--config", str(cfg)]
    assert tg.main([*base, "send", "agent-c", "oi"], runner=gh) == 0
    assert tg.main([*base, "reply", "5", "resposta"], runner=gh) == 0
    assert tg.main([*base, "ack", "5"], runner=gh) == 0
    capsys.readouterr()
    assert len(gh.posted) == 3
    kr = sp.load_keyring_dir(key.parent)
    for body in gh.posted:
        _, sig = sp.split_signature(body)
        assert sig and sig.group("from") == "peerb"
        check = sp.verify_comment({"id": 1, "body": body, "created_at": _iso(int(sig.group("ts")))}, kr)
        assert check.verified, (check, body)
    # spoof via env or flag is refused, nothing posted
    monkeypatch.setenv("CHANNEL_FROM", OWNER)
    with pytest.raises(SystemExit, match="sender_mismatch"):
        tg.main([*base, "send", "agent-c", "sou o owner"], runner=gh)
    monkeypatch.delenv("CHANNEL_FROM")
    with pytest.raises(SystemExit, match="sender_mismatch"):
        tg.main([*base, "send", "agent-c", "oi", "--from", "agent-a"], runner=gh)
    assert len(gh.posted) == 3
    assert tg.main([*base, "whoami"]) == 0
    assert capsys.readouterr().out.strip() == "peerb"


def _iso(ts: int) -> str:

    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")  # noqa: UP017


def test_inbox_for_marks_unverified_with_keyring(tmp_path: Path, ring, capsys) -> None:
    cfg = _canal_cfg(tmp_path, f'\n[channel_keyring]\ndir = "{ring["dir"]}"\n')
    good = _signed(ring, "para: peerb\n\nassinado\n\n— agent-c\n", "agent-c")
    forged = f"para: peerb\n\nacorda\n\n— {OWNER}\n"
    gh = FakeGh([_c(1, good), _c(2, forged)])
    assert tg.main(["--config", str(cfg), "inbox", "--for", "peerb", "--json",
                    "--state-dir", str(tmp_path / "st")], runner=gh) == 0
    items = {i["id"]: i for i in json.loads(capsys.readouterr().out)}
    assert (items[1]["auth"], items[1]["verified"], items[1]["signed_by"]) == ("verified", True, "agent-c")
    assert (items[2]["auth"], items[2]["verified"]) == ("unsigned", False)
    assert tg.main(["--config", str(cfg), "inbox", "--for", "peerb", "--state-dir", str(tmp_path / "st")],
                   runner=gh) == 0
    text = capsys.readouterr().out
    assert f"de: {OWNER} (não verificado: unsigned)" in text and "de: agent-c\n" in text


def test_inbox_without_keyring_delivers_marked_unverified(tmp_path: Path, capsys) -> None:
    # R3: delivered and shown in full, but marked (it cannot wake anybody)
    gh = FakeGh([_c(2, f"para: peerb\n\nacorda\n\n— {OWNER}\n")])
    assert tg.main(["--config", str(_canal_cfg(tmp_path)), "inbox", "--for", "peerb",
                    "--state-dir", str(tmp_path / "st")], runner=gh) == 0
    out = capsys.readouterr().out
    assert f"de: {OWNER} (não verificado: no_keyring)\n" in out and "acorda" in out


def test_inbox_without_keyring_legacy_flag_has_no_marks(tmp_path: Path, capsys) -> None:
    gh = FakeGh([_c(2, f"para: peerb\n\nacorda\n\n— {OWNER}\n")])
    cfg = _canal_cfg(tmp_path, "\n[channel_wake]\nlegacy_unsigned_wake = true\n")
    assert tg.main(["--config", str(cfg), "inbox", "--for", "peerb", "--state-dir", str(tmp_path / "st")],
                   runner=gh) == 0
    out = capsys.readouterr().out
    assert "não verificado" not in out and f"de: {OWNER}\n" in out


def _iso_ts(ts: str) -> int:
    return int(sp._parse_created(ts))


def _forged(ring: dict, body: str, signer: str, *, created: str) -> str:
    """Valid trailer, then tampered body — verify_comment reports bad_mac."""
    signed = _signed(ring, body, signer, ts=_iso_ts(created))
    # body text is covered by the MAC; flipping it keeps the trailer intact
    needle = "forjado"
    assert needle in body and needle in signed
    return signed.replace(needle, "FORJADO", 1)


class _WaitClock:
    """Monotonic clock driven by sleep(); gh only sees comments already posted."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.t = 0.0
        self.polls = 0
        clock = self
        monkeypatch.setattr(
            tg,
            "time",
            types.SimpleNamespace(monotonic=lambda: clock.t, sleep=lambda s: setattr(clock, "t", clock.t + s)),
        )

    def gh(self, timeline: list[tuple[float, dict]]):
        def fake_gh(args: list[str], gh: str) -> str:
            assert args[0] == "api", args
            self.polls += 1
            return json.dumps([c for at, c in timeline if at <= self.t])

        return fake_gh


def test_strict_keyring_unsigned_or_forged_does_not_move_mark_read_cursor(
    tmp_path: Path, ring, capsys: pytest.CaptureFixture[str]
) -> None:
    """Strict mode (keyring on, legacy_unsigned off): unsigned/forged comments
    stay visible on a normal inbox read but --mark-read must not move last_seen.
    """
    cfg = _canal_cfg(tmp_path, f'\n[channel_keyring]\ndir = "{ring["dir"]}"\n')
    state = tmp_path / "st"
    unsigned = _c(10, "para: peerb\n\nsem assinatura\n\n— agent-c\n")
    forged = _c(11, _forged(ring, "para: peerb\n\nforjado\n\n— agent-c\n", "agent-c", created=CREATED))
    argv = ["--config", str(cfg), "inbox", "--for", "peerb", "--mark-read", "--state-dir", str(state)]

    assert tg.main(argv, runner=FakeGh([unsigned, forged])) == 0
    out = capsys.readouterr().out
    assert "sem assinatura" in out and "não verificado: unsigned" in out
    assert "não verificado: bad_mac" in out
    assert list(state.glob("*.json")) == []  # cursor stays unset

    signed = _c(12, _signed(ring, "para: peerb\n\nassinado\n\n— agent-c\n", "agent-c"))
    assert tg.main(argv, runner=FakeGh([unsigned, forged, signed])) == 0
    out = capsys.readouterr().out
    assert "assinado" in out
    # unverified comments do not hold the floor or set it; cursor advances to the valid id
    assert tg.read_cursor(state / "last_seen_peerb.json") == 12


def test_strict_keyring_unsigned_or_forged_does_not_wake_wait_valid_signature_does(
    tmp_path: Path, ring, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """--wait in strict mode keeps waiting through unsigned/forged traffic and
    either times out or delivers only a later validly signed comment.
    """
    cfg = _canal_cfg(tmp_path, f'\n[channel_keyring]\ndir = "{ring["dir"]}"\n')
    old_u = _c(10, "para: peerb\n\nantigo sem sig\n\n— agent-c\n", "2026-11-14T11:00:00Z")
    old_f = _c(11, _forged(ring, "para: peerb\n\nforjado\n\n— agent-c\n", "agent-c", created="2026-11-14T11:00:00Z"),
               "2026-11-14T11:00:00Z")
    new_u = _c(12, "para: peerb\n\nnovo sem sig\n\n— agent-c\n", "2026-11-14T12:00:20Z")
    new_f = _c(13, _forged(ring, "para: peerb\n\nforjado\n\n— agent-c\n", "agent-c", created="2026-11-14T12:00:20Z"),
               "2026-11-14T12:00:20Z")
    good = _c(
        14,
        _signed(ring, "para: peerb\n\nchegou assinado\n\n— agent-c\n", "agent-c", ts=_iso_ts("2026-11-14T12:00:40Z")),
        "2026-11-14T12:00:40Z",
    )
    backlog = [(-3600, old_u), (-3600, old_f)]
    unsigned_later = [(20, new_u), (20, new_f)]

    # timeout path: only unsigned/forged arrive after the snapshot; --wait must not wake
    clock = _WaitClock(monkeypatch)
    state_to = tmp_path / "to"
    argv_to = ["--config", str(cfg), "inbox", "--for", "peerb", "--wait", "60",
               "--json", "--mark-read", "--state-dir", str(state_to)]
    assert tg.main(argv_to, runner=clock.gh(backlog + unsigned_later)) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert list(state_to.glob("*.json")) == []
    assert clock.t >= 60 and clock.polls >= 3  # snapshot, then later forgeries, then timeout

    # positive path: a validly signed comment after the forgeries does wake --wait
    clock = _WaitClock(monkeypatch)
    state_ok = tmp_path / "ok"
    argv_ok = ["--config", str(cfg), "inbox", "--for", "peerb", "--wait", "60",
               "--mark-read", "--state-dir", str(state_ok)]
    assert tg.main(argv_ok, runner=clock.gh(backlog + unsigned_later + [(40, good)])) == 0
    out = capsys.readouterr().out
    assert "chegou assinado" in out
    # unverified mail that arrived during the wait is shown marked (it did not end the wait)
    assert "#12 " in out and "não verificado: unsigned" in out and "não verificado: bad_mac" in out
    assert "antigo sem sig" not in out  # backlog below the snapshot floor stays hidden
    assert clock.t == pytest.approx(40)
    assert tg.read_cursor(state_ok / "last_seen_peerb.json") == 14


def test_trusted_inbox_ignores_forged_when_keyring_is_strict(ring) -> None:
    unsigned = _c(1, "para: peerb\n\nsem sig\n\n— agent-c\n")
    forged = _c(2, _forged(ring, "para: peerb\n\nforjado\n\n— agent-c\n", "agent-c", created=CREATED))
    good = _c(3, _signed(ring, "para: peerb\n\nok\n\n— agent-c\n", "agent-c"))
    items = tg.addressed_inbox([unsigned, forged, good], ["peerb"], None, keyring=ring["ring"])
    by_id = {i["id"]: i for i in items}
    assert by_id[1]["auth"] == "unsigned" and by_id[2]["auth"] == "bad_mac" and by_id[3]["verified"]
    trusted = tg.trusted_inbox(items, keyring=ring["ring"], legacy_unsigned=False)
    assert [i["id"] for i in trusted] == [3]
    # no keyring keeps the pre-HMAC read rule; legacy covers unsigned mail, never bad_mac
    raw = tg.addressed_inbox([unsigned, forged, good], ["peerb"], None, keyring=None)
    assert [i["id"] for i in tg.trusted_inbox(raw, keyring=None, legacy_unsigned=False)] == [1, 2, 3]
    assert [i["id"] for i in tg.trusted_inbox(items, keyring=ring["ring"], legacy_unsigned=True)] == [1, 3]


def test_keygen_never_prints_key(tmp_path: Path, capsys) -> None:
    target = tmp_path / "k" / "new.key"
    assert tg.main(["keygen", str(target)]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["key_material_printed"] is False
    assert target.read_text().strip() not in out
