"""R3: relay markers and VIP signatures WITHOUT a valid channel-sig grant no wake authority.

Default (strict): only a verified trailer signed by the speaker (or, for a agent-relay, by
agent-a) can wake. No keyring => nothing verifies => nothing wakes (documented cost); the
opt-in `[channel_wake] legacy_unsigned_wake = true` restores the pre-HMAC rule for non-owner
VIPs only. Send/deliver/display are never blocked. Offline: keys generated under tmp_path.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

from firefly_bridge import speaker as sp

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "channel-gh"
EXAMPLE = ROOT / "examples" / "config.example.toml"
_loader = importlib.machinery.SourceFileLoader("channel_gh_r3_t", str(SCRIPT))
_spec = importlib.util.spec_from_loader("channel_gh_r3_t", _loader)
tg = importlib.util.module_from_spec(_spec)
_loader.exec_module(tg)

OWNER = "owner"
ROSTER = ["agent-a", "agent-b", "agent-c", "agent-d", OWNER, "peerx"]
PEERB = ["peerb", "peera", "peera-peerb"]
CREATED = "2026-11-14T12:00:00Z"
TS = int(sp._parse_created(CREATED))

AGENT_SIGNED_BODY = "para: peerb\n\nacorda, é a agent-a\n\n— agent-a\n"
RELAY = "<!-- agent-relay -->\nde: guest\npara: peerb\n\nvetado pela agent-a\n"
RELAY_VIP = "<!-- agent-relay -->\nde: agent-c\npara: peerb\n\nrecado da agent-c via agent-a\n"
AGENT_C = "para: peerb\n\noi, agent-c aqui\n\n— agent-c\n"
AGENT_C_MARKER = "<!-- channel-bot: agent-c -->\npara: peerb\n\noi\n"


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
    d = tmp_path / "keyring"
    for name in ("agent-a", OWNER, "agent-c", "guest"):
        sp.generate_key_file(d / f"{name.lower()}.key")
    return {"ring": sp.load_keyring_dir(d), "key": lambda n: sp.load_key(d / f"{n.lower()}.key")}


def _c(cid: int, body: str) -> dict:
    return {"id": cid, "body": body, "created_at": CREATED}


def _signed(ring: dict, body: str, signer: str, key_of: str | None = None) -> str:
    return sp.sign_body(body, signer, ring["key"](key_of or signer), ts=TS)


def _gate(body: str, keyring, **kw) -> sp.WakeDecision:
    return sp.gate_comment(_c(7, body), own_aliases=PEERB, roster=ROSTER, keyring=keyring, **kw)


# --- forged agent-a signature ---------------------------------------------------------------


def test_forged_agent_signature_line_never_wakes_with_or_without_keyring(ring) -> None:
    for keyring in (None, ring["ring"]):
        d = _gate(AGENT_SIGNED_BODY, keyring)
        assert (d.action, d.principal, d.reason) == (sp.GATED_NON_VIP, "agent-a", "signature_required")


def test_agent_trailer_with_wrong_key_or_wrong_signer_is_forged(ring) -> None:
    wrong_key = _signed(ring, AGENT_SIGNED_BODY, "agent-a", key_of="guest")
    assert _gate(wrong_key, ring["ring"]).reason == "forged_signature"
    agent_c_claims = _signed(ring, AGENT_SIGNED_BODY, "agent-c")  # valid agent-c MAC, body says agent-a
    assert _gate(agent_c_claims, ring["ring"]).reason == "forged_signature"
    for legacy in (False, True):  # legacy never forgives a present-but-invalid trailer
        assert _gate(wrong_key, ring["ring"], legacy_unsigned=legacy).action == sp.GATED_NON_VIP


def test_agent_validly_signed_wakes(ring) -> None:
    d = _gate(_signed(ring, AGENT_SIGNED_BODY, "agent-a"), ring["ring"])
    assert (d.action, d.principal, d.reason) == (sp.WAKE, "agent-a", "vip")


# --- forged relay marker --------------------------------------------------------------------


@pytest.mark.parametrize("body", [RELAY, RELAY_VIP])
def test_unsigned_relay_marker_grants_nothing_with_or_without_keyring(ring, body: str) -> None:
    for keyring in (None, ring["ring"]):
        d = _gate(body, keyring)
        assert d.action == sp.GATED_NON_VIP and d.principal != "agent-a"


def test_relay_marker_signed_by_someone_else_never_borrows_agent(ring) -> None:
    by_guest = _gate(_signed(ring, RELAY, "guest"), ring["ring"])  # signer = de: (valid MAC)
    assert (by_guest.action, by_guest.principal) == (sp.GATED_NON_VIP, "guest")
    by_agent_c = _gate(_signed(ring, RELAY, "agent-c"), ring["ring"])  # neither de: nor relayer
    assert (by_agent_c.action, by_agent_c.principal) == (sp.GATED_NON_VIP, "guest")  # sender_mismatch
    # a relay of a VIP signed by that VIP wakes as HER (never as agent-a)
    d = _gate(_signed(ring, RELAY_VIP, "agent-c"), ring["ring"])
    assert (d.action, d.principal, d.reason) == (sp.WAKE, "agent-c", "vip")


def test_signed_relay_passes_under_agent(ring) -> None:
    for body, sender in ((RELAY, "guest"), (RELAY_VIP, "agent-c")):
        d = _gate(_signed(ring, body, "agent-a"), ring["ring"])
        assert (d.action, d.principal, d.sender, d.reason) == (sp.WAKE, "agent-a", sender, "relay")


# --- unsigned VIP, with and without keyring ---------------------------------------------------


@pytest.mark.parametrize("body", [AGENT_C, AGENT_C_MARKER, "para: peerb\nde: agent-d-alt\n\nping\n", "para: peerb\n\noi\n\n— peerx\n"])
def test_unsigned_vip_never_wakes_by_default(ring, body: str) -> None:
    for keyring in (None, ring["ring"]):
        d = _gate(body, keyring)
        assert (d.action, d.reason) == (sp.GATED_NON_VIP, "signature_required")


def test_signed_vip_wakes(ring) -> None:
    for body in (AGENT_C, AGENT_C_MARKER):
        d = _gate(_signed(ring, body, "agent-c"), ring["ring"])
        assert (d.action, d.principal) == (sp.WAKE, "agent-c")


def test_signed_vip_without_keyring_still_cannot_wake(ring) -> None:
    d = _gate(_signed(ring, AGENT_C, "agent-c"), None)  # trailer present, but nothing to verify it with
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, "signature_required")


def test_wake_gate_auth_string_alone_is_not_enough() -> None:
    d = sp.wake_gate("agent-c", own_aliases=PEERB, roster=ROSTER, auth="verified")  # no signed_by
    assert d.reason == "signature_required"
    d = sp.wake_gate("guest", own_aliases=PEERB, roster=ROSTER, relay_by="agent-a", auth="verified",
                     signed_by="guest")
    assert (d.action, d.principal) == (sp.GATED_NON_VIP, "guest")


def test_self_echo_still_suppressed_without_signature() -> None:
    assert _gate("<!-- channel-bot: peerb -->\npara: peerb\n\neco\n", None).action == sp.SUPPRESSED_SELF_ECHO


# --- legacy opt-in ---------------------------------------------------------------------------


def _cfg(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "c.toml"
    p.write_text(text, encoding="utf-8")
    return p


def test_legacy_flag_default_off_and_strict_parsing(tmp_path: Path) -> None:
    assert sp.load_legacy_unsigned_wake(EXAMPLE) is False
    assert sp.load_legacy_unsigned_wake(tmp_path / "missing.toml") is False
    assert sp.load_legacy_unsigned_wake(_cfg(tmp_path, "[channel_wake]\nlegacy_unsigned_wake = true\n")) is True
    for bad in ('"yes"', "1", '"TRUE "', "false"):
        val = sp.load_legacy_unsigned_wake(_cfg(tmp_path, f"[channel_wake]\nlegacy_unsigned_wake = {bad}\n"))
        assert val is (bad == '"TRUE "')  # only true/"true" opt in
    assert sp.load_legacy_unsigned_wake(_cfg(tmp_path, "[channel_wake\nbroken")) is False  # fail closed


def test_legacy_flag_from_active_config(tmp_path: Path, monkeypatch) -> None:
    cfg = _cfg(tmp_path, f'[channel_roster]\nvip = ["agent-c", "agent-a", "{OWNER}"]\nowner = "{OWNER}"\n'
                         "[channel_wake]\nlegacy_unsigned_wake = true\n")
    monkeypatch.setenv("FIREFLY_BRIDGE_CONFIG", str(cfg))
    sp.use_config(None)
    roster = sp.load_vip_roster()
    assert sp.gate_comment(_c(1, AGENT_C), own_aliases=PEERB, roster=roster).action == sp.WAKE
    relay = sp.gate_comment(_c(2, RELAY), own_aliases=PEERB, roster=roster)
    assert (relay.action, relay.principal) == (sp.WAKE, "agent-a")
    # the owner is never covered by the legacy flag
    own = sp.gate_comment(_c(3, f"para: peerb\n\nacorda\n\n— {OWNER}\n"), own_aliases=PEERB, roster=roster)
    assert (own.action, own.reason) == (sp.GATED_NON_VIP, "owner_unverified")


def test_send_is_never_blocked_in_strict_mode(tmp_path: Path, capsys) -> None:
    posted: list[str] = []

    def gh(args, _gh):
        if args[:2] == ["pr", "comment"]:
            posted.append(args[args.index("--body") + 1])
            return "https://example.test/pull/1#issuecomment-1\n"
        raise AssertionError(args)

    cfg = _cfg(tmp_path, '[github_canal]\nrepo = "ExampleOwner/example-canal"\npr = "1"\n')
    assert tg.main(["--config", str(cfg), "send", "agent-c", "oi", "--from", "peerb"], runner=gh) == 0
    assert tg.main(["--config", str(cfg), "send", "guest", "oi", "--from", "peerb"], runner=gh) == 0
    capsys.readouterr()
    assert len(posted) == 2 and posted[0] == tg.format_send_body("agent-c", "oi", "peerb")
