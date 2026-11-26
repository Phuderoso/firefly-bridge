"""Opt-in channel-sig v=1 on agent-a's `<!-- agent-relay -->` posts (default: unsigned).

Same trailer and verifier as send/reply (speaker.sign_body / verify_comment) and the B1
presence gate (wake_decision + nonce ledger). Offline: keys are generated under tmp_path,
gh is a fake runner, nothing is posted.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import speaker as sp
from tests.hmac_fixtures import SIG_TS, make_keyring

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "channel-gh"
EXAMPLE = ROOT / "examples" / "config.example.toml"
_loader = importlib.machinery.SourceFileLoader("channel_gh_relay_t", str(SCRIPT))
_spec = importlib.util.spec_from_loader("channel_gh_relay_t", _loader)
tg = importlib.util.module_from_spec(_spec)
_loader.exec_module(tg)

CREATED = datetime.fromtimestamp(SIG_TS, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
NAMES = ("agent-a", "agent-c", "peerb", "agent-b")


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
    return make_keyring(tmp_path, NAMES)


def _cfg(tmp_path: Path, ring: dict, identity: str | None) -> Path:
    text = '[github_canal]\nrepo = "o/canal"\npr = "1"\n' + (
        f'[channel_keyring]\ndir = "{ring["dir"]}"\n'
    )
    if identity:
        text += (
            f'[channel_identity]\nname = "{identity}"\n'
            f'key_file = "{ring["dir"] / (identity.lower() + ".key")}"\n'
        )
    p = tmp_path / f"cfg-{identity or 'none'}.toml"
    p.write_text(text, encoding="utf-8")
    p.chmod(0o600)
    return p


class FakeGh:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], gh: str = "gh") -> str:
        self.calls.append(args)
        return "https://example.invalid/c/1\n"

    @property
    def body(self) -> str:
        return self.calls[-1][self.calls[-1].index("--body") + 1]


def _c(body: str, created: str = CREATED, cid: int = 7) -> dict:
    return {"id": cid, "body": body, "created_at": created}


def _relay(text: str = "recado da agent-c via agent-a") -> str:
    return sp.format_relay_body("agent-c", text, para="peerb")


# --- body shape -------------------------------------------------------------------------------


def test_relay_body_shape_matches_what_the_canal_already_parses() -> None:
    body = sp.format_relay_body("agent-c", "oi", para="peerb", reply_to=42)
    assert body == "<!-- agent-relay -->\n<!-- reply-to: 42 -->\n**de: agent-c**\npara: peerb\n\noi\n"
    spk = sp.resolve_speaker(body)
    assert (spk.name, spk.relay_by) == ("agent-c", "agent-a")
    assert sp.parse_headers(body) == {"de": "agent-c", "para": "peerb"}


@pytest.mark.parametrize("de", ["", "  ", "a<!--b", "x-->", "agent-c\nde: owner"])
def test_relay_rejects_bad_names(de: str) -> None:
    with pytest.raises(ValueError):
        sp.format_relay_body(de, "oi", para="peerb")


def test_relay_refuses_a_typed_trailer_in_the_message(ring: dict) -> None:
    forged = sp.sign_body("x\n", "agent-a", ring["key"]("agent-a"), ts=SIG_TS)
    with pytest.raises(ValueError, match="sig_trailer"):
        sp.format_relay_body("agent-c", forged, para="peerb")


# --- sign -> verify ---------------------------------------------------------------------------


def test_round_trip_signed_relay_is_verified_as_agent(ring: dict) -> None:
    body = sp.sign_relay_body(_relay(), "agent-a", ring["key"]("agent-a"), ts=SIG_TS)
    assert sp.SIG_LINE_RE.match(body.rstrip("\n").rsplit("\n", 1)[1])
    check = sp.verify_comment(_c(body), ring["ring"], {})
    assert (check.auth, check.signed_by) == (sp.AUTH_VERIFIED, "agent-a")
    gate = sp.wake_gate(
        "agent-c", own_aliases=["peerb"], roster=["agent-a", "agent-c"], relay_by="agent-a",
        auth=check.auth, signed_by=check.signed_by, legacy_unsigned=False,
    )
    assert (gate.action, gate.principal) == (sp.WAKE, "agent-a")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.replace("recado da agent-c", "recado da agent-b"),
        lambda b: b.replace("**de: agent-c**", "**de: agent-b**"),
        lambda b: b.replace("para: peerb", "para: agent-b"),
        lambda b: b.replace("<!-- agent-relay -->\n", "<!-- agent-relay -->\n<!-- reply-to: 1 -->\n"),
    ],
)
def test_tampered_relay_is_bad_mac(ring: dict, mutate) -> None:
    body = sp.sign_relay_body(_relay(), "agent-a", ring["key"]("agent-a"), ts=SIG_TS)
    assert sp.verify_comment(_c(mutate(body)), ring["ring"], {}).auth == "bad_mac"


def test_wrong_key_is_rejected(ring: dict) -> None:
    body = sp.sign_body(_relay(), "agent-a", ring["key"]("agent-c"), ts=SIG_TS)  # agent-c's key, agent-a's name
    assert sp.verify_comment(_c(body), ring["ring"], {}).auth == "bad_mac"
    other = make_keyring(Path(str(ring["dir"]) + "-other"), ("agent-a",))
    body = sp.sign_relay_body(_relay(), "agent-a", other["key"]("agent-a"), ts=SIG_TS)
    assert sp.verify_comment(_c(body), ring["ring"], {}).auth == "bad_mac"


def test_relay_signs_only_as_the_relayer(ring: dict) -> None:
    with pytest.raises(ValueError, match="relayer"):
        sp.sign_relay_body(_relay(), "agent-c", ring["key"]("agent-c"), ts=SIG_TS)
    with pytest.raises(ValueError, match="not_an_agent_relay"):
        sp.sign_relay_body("para: peerb\n\noi\n", "agent-a", ring["key"]("agent-a"), ts=SIG_TS)


def test_unsigned_relay_still_parses_as_unsigned(ring: dict) -> None:
    body = _relay()
    assert sp.verify_comment(_c(body), ring["ring"], {}).auth == sp.AUTH_UNSIGNED
    assert sp.verify_comment(_c(body), None, {}).auth == sp.AUTH_NO_KEYRING


def test_signed_relay_fits_b1_presence_gate_and_ledger(ring: dict, tmp_path: Path) -> None:
    sp.use_config(EXAMPLE)
    now = float(SIG_TS)
    body = sp.sign_relay_body(_relay(), "agent-a", ring["key"]("agent-a"), ts=SIG_TS)
    base = dict(
        target="peerb", own_aliases=["peerb"], roster=["agent-a", "agent-c"], now=now,
        sources=[lambda n: pr.PresenceRecord(n, now, "idle")],
        cfg=pr.PresenceConfig(terminals={"peerb": str(tmp_path / "hb.json")}),
        keyring=ring["ring"], nonce_store=tmp_path / "nonces.json", relay_by="agent-a",
        claim=True,
    )
    first = pr.wake_decision("agent-c", body=body, created_at=CREATED, **base)
    assert (first.action, first.principal) == (sp.WAKE, "agent-a")
    again = pr.wake_decision("agent-c", body=body, created_at=CREATED, **base)
    assert (again.action, again.reason) == (sp.GATED_NON_VIP, "replayed_nonce")


# --- CLI: channel-gh relay ------------------------------------------------------------------


def test_cli_default_is_unsigned_and_unchanged(ring: dict, tmp_path: Path) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, "agent-a")  # identity bound, but no --sign => no trailer
    assert tg.main(["--config", str(cfg), "relay", "--de", "agent-c", "--para", "peerb", "oi", "peerb"], gh) == 0
    assert gh.body == sp.format_relay_body("agent-c", "oi peerb", para="peerb")
    assert sp.split_signature(gh.body)[1] is None
    assert sp.verify_comment(_c(gh.body), ring["ring"], {}).auth == sp.AUTH_UNSIGNED


def test_cli_sign_posts_fresh_verified_trailer(ring: dict, tmp_path: Path) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, "agent-a")
    before = int(time.time())
    assert tg.main(["--config", str(cfg), "relay", "--sign", "--de", "agent-c", "--para", "peerb", "oi"], gh) == 0
    _, sig = sp.split_signature(gh.body)
    assert sig is not None and sig.group("from") == "agent-a"
    assert before <= int(sig.group("ts")) <= int(time.time())
    created = datetime.fromtimestamp(int(sig.group("ts")), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    check = sp.verify_comment(_c(gh.body, created), ring["ring"], {})
    assert (check.auth, check.signed_by) == (sp.AUTH_VERIFIED, "agent-a")
    key_hex = ring["key"]("agent-a").hex()
    assert key_hex not in " ".join(gh.calls[-1])


def test_cli_two_signed_relays_get_distinct_nonces(ring: dict, tmp_path: Path) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, "agent-a")
    for _ in range(2):
        tg.main(["--config", str(cfg), "relay", "--sign", "--de", "agent-c", "oi"], gh)
    nonces = {sp.split_signature(c[c.index("--body") + 1])[1].group("nonce") for c in gh.calls}
    assert len(nonces) == 2


def test_cli_sign_refuses_non_relayer_identity(ring: dict, tmp_path: Path) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, "peerb")
    with pytest.raises(SystemExit, match="relay_signer_must_be_relayer"):
        tg.main(["--config", str(cfg), "relay", "--sign", "--de", "agent-c", "oi"], gh)
    assert gh.calls == []


def test_cli_sign_without_identity_refuses(ring: dict, tmp_path: Path) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, None)
    with pytest.raises(SystemExit, match="relay_sign_needs_identity"):
        tg.main(["--config", str(cfg), "relay", "--sign", "--de", "agent-c", "oi"], gh)
    assert gh.calls == []


def test_cli_sign_refuses_open_key_file(ring: dict, tmp_path: Path) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, "agent-a")
    (ring["dir"] / "agent-a.key").chmod(0o644)
    with pytest.raises(SystemExit, match="key_file_mode_too_open"):
        tg.main(["--config", str(cfg), "relay", "--sign", "--de", "agent-c", "oi"], gh)
    assert gh.calls == []


def test_cli_signed_dry_run_posts_nothing_and_redacts_mac(
    ring: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gh = FakeGh()
    cfg = _cfg(tmp_path, ring, "agent-a")
    assert tg.main(["--config", str(cfg), "relay", "--sign", "--dry-run", "--de", "agent-c", "oi"], gh) == 0
    out = capsys.readouterr().out
    assert gh.calls == []
    assert "channel-sig v=1 from=agent-a" in out and "mac=<redacted>" in out
    assert ring["key"]("agent-a").hex() not in out
    assert sp.split_signature(out)[1] is None  # not a postable signed body
