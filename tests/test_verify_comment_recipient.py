"""Regression tests for issue #18: a signed canal comment is bound to its `para:` recipient.

The `para:` header is inside the MAC, so a verifier that knows its own identity can refuse a
validly signed comment addressed to somebody else (for example one copied from another
thread or re-posted to wake a different terminal). Neutral names only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from firefly_bridge import speaker as sp

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "config.example.toml"
CREATED = "2026-11-14T12:00:00Z"
TS = int(sp._parse_created(CREATED))
ME = ["Alpha", "Alpha-One"]
ROSTER = ["Beta", "Gamma"]


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("FIREFLY_BRIDGE_CONFIG", str(EXAMPLE))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    sp.use_config(None)
    yield
    sp.use_config(None)


@pytest.fixture()
def ring(tmp_path: Path) -> dict:
    d = tmp_path / "keyring"
    for name in ("Beta", "Gamma"):
        sp.generate_key_file(d / f"{name.lower()}.key")
    return {"ring": sp.load_keyring_dir(d), "key": lambda n: sp.load_key(d / f"{n.lower()}.key")}


def _c(cid: int, body: str) -> dict:
    return {"id": cid, "body": body, "created_at": CREATED}


def _signed(ring: dict, body: str, signer: str = "Beta") -> str:
    return sp.sign_body(body, signer, ring["key"](signer), ts=TS)


def test_gate_refuses_signed_comment_addressed_to_someone_else(ring: dict) -> None:
    body = _signed(ring, "para: Gamma\n\nwake up\n\n— Beta\n")
    d = sp.gate_comment(_c(1, body), own_aliases=ME, roster=ROSTER, keyring=ring["ring"], owners=[])
    assert d.action == sp.GATED_NON_VIP and d.reason == "wrong_recipient"


def test_gate_refuses_wrong_recipient_in_legacy_mode_too(ring: dict) -> None:
    body = _signed(ring, "para: Gamma\n\nwake up\n\n— Beta\n")
    d = sp.gate_comment(
        _c(1, body), own_aliases=ME, roster=ROSTER, keyring=ring["ring"], owners=[], legacy_unsigned=True
    )
    assert d.action == sp.GATED_NON_VIP and d.reason == "wrong_recipient"


@pytest.mark.parametrize("para", ["Alpha", "alpha-one", "Gamma, Alpha", "**Alpha**"])
def test_gate_wakes_when_addressed_to_us(ring: dict, para: str) -> None:
    body = _signed(ring, f"para: {para}\n\nwake up\n\n— Beta\n")
    d = sp.gate_comment(_c(1, body), own_aliases=ME, roster=ROSTER, keyring=ring["ring"], owners=[])
    assert d.action == sp.WAKE


def test_gate_unaddressed_comment_unchanged(ring: dict) -> None:
    body = _signed(ring, "wake up\n\n— Beta\n")
    d = sp.gate_comment(_c(1, body), own_aliases=ME, roster=ROSTER, keyring=ring["ring"], owners=[])
    assert d.action == sp.WAKE


def test_verify_comment_expected_recipient(ring: dict) -> None:
    other = _c(1, _signed(ring, "para: Gamma\n\nhi\n\n— Beta\n"))
    mine = _c(2, _signed(ring, "para: Alpha\n\nhi\n\n— Beta\n"))
    assert sp.verify_comment(other, ring["ring"], expected_recipient=ME).auth == "wrong_recipient"
    assert sp.verify_comment(mine, ring["ring"], expected_recipient=ME).verified
    # default (no expected recipient): previous behaviour, no binding
    assert sp.verify_comment(other, ring["ring"]).verified


def test_recipient_header_above_trailer_cannot_be_edited(ring: dict) -> None:
    body = _signed(ring, "para: Gamma\n\nhi\n\n— Beta\n").replace("para: Gamma", "para: Alpha")
    assert sp.verify_comment(_c(1, body), ring["ring"], expected_recipient=ME).auth == "bad_mac"


def test_wrong_recipient_still_records_nonce(ring: dict) -> None:
    body = _signed(ring, "para: Gamma\n\nhi\n\n— Beta\n")
    seen: dict[str, int] = {}
    assert sp.verify_comment(_c(1, body), ring["ring"], seen, expected_recipient=ME).auth == "wrong_recipient"
    assert sp.verify_comment(_c(2, body), ring["ring"], seen).auth == "replayed_nonce"
