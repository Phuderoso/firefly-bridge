"""Issue #22: presence.wake_decision binds a signed comment to its `para:` recipient.

Since #21 gate_comment refuses a validly signed comment addressed to someone else
(`wrong_recipient`). wake_decision must do the same, for claims and dry runs, and must not
spend the nonce. Neutral names only.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import speaker as sp

ROOT = Path(__file__).resolve().parents[1]
TS = 1_763_130_000
NOW = float(TS)


@pytest.fixture
def env(tmp_path: Path):
    sp.use_config(ROOT / "examples/config.example.toml")
    d = tmp_path / "keyring"
    sp.generate_key_file(d / "beta.key")
    ring = sp.load_keyring_dir(d)
    store = tmp_path / "state" / "nonces.json"
    store.parent.mkdir(mode=0o700)
    base = dict(
        target="Alpha",
        own_aliases=["Alpha", "Alpha-One"],
        roster=["Beta"],
        now=NOW,
        sources=[lambda n: pr.PresenceRecord(n, NOW, "idle")],
        cfg=pr.PresenceConfig(terminals={"alpha": str(tmp_path / "hb.json")}),
        keyring=ring,
        nonce_store=store,
        legacy_unsigned=False,
    )
    yield ring, base, store
    sp.use_config(None)


def _body(ring: dict, para: str | None) -> str:
    head = f"para: {para}\n\n" if para else ""
    return sp.sign_body(f"{head}wake up\n\n— Beta\n", "Beta", ring["beta"], ts=TS)


def _decide(env, body: str, **kw) -> pr.PresenceDecision:
    _, base, _ = env
    created = datetime.fromtimestamp(TS, UTC).isoformat()
    return pr.wake_decision("Beta", **dict(base, body=body, created_at=created, **kw))


@pytest.mark.parametrize("claim", [True, False])
def test_comment_signed_for_someone_else_never_wakes(env, claim: bool) -> None:
    ring, _, store = env
    d = _decide(env, _body(ring, "Gamma"), claim=claim)
    assert d.action == sp.GATED_NON_VIP and d.reason == "wrong_recipient"
    if store.exists():
        assert json.loads(store.read_text()).get("nonces", {}) == {}  # nonce not spent


def test_wrong_recipient_in_legacy_mode_never_wakes(env) -> None:
    ring, _, _ = env
    d = _decide(env, _body(ring, "Gamma"), legacy_unsigned=True)
    assert d.action == sp.GATED_NON_VIP and d.reason == "wrong_recipient"


@pytest.mark.parametrize("para", ["Alpha", "alpha-one", "Gamma, Alpha", None])
def test_addressed_or_unaddressed_comment_still_wakes(env, para) -> None:
    ring, _, _ = env
    assert _decide(env, _body(ring, para)).action == sp.WAKE
