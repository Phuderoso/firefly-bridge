"""Test-only HMAC keyring and signed canal bodies.

Keys are generated under a tmp path in the test process. Never a real deployment key,
never a committed secret. Trailer ts is pinned so tests need no sleep.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from firefly_bridge import speaker as sp

# Same epoch the presence tests use (2025-11-14T15:40:00Z).
SIG_TS = 1_763_130_000
CREATED_AT = datetime.fromtimestamp(SIG_TS, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
DEFAULT_NAMES = (
    "agent-a",
    "agent-b",
    "agent-c",
    "agent-d",
    "owner",
    "ownernick",
    "ownerlogin",
    "peerx",
)


def make_keyring(tmp_path: Path, names: tuple[str, ...] = DEFAULT_NAMES) -> dict:
    """Return ``{"dir", "ring", "key"}`` with a fresh 0600 key per name under tmp_path."""
    d = Path(tmp_path) / "test-keyring"
    d.mkdir(parents=True, exist_ok=True)
    for name in names:
        sp.generate_key_file(d / f"{name.lower()}.key")
    ring = sp.load_keyring_dir(d)
    return {"dir": d, "ring": ring, "key": lambda n, _ring=ring: _ring[sp.norm_name(n)]}


def signed_body(ring: dict, sender: str, text: str = "oi peerb", *, ts: int = SIG_TS) -> str:
    body = f"para: peerb\n\n{text}\n\n— {sender}\n"
    return sp.sign_body(body, sender, ring["key"](sender), ts=ts)


def signed_kwargs(ring: dict, sender: str, text: str = "oi peerb", **extra) -> dict:
    """Kwargs for ``wake_decision``: verified trailer for ``sender``."""
    body = signed_body(ring, sender, text)
    return {"body": body, "keyring": ring["ring"], "created_at": CREATED_AT, **extra}


def keyring_config_lines(ring: dict) -> str:
    return f'[channel_keyring]\ndir = "{ring["dir"]}"\n'
