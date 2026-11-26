"""Optional per-message authenticity: HMAC-SHA256 signed trailer.

The plain ``agent-a: `` prefix is attribution only: anything that can write to
the leader socket can type it. In ``hmac`` mode the bridge appends one trailer
line to the outbound text::

    agent-a: <body>

    [msgsig v=1 from=agent-a id=id_... sid=<session> ts=<unix> nonce=<hex> mac=<hex>]

``mac`` is HMAC-SHA256 over a canonical string that binds the sender, session
id, message id, timestamp, nonce and the SHA-256 of the exact body. The key is a
shared secret in a file that must be mode 0600 (owner-only). A receiver that has
the same key file can verify with ``firefly-bridge verify`` or
:func:`verify_text`. Verification is opt-in on the receiving side; a model that
never runs the verifier gets nothing from the signature.

Limits (also in THREAT_MODEL.md): anyone who can read the key file can forge;
same-user processes can usually read it. Replay protection is a timestamp
window plus an optional seen-nonce set kept by the verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from firefly_bridge.speaker import _read_key_file_once

VERSION = "1"
_TRAILER_RE = re.compile(
    r"\n\n\[msgsig v=(?P<v>\d+) from=(?P<from>\S+) id=(?P<id>\S+) sid=(?P<sid>\S+) "
    r"ts=(?P<ts>\d+) nonce=(?P<nonce>[0-9a-f]{16,64}) mac=(?P<mac>[0-9a-f]{64})\]\s*\Z"
)
MIN_KEY_BYTES = 32


class KeyFileError(ValueError):
    pass


def generate_key_file(path: str | Path, *, overwrite: bool = False) -> Path:
    """Create a random 32-byte hex key with mode 0600. Never prints the key."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise KeyFileError("key_file_exists") from exc
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (secrets.token_hex(32) + "\n").encode("ascii"))
    finally:
        os.close(fd)
    return target


def load_key(path: str | Path) -> bytes:
    """Read a key file, refusing group/other-accessible files, symlinks and short keys.

    The file is opened once and checked and read through that descriptor (no TOCTOU).
    """
    target = Path(path).expanduser()
    raw, reason = _read_key_file_once(target)
    if raw is None:
        raise KeyFileError(
            {
                "missing": "key_file_missing",
                "not_regular": "key_file_not_regular",
                "unreadable": "key_file_unreadable",
                "too_large": "key_file_too_large",
                "mode": "key_file_permissions_too_open_need_0600",
                "owner": "key_file_not_owned_by_user",
            }[reason]
        )
    raw = raw.strip()
    if len(raw) < MIN_KEY_BYTES:
        raise KeyFileError("key_too_short")
    return raw


def _canonical(
    sender: str, session_id: str, message_id: str, ts: int, nonce: str, body: str
) -> bytes:
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return "\n".join(
        ["msgsig", VERSION, sender, session_id, message_id, str(ts), nonce, digest]
    ).encode("utf-8")


def _check_token(name: str, value: str) -> str:
    if not value or any(ch.isspace() or ch in "[]=" for ch in value):
        raise ValueError(f"{name}_invalid_for_trailer")
    return value


def sign_text(
    key: bytes,
    *,
    prefix: str,
    sender: str,
    session_id: str,
    message_id: str,
    body: str,
    ts: int | None = None,
    nonce: str | None = None,
) -> str:
    """Return ``prefix + body`` followed by a signed trailer line."""
    _check_token("sender", sender)
    _check_token("session_id", session_id)
    _check_token("message_id", message_id)
    ts = int(time.time()) if ts is None else int(ts)
    nonce = nonce or secrets.token_hex(12)
    mac = hmac.new(key, _canonical(sender, session_id, message_id, ts, nonce, body), hashlib.sha256)
    trailer = (
        f"[msgsig v={VERSION} from={sender} id={message_id} sid={session_id} "
        f"ts={ts} nonce={nonce} mac={mac.hexdigest()}]"
    )
    return f"{prefix}{body}\n\n{trailer}"


@dataclass
class Verification:
    valid: bool
    reason: str
    sender: str | None = None
    message_id: str | None = None
    session_id: str | None = None
    ts: int | None = None
    body: str | None = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "sender": self.sender,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "ts": self.ts,
        }


def verify_text(
    key: bytes,
    text: str,
    *,
    prefix: str = "agent-a: ",
    expected_sender: str | None = None,
    expected_session_id: str | None = None,
    max_age_s: float | None = 3600,
    now: float | None = None,
    seen_nonces: set | None = None,
) -> Verification:
    """Verify a signed message as received (the full user text block)."""
    match = _TRAILER_RE.search(text)
    if not match:
        return Verification(False, "no_signature_trailer")
    if match.group("v") != VERSION:
        return Verification(False, "unsupported_version")
    head = text[: match.start()]
    if not head.startswith(prefix):
        return Verification(False, "prefix_mismatch")
    body = head[len(prefix) :]
    sender, mid, sid = match.group("from"), match.group("id"), match.group("sid")
    ts, nonce = int(match.group("ts")), match.group("nonce")
    expected = hmac.new(
        key, _canonical(sender, sid, mid, ts, nonce, body), hashlib.sha256
    ).hexdigest()
    base = dict(sender=sender, message_id=mid, session_id=sid, ts=ts)
    if not hmac.compare_digest(expected, match.group("mac")):
        return Verification(False, "bad_mac", **base)
    if expected_sender is not None and sender != expected_sender:
        return Verification(False, "sender_mismatch", **base)
    if expected_session_id is not None and sid != expected_session_id:
        return Verification(False, "session_mismatch", **base)
    current = time.time() if now is None else now
    if max_age_s is not None and abs(current - ts) > max_age_s:
        return Verification(False, "outside_time_window", **base)
    if seen_nonces is not None:
        if nonce in seen_nonces:
            return Verification(False, "replayed_nonce", **base)
        seen_nonces.add(nonce)
    return Verification(True, "ok", body=body, **base)
