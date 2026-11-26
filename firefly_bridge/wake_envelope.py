"""Canal/wake body envelope: recado vs tool_request.

Wake delivers text. It is not a click on peerb's tools. ``kind: recado`` is the
default. ``kind: tool_request`` is still only a text ask; it must never auto-
answer ``session/request_permission``. The word "channel" does not grant
tool approval. Unknown kinds fail closed to recado.

See docs/WAKE_VS_TOOL.md.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from firefly_bridge.permissions import cancelled_result, denied_decision, selected_result
from firefly_bridge.privacy import redact_text
from firefly_bridge.speaker import resolve_speaker

KIND_RECADO = "recado"
KIND_TOOL_REQUEST = "tool_request"
KNOWN_KINDS = frozenset({KIND_RECADO, KIND_TOOL_REQUEST})
WAKE_ORIGIN_DENY_REASON = "wake_origin_tool_denied"
WAKE_BODY_MARK = "[channel-wake"

_HEADER_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,32}$")
_SIGNATURE = re.compile(r"^\s*(?:—|--|–)\s+\S")
_CANAL_KEYS = frozenset({"para", "to", "de", "from"})

DEFAULT_PENDING_CARD = "~/.grok/channel/pending_card.json"


@dataclass
class WakeEnvelope:
    """Parsed canal/wake body. Delivery is always text."""

    kind: str = KIND_RECADO
    text: str = ""
    raw: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def is_recado(self) -> bool:
        return self.kind == KIND_RECADO

    @property
    def is_tool_request(self) -> bool:
        return self.kind == KIND_TOOL_REQUEST

    @property
    def speaker(self) -> str:
        """Canal speaker from the raw body (shared parse: marker > `de:` > signature)."""
        return resolve_speaker(self.raw).name

    @property
    def auto_answer_permission(self) -> bool:
        """Never. tool_request is a text ask; recado is text only."""
        return False

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "auto_answer_permission": False,
            "from": self.speaker or self.meta.get("from") or self.meta.get("de") or None,
            "tool": self.meta.get("tool") or self.meta.get("tool_name"),
            "unknown_kind": self.meta.get("unknown_kind"),
        }


def _normalize_kind(raw: object) -> tuple[str, str | None]:
    if not isinstance(raw, str):
        return KIND_RECADO, "non_string_kind_treated_as_recado"
    kind = raw.strip().lower()
    if kind in KNOWN_KINDS:
        return kind, None
    return KIND_RECADO, kind or "empty_kind_treated_as_recado"


def _leading_headers(text: str) -> tuple[dict[str, str], str]:
    """Read up to two leading ``key: value`` groups (canal wrap + envelope)."""
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    headers: dict[str, str] = {}
    groups = 0
    while groups < 2 and i < len(lines):
        consumed = 0
        while i < len(lines):
            raw_line = lines[i]
            if not raw_line.strip():
                i += 1
                break
            if _SIGNATURE.match(raw_line):
                return headers, "\n".join(lines[i:]).strip("\n")
            if ":" not in raw_line or raw_line.startswith(" ") or raw_line.startswith("\t"):
                return headers, "\n".join(lines[i:]).strip("\n")
            key, _, val = raw_line.partition(":")
            key_n = key.strip()
            if not _HEADER_KEY.match(key_n):
                return headers, "\n".join(lines[i:]).strip("\n")
            headers[key_n.lower()] = val.strip()
            consumed += 1
            i += 1
            if consumed >= 24:
                return headers, "\n".join(lines[i:]).strip("\n")
        if consumed:
            groups += 1
        else:
            break
    return headers, "\n".join(lines[i:]).strip("\n")


def _from_mapping(obj: dict, raw: str) -> WakeEnvelope:
    kind, unknown = _normalize_kind(obj.get("kind"))
    text = obj.get("text")
    if not isinstance(text, str):
        text = raw
    meta = {
        k: v
        for k, v in obj.items()
        if k not in {"kind", "text"} and isinstance(v, (str, int, bool))
    }
    if unknown:
        meta["unknown_kind"] = unknown
    return WakeEnvelope(kind=kind, text=text, raw=raw, meta=meta)


def body_marks_wake_origin(body: str | None) -> bool:
    """True when the body is a knock/wake marker, even without an IPC flag."""
    text = body if isinstance(body, str) else ""
    return text.lstrip().startswith(WAKE_BODY_MARK)


def count_wake_origin_denied(events) -> int:
    """Count receipt permission_events that are wake-origin denies.

    Prefer ``phase=response_sent`` so decision_intent + response_sent do not
    double-count. Fall back to any matching reason if the response was not logged.
    """
    rows = [e for e in (events or []) if isinstance(e, dict)]
    denied = [e for e in rows if e.get("reason") == WAKE_ORIGIN_DENY_REASON]
    sent = [e for e in denied if e.get("phase") == "response_sent"]
    return len(sent) if sent else len(denied)


def parse_wake_envelope(body: str | None) -> WakeEnvelope:
    """Classify a canal/wake body. Default ``kind`` is recado (text only)."""
    raw = body if isinstance(body, str) else ""
    stripped = raw.strip()
    if not stripped:
        return WakeEnvelope(kind=KIND_RECADO, text="", raw=raw, meta={})

    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and "kind" in obj:
            return _from_mapping(obj, raw)

    headers, rest = _leading_headers(raw)
    if "kind" in headers:
        kind, unknown = _normalize_kind(headers.get("kind"))
        meta = {k: v for k, v in headers.items() if k != "kind"}
        if unknown:
            meta["unknown_kind"] = unknown
        text = rest if rest.strip() else raw
        return WakeEnvelope(kind=kind, text=text, raw=raw, meta=meta)

    # Canal wrap with no kind header is still a recado.
    if headers and any(k in _CANAL_KEYS for k in headers):
        meta = dict(headers)
        return WakeEnvelope(kind=KIND_RECADO, text=rest if rest.strip() else raw, raw=raw, meta=meta)

    return WakeEnvelope(kind=KIND_RECADO, text=raw, raw=raw, meta={})


def wake_origin_permission_decision(request: dict):
    """Always deny. A wake is not a tool click, even for kind: tool_request."""
    return denied_decision(request, WAKE_ORIGIN_DENY_REASON)


def wake_origin_permission_result(request: dict) -> dict:
    """JSON-RPC result for a wake-origin permission: reject_once or cancel.

    Never selects allow_once / allow_always. Missing reject_once becomes
    cancelled, not silence, so a clickable Allow does not sit on the TUI.
    """
    decision = wake_origin_permission_decision(request)
    if decision.option_id:
        return selected_result(decision.option_id)
    return cancelled_result()


def pending_card_from_request(
    request: dict,
    *,
    envelope: WakeEnvelope | None = None,
    message_id: str | None = None,
    sender: str | None = None,
    now_epoch: float | None = None,
) -> dict:
    """Named card: who asked, which tool. Status is denied, not Allow."""
    decision = wake_origin_permission_decision(request)
    ts = time.time() if now_epoch is None else float(now_epoch)
    stamp = datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")  # noqa: UP017
    env = envelope or WakeEnvelope()
    # The bridge principal (IPC-authenticated) wins; else the canal speaker of the body.
    who = sender or env.speaker or env.meta.get("from") or env.meta.get("de") or ""
    paths = [redact_text(p)[:240] for p in (decision.paths or [])]
    return {
        "status": "denied",
        "reason": WAKE_ORIGIN_DENY_REASON,
        "action": "deny",
        "message_id": message_id or "",
        "from": who,
        "envelope_kind": env.kind,
        "tool_kind": decision.tool_kind,
        "title": redact_text(str(decision.title or ""))[:180],
        "paths": paths,
        "option_id": decision.option_id,
        "ts": stamp,
        "note": (
            "Wake-origin tool. agent-a never Allow. Named card, not a TUI click. "
            "kind: tool_request is text; peerb decides after she is awake."
        ),
    }


def write_pending_card(path: str | Path, card: dict) -> Path:
    """Atomic 0600 write. Parent dir 0700. Does not raise on empty path."""
    target = Path(os.path.expandvars(os.path.expanduser(str(path))))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(card, sort_keys=True, ensure_ascii=False) + "\n"
    # Unique tmp in the same dir: concurrent writers never share or clobber it.
    fd, tmp = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
    try:
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def count_real_approvals(events) -> int:
    """Allows actually sent. Daemon events say ``approve``; older ones ``allow_once``/``allow_always``."""
    return sum(
        1
        for e in (events or [])
        if isinstance(e, dict)
        and e.get("phase") == "response_sent"
        and e.get("action") in ("approve", "allow_once", "allow_always")
    )


def count_permission_requests(events) -> int:
    """Distinct permission requests (intent + response are one request)."""
    rows = [e for e in (events or []) if isinstance(e, dict)]
    keyed = {(e.get("turn_id"), e.get("request_sha256")) for e in rows if e.get("request_sha256")}
    if keyed:
        return len(keyed)
    intents = [e for e in rows if e.get("phase") == "decision_intent"]
    return len(intents) if intents else len(rows)
