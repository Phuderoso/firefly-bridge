"""Local receipt model. Outcomes name this bridge, not a hidden Grok ack."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

SOURCE = "agent-a"
OUTCOMES = ("prepared", "transport-accepted", "responded", "unknown")

# JSON-RPC methods this client is willing to send. session/load is documented
# as history replay and is intentionally absent: it is not live attachment.
ALLOWED_CLIENT_METHODS = frozenset({"session/prompt"})

FORBIDDEN_CLIENT_METHODS = frozenset(
    {
        "session/new",
        "session/load",
        "session/fork",
        "session/resume",
        "session/cancel",
        "session/close",
        "session/set_config_option",
        "authenticate",
        "x.ai/session/fork",
    }
)

_REJECT_IDS = frozenset(
    {
        "",
        "latest",
        "continue",
        "new",
        "resume",
        "fork",
        "current",
        "last",
    }
)


class SessionPinError(ValueError):
    pass


class AttributionError(ValueError):
    pass


class DuplicateMessage(ValueError):
    pass


class AlreadySettled(ValueError):
    pass


class ConflictingMessage(ValueError):
    pass


class EmptyText(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()  # noqa: UP017


def new_message_id() -> str:
    return "id_" + uuid.uuid4().hex


def validate_session_id(session_id: str | None) -> str:
    if session_id is None or not isinstance(session_id, str):
        raise SessionPinError("session_id_required")
    if session_id != session_id.strip() or any(ch.isspace() for ch in session_id):
        raise SessionPinError("session_id_invalid")
    if session_id.lower() in _REJECT_IDS:
        raise SessionPinError("session_id_not_pinned")
    if len(session_id) < 8 or len(session_id) > 200:
        raise SessionPinError("session_id_invalid")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-")
    if any(ch not in allowed for ch in session_id):
        raise SessionPinError("session_id_invalid")
    return session_id


def validate_text(text: str | None) -> str:
    if not isinstance(text, str) or text == "":
        raise EmptyText("text_required")
    if len(text) > 8000:
        raise EmptyText("text_too_long")
    return text


def validate_source(source: str) -> str:
    if source != SOURCE:
        raise AttributionError("source_must_match_sender")
    return source


@dataclass
class Receipt:
    message_id: str
    session_id: str
    source: str
    text: str
    outcome: str
    history: list[str] = field(default_factory=list)
    block_code: str | None = None
    block_detail: str | None = None
    correlation: dict = field(default_factory=dict)
    transport: str = "none"
    timeout_s: float | None = None
    resend_attempted: bool = False
    attribution_channel: str = "outbound-user-content"
    acp_speaker_field: None = None
    outbound_text: str = ""
    attempt_committed: bool = False
    notes: list[str] = field(default_factory=list)
    permission: dict | None = None

    def transition(self, outcome: str) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(outcome)
        self.outcome = outcome
        if not self.history or self.history[-1] != outcome:
            self.history.append(outcome)

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "session_id": self.session_id,
            "source": self.source,
            "text": self.text,
            "outcome": self.outcome,
            "history": list(self.history),
            "block_code": self.block_code,
            "block_detail": self.block_detail,
            "correlation": self.correlation,
            "transport": self.transport,
            "timeout_s": self.timeout_s,
            "resend_attempted": self.resend_attempted,
            "attribution_channel": self.attribution_channel,
            "acp_speaker_field": self.acp_speaker_field,
            "outbound_text": self.outbound_text,
            "attempt_committed": self.attempt_committed,
            "notes": list(self.notes),
            "permission": self.permission,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Receipt:
        history = data.get("history")
        if not isinstance(history, list) or not history:
            history = [data.get("outcome") or "prepared"]
        return cls(
            message_id=data["message_id"],
            session_id=data["session_id"],
            source=data["source"],
            text=data["text"],
            outcome=data["outcome"],
            history=list(history),
            block_code=data.get("block_code"),
            block_detail=data.get("block_detail"),
            correlation=dict(data.get("correlation") or {}),
            transport=data.get("transport") or "none",
            timeout_s=data.get("timeout_s"),
            resend_attempted=False,
            attribution_channel=data.get("attribution_channel") or "outbound-user-content",
            outbound_text=data.get("outbound_text") or "",
            attempt_committed=bool(data.get("attempt_committed")),
            notes=list(data.get("notes") or []),
            permission=data.get("permission"),
        )
