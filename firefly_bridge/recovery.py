"""Read-only chat_history recovery seam. NO Grok API is assumed or invoked.

Only a separately proven, authorized adapter may implement this interface. The
shipping adapter is a fail-closed stub. Queries always name the exact attested
origin, never latest/global history, files, screens, or a new prompt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ReplyLocator:
    session_id: str
    incarnation: str
    turn_id: str
    initiator: str
    message_id: str
    sender: str
    nonce: str
    max_bytes: int


@dataclass(frozen=True)
class HistoryReply:
    locator: ReplyLocator
    text: str


class RecoveryUnavailable(RuntimeError):
    pass


class ChatHistory(Protocol):
    proven_read_only: bool

    def recover_reply(self, locator: ReplyLocator) -> HistoryReply | None: ...


class UnavailableChatHistory:
    """Default: there is no proven read-only chat_history API in this package."""

    proven_read_only = False

    def recover_reply(self, locator: ReplyLocator) -> HistoryReply | None:
        raise RecoveryUnavailable("no_proven_chat_history_api")


def recover_reply(history: ChatHistory, locator: ReplyLocator) -> str | None:
    try:
        if history.proven_read_only is not True:
            return None
        reply = history.recover_reply(locator)
        if (
            not isinstance(reply, HistoryReply)
            or reply.locator != locator
            or not isinstance(reply.text, str)
            or not reply.text
            or len(reply.text.encode("utf-8")) > locator.max_bytes
        ):
            return None
        return reply.text
    except Exception:
        # Never log/echo raw history errors. No alternate API, prompt or resend.
        return None
