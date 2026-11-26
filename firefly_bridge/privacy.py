"""Fail-closed sanitization. Logs deliberately omit arbitrary tool/model content."""

from __future__ import annotations

import math
import re
import unicodedata

OMIT = frozenset(
    {
        "body",
        "text",
        "outbound_text",
        "rawInput",
        "command",
        "title",
        "paths",
        "path",
        "content",
        "result",
        "key",
        "mac",
        "password",
        "secret",
        "token",
        "api_key",
        "authorization",
        "cookie",
    }
)
PATTERNS = (
    (
        re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S),
        "[PRIVATE_KEY]",
    ),
    (re.compile(r"(?i)\b(?:bearer\s+)[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|token|password|secret|authorization|cookie)\s*[=:]\s*[^\s,;]+"
        ),
        "[REDACTED]",
    ),
    (re.compile(r"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{8,}"), "[REDACTED]"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{8,}"), "pypi-[REDACTED]"),
    (re.compile(r"(?:/Users/[^/\s]+/|/home/[^/\s]+/|~/)[^\s`'\"<>]+"), "[REDACTED-PATH]"),
    (re.compile(r"https?://[^/@\s:]+:[^/@\s]+@"), "https://[REDACTED]@"),
)


def redact_text(text: str) -> str:
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# These are protocol metadata, not model/tool content. Preserve only validated
# fields, independently of the fallible free-text redactor. Never whitelist text.
IDENTIFIER_FIELDS = frozenset(
    {
        "message_id",
        "turn_id",
        "session_id",
        "requested_session_id",
        "verified_session_id",
        "in_flight",
        "prompt_id",
    }
)
_AGENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
ENUM_FIELDS = {
    "adapter_mode": {"attested", "stock_grok"},
    "queue_state": {
        "queued",
        "in_flight",
        "unknown",
        "delivered",
        "cancelled",
        "failed",
        "closed",
        "cancel_requested",
        "refused",
    },
    "remote_state": {"idle", "busy", "unknown"},
    "stop_reason": {"end_turn", "cancelled", "max_tokens", "refusal"},
    "permission_mode": {
        "pending",
        "allowlist",
        "allowlist_shared",
        "allow_all",
        "allow_all_own_turns",
    },
}
CODE_FIELDS = frozenset(
    {"reason", "event", "action", "reply_recovery", "kind", "error", "phase", "policy_version"}
)


def protocol_metadata(key, value):
    if not isinstance(value, str):
        return False
    if key == "timezone":
        return bool(re.fullmatch(r"[A-Za-z0-9_+-]{1,32}(?:/[A-Za-z0-9_+-]{1,48}){0,2}", value))
    if key == "sender":
        return bool(_AGENT_NAME.fullmatch(value))
    if key == "actor":
        return value in {"human", "recipient"} or bool(_AGENT_NAME.fullmatch(value))
    if key.endswith("_local"):
        return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", value))
    if key.endswith("sha256"):
        return bool(re.fullmatch(r"[0-9a-f]{64}", value))
    if key in IDENTIFIER_FIELDS:
        return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", value))
    if key in ENUM_FIELDS:
        return value in ENUM_FIELDS[key]
    if key in CODE_FIELDS:
        return bool(re.fullmatch(r"[a-z][a-z0-9_]{0,95}", value))
    return False


class _RenderedText(str):
    """Internal marker: content already redacted, never reconstructed from IPC JSON."""


def render_content(text: str):
    """Return text + success, so callers can trigger bounded history recovery."""
    try:
        rendered = redact_text(text)
        if not isinstance(rendered, str):
            raise TypeError("redactor_must_return_text")
        return _RenderedText(rendered), True
    except Exception:
        return "[REDACTION_FAILED]", False


def safe(value):
    """Never fall back to raw text if a regex/export operation fails."""
    try:
        if isinstance(value, dict):
            return {
                str(k): (
                    "[OMITTED]"
                    if str(k).lower() in {x.lower() for x in OMIT}
                    else v
                    if protocol_metadata(k, v)
                    else safe(v)
                )
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [safe(v) for v in value]
        if isinstance(value, _RenderedText):
            return value
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, float) and not math.isfinite(value):
            return None
        if value is None or isinstance(value, (int, float, bool)):
            return value
        return "[OMITTED]"
    except Exception:
        return "[REDACTION_FAILED]"


def validate_body(body: str, max_bytes: int) -> str:
    if not isinstance(body, str) or not body.strip() or len(body) > 8000:
        raise ValueError("body_invalid_or_too_long")
    if len(body.encode("utf-8")) > max_bytes:
        raise ValueError("body_bytes_exceeded")
    # Prevent terminal escape, carriage-return erasure and bidi header spoofing.
    if any(unicodedata.category(c).startswith("C") and c not in "\n\t" for c in body):
        raise ValueError("body_presentation_controls_forbidden")
    return body
