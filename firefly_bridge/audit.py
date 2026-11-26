"""Content-minimal audit metadata. Tool/target IDs are fingerprints, not raw input."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from zoneinfo import ZoneInfo

LOCAL_ZONE = "UTC"


def local_time(epoch):
    return (
        None
        if epoch is None
        else datetime.fromtimestamp(epoch, ZoneInfo(LOCAL_ZONE)).isoformat(timespec="seconds")
    )


def fingerprint(value):
    try:
        encoded = json.dumps(
            value, sort_keys=True, ensure_ascii=True, default=lambda _: "[UNSUPPORTED]"
        ).encode()
    except (ValueError, TypeError, RecursionError, UnicodeError):
        encoded = b"[UNFINGERPRINTABLE]"
    return hashlib.sha256(encoded).hexdigest()


def tool_metadata(request, decision, base_dir):
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    tool = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
    raw = tool.get("rawInput", {})
    canonicalized = True
    try:
        paths = [
            os.path.realpath(p if os.path.isabs(p) else os.path.join(base_dir, p))
            for p in decision.paths
        ]
    except (OSError, ValueError, TypeError):
        paths = list(decision.paths)
        canonicalized = False
    kind = (
        decision.tool_kind
        if isinstance(decision.tool_kind, str)
        and decision.tool_kind
        in {"read", "edit", "delete", "execute", "search", "fetch", "other", "think", "switch_mode"}
        else "unknown"
    )
    return {
        "tool": {
            "kind": kind,
            "identity_sha256": fingerprint(
                [tool.get("name"), tool.get("toolName"), tool.get("title"), tool.get("toolCallId")]
            ),
        },
        "target": {
            "kind": "file" if paths else "opaque",
            "count": len(paths),
            "canonicalized": canonicalized,
            "sha256": fingerprint(paths if paths else raw),
        },
        "rpc_id_sha256": fingerprint(request.get("id")),
        "tool_call_id_sha256": fingerprint(tool.get("toolCallId")),
        "policy_version": "protected_tools_v1",
    }
