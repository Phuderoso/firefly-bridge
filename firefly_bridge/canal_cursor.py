"""Unified channel canal cursor (watermark) helper.

Schema (one file per addressee set)::

    ~/.grok/channel/last_seen_<canonical>.json
    {"last_id": <int>, "updated_at": "<iso8601>"}

``canonical`` is the sorted, lowercased, comma-joined alias list with
non ``[a-z0-9_-]`` folded to ``_`` (``peerb,peera`` and ``peera,peerb`` share
``last_seen_peera_peerb.json``). Writes are monotonic: a smaller id is ignored.

``scripts/channel-gh`` currently keeps its own ``cursor_path`` /
``read_cursor`` / ``write_cursor`` (same filename convention under
``~/.grok/channel/``). Callers should share this helper.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_STATE_DIR = Path.home() / ".grok" / "channel"


def default_state_dir() -> Path:
    override = os.environ.get("CHANNEL_STATE_DIR", "").strip()
    if override:
        return Path(os.path.expanduser(os.path.expandvars(override)))
    return DEFAULT_STATE_DIR


def canonical_alias_key(aliases: list[str]) -> str:
    """Sorted lower names joined — ``peerb,peera`` and ``peera,peerb`` share a cursor."""
    parts = sorted({a.strip().lower() for a in aliases if a and a.strip()})
    return ",".join(parts) if parts else "default"


def cursor_path(state_dir: Path | str, aliases: list[str]) -> Path:
    """``last_seen_<canonical>.json`` under ``state_dir``."""
    slug = re.sub(r"[^a-z0-9_-]+", "_", canonical_alias_key(aliases).strip().lower()) or "default"
    return Path(state_dir) / f"last_seen_{slug}.json"


def read_cursor(path: Path) -> int | None:
    """Return the stored ``last_id``, or None if missing/invalid."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = data.get("last_id") if isinstance(data, dict) else None
    return int(value) if isinstance(value, int) else None


def write_cursor(path: Path, last_id: int) -> None:
    """Store ``last_id``. Monotonic: ignore writes that would go backwards."""
    last_id = int(last_id)
    current = read_cursor(path)
    if current is not None and current >= last_id:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(
            {"last_id": last_id, "updated_at": datetime.now(UTC).isoformat()},
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)
