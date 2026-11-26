"""On-disk persistence for ``firefly_bridge.queue.Outbox`` (optional, fail-closed).

When a state path is configured, the outbox writes pending and completed turns to one
JSON file so a daemon restart can reload the queue. Without a path, this module is unused
and the outbox stays memory-only.

The file never stores HMAC keys, tokens, or other secrets. Pending turns keep ``body``
(unsigned). Signatures (``[msgsig ...]`` / ``channel-sig``) and ``outbound_text`` are not
persisted: the caller re-signs on send after a restart. Completed turns keep only
``message_id``, terminal ``state``, ``settled_at`` and ``body_sha256``. ``result`` and
permission cards are omitted.

Writes are atomic (tmp in the same directory + fsync + replace + best-effort directory
fsync), mode 0600, under an exclusive flock on a sibling ``.lock``. Times are stored
relative to ``saved_at`` (the outbox clock). On load, if the live clock is still in the
same epoch (``now() >= saved_at``), absolute times are restored (``saved_at + rel``) so a
continuing clock keeps the original due instant. If the clock reset (new monotonic epoch),
the remaining interval is applied to ``now``, minus elapsed wall time from ``saved_wall``
(``time.time()``, injectable) so a mid-backoff restart does not wait the full interval again.

A missing file is an empty queue (first run). A leftover ``.tmp`` is ignored. An
unreadable or invalid file is not deleted: it is renamed to ``<name>.corrupt-<ts>``
(`int(now())` of the outbox clock), the queue starts empty, and a log is emitted.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import stat
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

QUEUE_STATE_VERSION = 2
ACCEPTED_STATE_VERSIONS = (1, 2)
QUEUE_SECTION = "channel_queue"
MAX_STATE_BYTES = 1_048_576  # 1 MiB; a bigger file is treated as corrupt
_FILE_MODE = 0o600
_LOCK_MODE = 0o600
_LOG = logging.getLogger("firefly_bridge.queue")

# Allowlisted keys only. Never persist or reload a secret field name.
PENDING_FIELDS = (
    "message_id",
    "session_id",
    "body",
    "sender",
    "turn_id",
    "generation",
    "wake_origin",
    "state",
    "reason",
    "attempts",
    "presence_action",
    "route",
    "enqueued_at",
    "next_attempt_at",
    "started_at",
    "settled_at",
    "deadline",
)
COMPLETED_FIELDS = (
    "message_id",
    "state",
    "settled_at",
    "body_sha256",
)
# Relative-time keys: stored as (value - saved_at). Restore depends on the clock epoch.
_TIME_KEYS = frozenset({"enqueued_at", "next_attempt_at", "started_at", "settled_at", "deadline"})
_SECRET_KEYS = frozenset({
    "key",
    "mac",
    "password",
    "secret",
    "token",
    "api_key",
    "authorization",
    "cookie",
    "hmac_key",
    "hmac_key_file",
    "ipc_key",
    "ipc_key_file",
})


class QueueStoreError(Exception):
    pass


def parse_queue_config_text(text: str) -> str | None:
    """Return ``state_path`` from ``[channel_queue]``, or None if unset/blank."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - py<3.11
        return None
    try:
        table = tomllib.loads(text).get(QUEUE_SECTION) or {}
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("config_toml_invalid") from exc
    if not isinstance(table, dict):
        raise ValueError("queue_section_must_be_table")
    raw = table.get("state_path")
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ValueError("queue_state_path_must_be_string")
    return os.path.expanduser(raw.strip()) or None


def load_queue_state_path(config_path: str | Path | None) -> str | None:
    """Read ``[channel_queue].state_path`` from a config file. Missing file => None."""
    if not config_path:
        return None
    path = Path(config_path).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return parse_queue_config_text(text)


def _try_flock(fd: int, acquire: bool) -> bool:
    """Return True if the lock was taken/released. Raise QueueStoreError if flock exists and fails.

    When ``fcntl`` is missing (non-Unix), return False and let the caller warn: the write
    proceeds unlocked, documented as best-effort only.
    """
    try:
        import fcntl
    except ImportError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if acquire else fcntl.LOCK_UN)
        return True
    except OSError as exc:
        raise QueueStoreError(f"queue_state_flock_failed:{exc}") from exc


@contextlib.contextmanager
def _exclusive_lock(lock_path: Path, *, log=None):
    parent = lock_path.parent
    if not parent.is_dir():
        raise FileNotFoundError("queue_state_dir_missing")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(str(lock_path), flags, _LOCK_MODE)
    held = False
    try:
        try:
            os.chmod(str(lock_path), _LOCK_MODE)
        except OSError:
            pass
        try:
            held = _try_flock(fd, True)
        except QueueStoreError:
            raise
        if not held:
            msg = "outbox_state_flock_unavailable: writing without an exclusive lock"
            (log or (lambda m: _LOG.warning("%s", m)))(msg)
        yield
    finally:
        if held:
            try:
                _try_flock(fd, False)
            except QueueStoreError:
                pass
        os.close(fd)


def _fsync_dir(dirpath: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(str(dirpath), flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(dest: Path, data: bytes) -> Path:
    if not dest.parent.is_dir():
        raise FileNotFoundError("queue_state_dir_missing")
    fd, tmp = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, _FILE_MODE)
        os.replace(tmp, dest)
        tmp = ""
        _fsync_dir(dest.parent)
    except BaseException:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    return dest


def _rel_times(obj: dict, saved_at: float) -> dict:
    """Encode live clock values as offsets from saved_at for the disk payload."""
    out = {}
    for key, value in obj.items():
        if key in _TIME_KEYS:
            out[key] = None if value is None else (float(value) - saved_at)
        else:
            out[key] = value
    return out


def _restore_times(obj: dict, *, now: float, saved_at: float, wall_elapsed: float) -> dict:
    """Map disk offsets back into the live clock.

    Same epoch (now >= saved_at): restore the original absolute instant.
    Reset epoch (typical time.monotonic after a process restart): apply the remaining
    interval to now, minus wall-clock elapsed since the checkpoint.
    """
    same_epoch = now >= saved_at
    out = {}
    for key, value in obj.items():
        if key in _TIME_KEYS:
            if value is None:
                out[key] = None
            elif same_epoch:
                out[key] = saved_at + float(value)
            else:
                out[key] = now + (float(value) - wall_elapsed)
        else:
            out[key] = value
    return out


def _pick(obj: dict, fields: tuple[str, ...]) -> dict:
    clean = {k: obj[k] for k in fields if k in obj and k not in _SECRET_KEYS}
    for key in _SECRET_KEYS:
        clean.pop(key, None)
    return clean


def _valid_record(obj: object, fields: tuple[str, ...], *, require: tuple[str, ...]) -> bool:
    if not isinstance(obj, dict):
        return False
    if any(k in obj for k in _SECRET_KEYS):
        return False
    if not all(isinstance(k, str) for k in obj):
        return False
    if not all(r in obj for r in require):
        return False
    mid = obj.get("message_id")
    if not isinstance(mid, str) or not mid.strip():
        return False
    # Unknown extra keys (except secrets, already rejected) are ignored on pick.
    _ = fields
    return True



def is_state_tmp(path: Path, dest: Path) -> bool:
    """True iff ``path`` matches this state's mkstemp name: ``.{dest.name}.<id>.tmp``."""
    name = path.name
    prefix = f".{dest.name}."
    if not (name.startswith(prefix) and name.endswith(".tmp")):
        return False
    mid = name[len(prefix) : -len(".tmp")]
    return bool(mid) and "/" not in mid and mid != "."


def cleanup_orphan_tmps(dest: Path) -> list[Path]:
    """Unlink regular leftover tmp files for ``dest`` that are older than the current state file.

    If the state file does not exist yet, every matching leftover is treated as stale.
    Symlinks and names that do not match the exact mkstemp pattern are left alone.
    """
    parent = dest.parent
    if not parent.is_dir():
        return []
    try:
        current_mtime = os.lstat(dest).st_mtime
    except FileNotFoundError:
        current_mtime = float("inf")
    except OSError:
        return []
    removed: list[Path] = []
    try:
        entries = list(parent.iterdir())
    except OSError:
        return []
    for item in entries:
        if not is_state_tmp(item, dest):
            continue
        try:
            st = os.lstat(item)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_mtime >= current_mtime:
            continue
        try:
            os.unlink(item)
            removed.append(item)
        except OSError:
            continue
    return removed


def _slim_completed(rec: dict) -> dict:
    """Keep only id / terminal state / ts / body hash. Derive the hash from a legacy body."""
    import hashlib

    out = _pick(rec, COMPLETED_FIELDS)
    digest = out.get("body_sha256")
    if not digest and rec.get("body") is not None:
        digest = hashlib.sha256(str(rec.get("body") or "").encode("utf-8")).hexdigest()
        out["body_sha256"] = digest
    out.pop("body", None)
    out.pop("outbound_text", None)
    return out


class QueueStore:
    """Load and save one outbox state file. ``now`` is injectable (tests, no sleep)."""

    def __init__(
        self,
        path: str | Path,
        *,
        now: Callable[[], float],
        log: Callable[[str], None] | None = None,
        wall: Callable[[], float] | None = None,
    ) -> None:
        self.path = Path(os.path.expanduser(str(path)))
        self.lock_path = Path(str(self.path) + ".lock")
        self._now = now
        self._wall = wall or time.time
        self._log = log or (lambda msg: _LOG.error("%s", msg))

    def load(self) -> dict:
        """Return ``{"pending": [...], "completed": [...], "in_flight": None}`` in the live clock.

        On corruption the original file is renamed and this returns empty lists.
        A missing file or leftover tmp-only directory is an empty queue.
        """
        if not self.path.parent.is_dir():
            return {"pending": [], "completed": [], "in_flight": None}
        with _exclusive_lock(self.lock_path, log=self._log):
            cleanup_orphan_tmps(self.path)
            return self._load_locked()

    def save(self, *, pending: list[dict], completed: list[dict], in_flight: dict | None, clock_now: float) -> Path:
        dest = self.path
        payload = {
            "v": QUEUE_STATE_VERSION,
            "saved_at": float(clock_now),
            "saved_wall": float(self._wall()),
            "pending": [_rel_times(_pick(p, PENDING_FIELDS), clock_now) for p in pending],
            "completed": [_rel_times(_pick(c, COMPLETED_FIELDS), clock_now) for c in completed],
            "in_flight": (
                _rel_times(_pick(in_flight, PENDING_FIELDS), clock_now) if in_flight else None
            ),
        }
        data = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        if len(data) > MAX_STATE_BYTES:
            raise QueueStoreError("queue_state_too_large")
        with _exclusive_lock(self.lock_path, log=self._log):
            cleanup_orphan_tmps(dest)
            return _atomic_write(dest, data)

    def _load_locked(self) -> dict:
        empty = {"pending": [], "completed": [], "in_flight": None}
        path = self.path
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return empty
        except OSError as exc:
            self._quarantine(f"queue_state_unreadable:{exc}")
            return empty
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_STATE_BYTES:
            self._quarantine("queue_state_not_regular_or_too_large")
            return empty
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            self._quarantine("queue_state_invalid_json")
            return empty
        parsed = self._validate(obj)
        if parsed is None:
            self._quarantine("queue_state_schema_invalid")
            return empty
        now = float(self._now())
        saved_at = float(parsed["saved_at"])
        saved_wall = parsed["saved_wall"]
        wall_elapsed = 0.0 if saved_wall is None else max(0.0, float(self._wall()) - float(saved_wall))
        kw = {"now": now, "saved_at": saved_at, "wall_elapsed": wall_elapsed}
        inflight = parsed["in_flight"]
        return {
            "pending": [_restore_times(p, **kw) for p in parsed["pending"]],
            "completed": [_restore_times(c, **kw) for c in parsed["completed"]],
            "in_flight": _restore_times(inflight, **kw) if inflight is not None else None,
        }

    def _validate(self, obj: object) -> dict | None:
        if not isinstance(obj, dict) or obj.get("v") not in ACCEPTED_STATE_VERSIONS:
            return None
        if any(k in obj for k in _SECRET_KEYS):
            return None
        saved_at = obj.get("saved_at")
        if not isinstance(saved_at, (int, float)) or isinstance(saved_at, bool):
            return None
        saved_wall = obj.get("saved_wall")
        if saved_wall is not None and (not isinstance(saved_wall, (int, float)) or isinstance(saved_wall, bool)):
            return None
        pending = obj.get("pending")
        completed = obj.get("completed")
        if not isinstance(pending, list) or not isinstance(completed, list):
            return None
        in_flight = obj.get("in_flight", None)
        if in_flight is not None and not _valid_record(in_flight, PENDING_FIELDS, require=("message_id", "state")):
            return None
        if not all(_valid_record(p, PENDING_FIELDS, require=("message_id", "state")) for p in pending):
            return None
        if not all(_valid_record(c, COMPLETED_FIELDS, require=("message_id", "state")) for c in completed):
            return None
        return {
            "saved_at": float(saved_at),
            "saved_wall": None if saved_wall is None else float(saved_wall),
            "pending": [_pick(p, PENDING_FIELDS) for p in pending],
            "completed": [_slim_completed(c) for c in completed],
            "in_flight": _pick(in_flight, PENDING_FIELDS) if in_flight is not None else None,
        }

    def _quarantine(self, reason: str) -> None:
        ts = int(float(self._now()))
        dest = Path(str(self.path) + f".corrupt-{ts}")
        if dest.exists():
            dest = Path(str(self.path) + f".corrupt-{ts}-{os.getpid()}")
        try:
            os.rename(self.path, dest)
            renamed = str(dest)
        except OSError as exc:
            renamed = f"(rename_failed:{exc})"
        self._log(f"outbox_state_corrupt reason={reason} renamed={renamed}")
