"""Heartbeat writer (pure helper; no loop, no daemon, no process, no TUI).

Each terminal self-declares its own presence by calling one of the hook entry points
(start_session / begin_turn / end_turn / tick_heartbeat / leave) from a wrapper it already
runs. Nothing here schedules itself: the caller owns the cadence (documented: every
``HEARTBEAT_CADENCE_S`` = 30 s; readers use ``max_age_s`` = 120). Tokens are always zero:
state comes from a local turn marker, never from a model.

Files in ``<directory>/`` (directory must already exist)::

    <slug(name)>.json   read by ``firefly_bridge.presence.read_state_file``
        {"name": "peerb", "ts": 1763130000.0, "state": "busy", "task": "draft notes", "v": 1}
    <slug(name)>.turn   internal marker (0600); presence() does not read it
        {"state": "busy", "ts": 1763130000.0, "task": "draft notes", "v": 1}
    <slug(name)>.lock   exclusive writer lock (0600); presence() does not read it

Writes are atomic (tmp in the same dir + fsync + rename + best-effort directory fsync).
``leave`` is a clean exit: it writes ``absent`` first, then drops the marker. Afterwards
tick / begin_turn / end_turn refuse to overwrite a closed session (they never resurrect
``absent``, even if a leftover ``.turn`` remains). Only ``start_session`` reopens.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

from firefly_bridge.presence import (
    ABSENT,
    BUSY,
    IDLE,
    MAX_STATE_BYTES,
    PresenceConfig,
    read_state_file,
)

HEARTBEAT_VERSION = 1
TURN_VERSION = 1
SESSION_CLOSED = "heartbeat_session_closed"
DEFAULT_FUTURE_SKEW_S = PresenceConfig().future_skew_s  # same clamp as presence(): 30s
MARKER_NONE, MARKER_BUSY, MARKER_IGNORED, MARKER_UNTRUSTED = (
    "none",
    "busy",
    "ignored",
    "untrusted",
)
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_JSON_MODE = 0o644
_TURN_MODE = 0o600
_LOCK_MODE = 0o600

# Process-local lock nesting (hooks call write_heartbeat under the same lock).
_LOCK_DEPTH: dict[str, int] = {}
_LOCK_FD: dict[str, int] = {}

# Test seams: one-shot callbacks / replaceable primitives. Production leaves them as below.
_before_tick = None  # optional callback() run before tick acquires the lock
_unlink = os.unlink
_try_flock = None  # filled after _flock_impl is defined; tests may replace it


def heartbeat_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-.")
    if not slug:
        raise ValueError("heartbeat_name_empty")
    return slug


def heartbeat_path(directory: str | Path, name: str) -> Path:
    return Path(os.path.expanduser(str(directory))) / f"{heartbeat_slug(name)}.json"


def turn_marker_path(directory: str | Path, name: str) -> Path:
    return Path(os.path.expanduser(str(directory))) / f"{heartbeat_slug(name)}.turn"


def lock_path(directory: str | Path, name: str) -> Path:
    return Path(os.path.expanduser(str(directory))) / f"{heartbeat_slug(name)}.lock"


def build_heartbeat(name: str, state: str, *, now: float, task: str = "") -> dict:
    """Pure: the JSON object a terminal declares about itself."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("heartbeat_name_empty")
    if state not in (BUSY, IDLE, ABSENT):
        raise ValueError("heartbeat_state_invalid")
    task = (task or "").strip()[:200]
    if state == IDLE and task:
        raise ValueError("heartbeat_idle_with_task")  # a task means busy; refuse the contradiction
    return {"name": name.strip(), "ts": float(now), "state": state, "task": task, "v": HEARTBEAT_VERSION}


def _fsync_dir(dirpath: Path) -> None:
    """Best-effort fsync of the directory after rename. Some OS/FS reject this; ignore then."""
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


def _atomic_write(dest: Path, data: bytes, *, mode: int = _JSON_MODE) -> Path:
    if len(data) > MAX_STATE_BYTES:
        raise ValueError("heartbeat_too_large")
    if not dest.parent.is_dir():
        raise FileNotFoundError("heartbeat_dir_missing")
    fd, tmp = tempfile.mkstemp(prefix=f".{dest.stem}.", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, dest)
        tmp = ""  # replace consumed it; don't unlink on the way out
        _fsync_dir(dest.parent)
    except BaseException:
        if tmp:
            try:
                _unlink(tmp)
            except OSError:
                pass
        raise
    return dest


def _flock_impl(fd: int, acquire: bool) -> bool:
    """Exclusive lock on ``fd``. False = not held (missing fcntl, or the OS refused)."""
    try:
        import fcntl
    except ImportError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if acquire else fcntl.LOCK_UN)
        return True
    except OSError:
        return False


_try_flock = _flock_impl


@contextlib.contextmanager
def _exclusive_lock(directory: str | Path, name: str):
    parent = Path(os.path.expanduser(str(directory)))
    if not parent.is_dir():
        raise FileNotFoundError("heartbeat_dir_missing")
    path = str(lock_path(directory, name))
    if _LOCK_DEPTH.get(path, 0) > 0:
        _LOCK_DEPTH[path] += 1
        try:
            yield
        finally:
            _LOCK_DEPTH[path] -= 1
        return
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, _LOCK_MODE)
    held = False
    try:
        try:
            os.chmod(path, _LOCK_MODE)
        except OSError:
            pass
        held = _try_flock(fd, True)
        _LOCK_FD[path] = fd
        _LOCK_DEPTH[path] = 1
        try:
            yield
        finally:
            _LOCK_DEPTH.pop(path, None)
            _LOCK_FD.pop(path, None)
            if held:
                _try_flock(fd, False)
    finally:
        os.close(fd)



def _heartbeat_view(directory: str | Path, name: str) -> tuple[str, object]:
    """Classify the heartbeat file with lstat: missing | unknown | absent | idle | busy.

    Unknown covers an unreadable, non-regular, or invalid file (fail closed for the reader).
    Only a fresh explicit ``absent`` is a closed session.
    """
    path = heartbeat_path(directory, name)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "unknown", None
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_STATE_BYTES:
        return "unknown", None
    rec = read_state_file(path)
    if rec is None or rec.state not in (BUSY, IDLE, ABSENT):
        return "unknown", None
    return rec.state, rec


def _session_closed(directory: str | Path, name: str) -> bool:
    """True only when the heartbeat is an explicit ``absent`` (leave). Unreadable is unknown, not closed."""
    view, _rec = _heartbeat_view(directory, name)
    return view == ABSENT


def _refuse_if_closed(directory: str | Path, name: str) -> None:
    if _session_closed(directory, name):
        raise ValueError(SESSION_CLOSED)


def write_heartbeat(
    directory: str | Path, name: str, state: str, *, now: float, task: str = "", reopen: bool = False
) -> Path:
    """Write one heartbeat atomically into an existing ``directory``. Single call, returns the path.

    ``reopen=True`` is only for ``start_session``. Writing ``absent`` is always allowed.
    Any other write against a closed (absent) session raises ``ValueError(SESSION_CLOSED)``.
    """
    obj = build_heartbeat(name, state, now=now, task=task)
    data = (json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if not reopen and state != ABSENT:
        _refuse_if_closed(directory, name)
    return _atomic_write(heartbeat_path(directory, name), data, mode=_JSON_MODE)


def build_turn_marker(*, now: float, task: str = "") -> dict:
    """Pure: the internal busy marker a turn wrapper leaves for later ticks."""
    return {"state": BUSY, "ts": float(now), "task": (task or "").strip()[:200], "v": TURN_VERSION}


def write_turn_marker(directory: str | Path, name: str, *, now: float, task: str = "") -> Path:
    obj = build_turn_marker(now=now, task=task)
    data = (json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    return _atomic_write(turn_marker_path(directory, name), data, mode=_TURN_MODE)


def clear_turn_marker(directory: str | Path, name: str) -> None:
    """Unlink a regular marker file only. FileNotFoundError is ignored; any other OSError is raised.

    A symlink is left untouched (the inspector refuses it as non-regular before any decision).
    """
    path = turn_marker_path(directory, name)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISREG(st.st_mode):
        try:
            _unlink(path)
        except FileNotFoundError:
            return


def _numeric_ts(raw) -> float | None:
    """Epoch seconds from a JSON number. Bools and strings are not used (no datetime parse)."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    return float(raw)


def _inspect_turn_marker(
    directory: str | Path,
    name: str,
    *,
    now: float | None = None,
    future_skew_s: float = DEFAULT_FUTURE_SKEW_S,
    idle_ts: float | None = None,
) -> tuple[str, str]:
    """Inspect the turn marker. Uses lstat and refuses a non-regular file before any other decision.

    Returns ``(kind, task)`` with kind:
    - ``none``: no marker file
    - ``busy``: regular, trustworthy, newer than idle (if any)
    - ``ignored``: leftover, not newer than the last idle heartbeat
    - ``untrusted``: non-regular (symlink, etc.) or a declared ts beyond ``future_skew_s`` in the future
    """
    path = turn_marker_path(directory, name)
    try:
        st = os.lstat(path)
    except OSError:
        return MARKER_NONE, ""
    if not stat.S_ISREG(st.st_mode):
        return MARKER_UNTRUSTED, ""
    obj: dict | None = None
    if st.st_size <= MAX_STATE_BYTES:
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            loaded = None
        if isinstance(loaded, dict):
            obj = loaded
    declared = _numeric_ts(obj.get("ts")) if obj is not None else None
    # future_skew applies to the declared ts only (same field presence() uses), not wall mtime.
    if now is not None and declared is not None and (now - declared) < -float(future_skew_s):
        return MARKER_UNTRUSTED, ""
    clock = declared if declared is not None else float(st.st_mtime)
    if idle_ts is not None and clock <= idle_ts:
        return MARKER_IGNORED, ""
    if st.st_size > MAX_STATE_BYTES or obj is None:
        return MARKER_BUSY, ""
    state = obj.get("state")
    state = state.strip().lower() if isinstance(state, str) else ""
    task = obj.get("task") if isinstance(obj.get("task"), str) else ""
    task = task.strip()[:200]
    if state != BUSY:
        return MARKER_BUSY, ""
    return MARKER_BUSY, task


def interpret_turn_marker(
    directory: str | Path,
    name: str,
    *,
    now: float | None = None,
    future_skew_s: float = DEFAULT_FUTURE_SKEW_S,
    idle_ts: float | None = None,
) -> tuple[str, str]:
    """Map the local marker to (state, task) without a model.

    No file → idle. A non-regular path (symlink, fifo, dir) is refused up front and is not busy.
    A regular, valid busy marker → busy + task, unless its declared ts is beyond ``future_skew_s``
    in the future (same clamp as ``presence()``) or not newer than the last idle heartbeat.
    Untrustworthy or leftover markers return idle: they must not resurrect busy.
    """
    kind, task = _inspect_turn_marker(
        directory, name, now=now, future_skew_s=future_skew_s, idle_ts=idle_ts
    )
    if kind == MARKER_BUSY:
        return BUSY, task
    return IDLE, ""


def start_session(directory: str | Path, name: str, *, now: float) -> Path:
    """Session is up and not in a turn: drop any leftover marker, declare idle. Reopens after leave."""
    with _exclusive_lock(directory, name):
        clear_turn_marker(directory, name)
        return write_heartbeat(directory, name, IDLE, now=now, reopen=True)


def begin_turn(directory: str | Path, name: str, *, now: float, task: str = "") -> Path:
    """Turn start: leave a busy marker and declare busy. Refuses a closed session."""
    with _exclusive_lock(directory, name):
        _refuse_if_closed(directory, name)
        write_turn_marker(directory, name, now=now, task=task)
        return write_heartbeat(directory, name, BUSY, now=now, task=task)


def end_turn(directory: str | Path, name: str, *, now: float) -> Path:
    """Turn end: write idle first, then drop the marker. Refuses a closed session.

    Idle is committed even if unlinking ``.turn`` fails; that error then propagates
    (FileNotFoundError is the only unlink error that is ignored), same as ``leave``.
    A leftover marker is then ignored by ``tick_heartbeat`` if it is not newer than this idle.
    """
    with _exclusive_lock(directory, name):
        _refuse_if_closed(directory, name)
        path = write_heartbeat(directory, name, IDLE, now=now)
        clear_turn_marker(directory, name)
        return path


def tick_heartbeat(
    directory: str | Path,
    name: str,
    *,
    now: float,
    future_skew_s: float = DEFAULT_FUTURE_SKEW_S,
) -> Path:
    """One cadence pulse: refresh ``ts`` from the turn marker. Never writes absent.

    If the session is already closed (``absent``), raises ``ValueError(SESSION_CLOSED)``
    without reading the turn marker. If the heartbeat JSON is unreadable, the tick leaves
    it alone (presence stays ``unknown``, the queue can retry) and does not consult ``.turn``.
    A leftover or future-beyond-skew marker must not resurrect busy.
    """
    hook = _before_tick
    if hook is not None:
        hook()
    dest = heartbeat_path(directory, name)
    with _exclusive_lock(directory, name):
        view, rec = _heartbeat_view(directory, name)
        if view == ABSENT:
            raise ValueError(SESSION_CLOSED)
        if view == "unknown":
            return dest
        idle_ts = rec.ts if rec is not None and rec.state == IDLE else None
        kind, task = _inspect_turn_marker(
            directory, name, now=now, future_skew_s=future_skew_s, idle_ts=idle_ts
        )
        if kind == MARKER_BUSY:
            return write_heartbeat(directory, name, BUSY, now=now, task=task)
        if view == IDLE:
            return write_heartbeat(directory, name, IDLE, now=now)
        if view == "missing" and kind == MARKER_NONE:
            return write_heartbeat(directory, name, IDLE, now=now)
        # Untrusted marker without a reliable idle declaration: do not invent idle or busy.
        return dest


def leave(directory: str | Path, name: str, *, now: float) -> Path:
    """Clean exit: write absent first, then drop the marker.

    Absent is committed even if unlinking ``.turn`` fails; that error then propagates
    (FileNotFoundError is the only unlink error that is ignored).
    """
    with _exclusive_lock(directory, name):
        path = write_heartbeat(directory, name, ABSENT, now=now)
        clear_turn_marker(directory, name)
        return path


def main(argv: list[str] | None = None, *, now: float | None = None) -> int:
    """One-shot CLI for a wrapper or a session-scoped ticker. Clock is injectable; default is time.time()."""
    parser = argparse.ArgumentParser(prog="presence_heartbeat", add_help=True)
    parser.add_argument("action", choices=("start", "begin", "end", "tick", "leave"))
    parser.add_argument("--dir", required=True, help="existing presence directory")
    parser.add_argument("--name", required=True, help="terminal name, e.g. peerb")
    parser.add_argument("--task", default="", help="short task label; only used with begin")
    args = parser.parse_args(argv)
    ts = time.time() if now is None else float(now)
    if args.action == "start":
        start_session(args.dir, args.name, now=ts)
    elif args.action == "begin":
        begin_turn(args.dir, args.name, now=ts, task=args.task)
    elif args.action == "end":
        end_turn(args.dir, args.name, now=ts)
    elif args.action == "tick":
        tick_heartbeat(args.dir, args.name, now=ts)
    else:
        leave(args.dir, args.name, now=ts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
