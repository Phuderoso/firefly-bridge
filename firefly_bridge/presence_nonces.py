"""Persistent, locked replay ledger for presence wake grants (not a message inbox)."""
from __future__ import annotations

import json
import math
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

MAX_LEDGER_BYTES = 1 << 20  # ~1 MiB; rows live <= ~1200 s, so a bigger file is not ours


class NonceStoreError(ValueError):
    """The replay ledger is unsafe, unreadable or could not be saved: fail closed."""


class LedgerRecords(dict):
    """``{ledger_key: expiry_epoch}`` plus ``watermark``: the highest expiry ever pruned.

    A body whose expiry is ``<= watermark`` may have been granted and then forgotten, so it is
    refused even if the receive clock stepped backwards (see ``forgotten``).
    """

    watermark: float = -math.inf

    def forgotten(self, key: str, expiry: float) -> bool:
        return key not in self and expiry <= self.watermark


def default_nonce_path() -> Path:
    """The ONE default ledger for queue_gate and channel-knock --presence."""
    override = os.environ.get("CHANNEL_PRESENCE_NONCES")
    return Path(override).expanduser() if override else (
        Path.home() / ".local/state/firefly-bridge/presence-nonces.json"
    )


def ledger_key(signer: str, nonce: str) -> str:
    """Config-independent key: the same base name the MAC canonical form signs (no aliases)."""
    from firefly_bridge import speaker as sp

    return sp._base_key(signer) + "\n" + nonce


def _check_parent(parent: Path) -> None:
    st = os.lstat(parent)  # a symlinked ledger directory is refused, not followed
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise NonceStoreError("nonce_store_parent_not_private")


def _private_open(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        os.close(fd)
        raise NonceStoreError("nonce_store_not_private_regular_file")
    return fd


def _load(path: Path) -> tuple[dict, float]:
    try:
        fd = _private_open(path, os.O_RDONLY)
    except FileNotFoundError:
        return {}, -math.inf
    with os.fdopen(fd, "rb") as stream:
        if os.fstat(stream.fileno()).st_size > MAX_LEDGER_BYTES:
            raise NonceStoreError("nonce_store_too_large")
        raw = stream.read(MAX_LEDGER_BYTES + 1)
    if len(raw) > MAX_LEDGER_BYTES:
        raise NonceStoreError("nonce_store_too_large")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except RecursionError as exc:  # deeply nested JSON: corrupt, not a crash
        raise NonceStoreError("nonce_store_corrupt") from exc
    if not isinstance(obj, dict) or obj.get("v") != 1 or not isinstance(obj.get("nonces"), dict):
        raise NonceStoreError("nonce_store_corrupt")
    records = obj["nonces"]
    if not all(isinstance(k, str) and _finite(v) for k, v in records.items()):
        raise NonceStoreError("nonce_store_corrupt")
    watermark = obj.get("watermark", -math.inf)
    if "watermark" in obj and not _finite(watermark):
        raise NonceStoreError("nonce_store_corrupt")
    return records, watermark


def _finite(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _save(path: Path, records: dict, watermark: float = -math.inf) -> None:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            payload: dict = {"v": 1, "nonces": dict(records)}
            if math.isfinite(watermark):
                payload["watermark"] = watermark
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def nonce_transaction(path: str | Path | None, now: float, *, write: bool = True):
    """Lock across verify + decision (+ durable save when ``write``).

    Values are signature-expiry epochs. The caller MUST check abs(now-ts) <= 600,
    including when a transport timestamp exists, before pruning is safe. Deferred
    (not yet granted) wakes do not claim a nonce, so queue backoff can try again.

    ``write=False`` (dry-run): shared lock, read only; creates nothing and never saves.
    Yields ``LedgerRecords``: rows pruned here raise its ``watermark`` (the highest pruned
    expiry, persisted as ``"watermark"`` and never lowered), so a body that may have been
    forgotten stays refused after a backward clock step. Deleting the ledger resets it.
    Ledger problems raise ``NonceStoreError``; errors from the caller's block pass through.
    """
    import fcntl

    if not math.isfinite(now):
        raise NonceStoreError("invalid_receive_time")
    path = Path(path).expanduser() if path is not None else default_nonce_path()
    lock_path = path.with_name(path.name + ".lock")
    lock = None
    try:
        if write:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.exists():
            _check_parent(path.parent)
            try:
                lock = _private_open(lock_path, (os.O_CREAT | os.O_RDWR) if write else os.O_RDONLY)
            except FileNotFoundError:
                lock = None  # read-only and nothing was ever claimed here
            if lock is not None:
                fcntl.flock(lock, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            loaded, watermark = _load(path)
        else:
            loaded, watermark = {}, -math.inf
        records = LedgerRecords((k, v) for k, v in loaded.items() if v >= now)
        records.watermark = max([watermark, *(v for v in loaded.values() if v < now)])
    except NonceStoreError:
        if lock is not None:
            os.close(lock)
        raise
    except (OSError, ValueError, TypeError) as exc:
        if lock is not None:
            os.close(lock)
        raise NonceStoreError(f"nonce_store_unreadable:{type(exc).__name__}") from exc
    try:
        yield records
        if write:
            try:
                _save(path, records, records.watermark)
            except OSError as exc:
                raise NonceStoreError(f"nonce_store_save_failed:{type(exc).__name__}") from exc
    finally:
        if lock is not None:
            os.close(lock)


def release_nonce(path: str | Path | None, key: str, now: float) -> bool:
    """Un-claim ``key`` after a granted wake that was provably NOT delivered (``BusyRefused``).

    Exclusive lock + durable save, like a claim. Returns True when a row was removed. Only the
    queue calls this, for a grant it made itself in the same attempt.
    """
    with nonce_transaction(path, now, write=True) as records:
        return records.pop(key, None) is not None
