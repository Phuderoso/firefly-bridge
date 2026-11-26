"""Local one-attempt receipt file (Generation 1 offline/mock prototype).

Note: The unified daemon uses :class:`firefly_bridge.broker_store.BrokerStore`
(SQLite) and standalone channel uses :class:`firefly_bridge.channel.ChannelLedger`.
This module is retained for backward compatibility with ``Bridge`` and ``prepare/send``.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path

from firefly_bridge.messages import AlreadySettled, ConflictingMessage, Receipt


class LedgerCorrupt(RuntimeError):
    pass


class Ledger:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")

    def get(self, message_id: str) -> Receipt | None:
        with self._exclusive():
            return self._read().get(message_id)

    def prepare(self, receipt: Receipt) -> Receipt:
        with self._exclusive():
            existing = self._read().get(receipt.message_id)
            if existing is not None:
                self._require_same_content(existing, receipt)
                return existing
            self._write(receipt)
            return receipt

    def block_before_attempt(self, receipt: Receipt, code: str, detail: str) -> bool:
        with self._exclusive():
            current = self._require(receipt.message_id)
            if self._settled(current):
                _copy_into(receipt, current)
                return False
            self._require_same_content(current, receipt)
            receipt.block_code = code
            receipt.block_detail = detail
            self._write(receipt)
            return True

    def claim_attempt(self, receipt: Receipt) -> bool:
        """Persist unknown before the caller is allowed to exchange."""

        with self._exclusive():
            current = self._require(receipt.message_id)
            if self._settled(current):
                _copy_into(receipt, current)
                return False
            self._require_same_content(current, receipt)
            snapshot = receipt.to_dict()
            receipt.attempt_committed = True
            receipt.transition("unknown")
            receipt.block_code = "attempt_opened"
            receipt.block_detail = (
                "Durable attempt recorded before any exchange. "
                "A restart will not send this id again."
            )
            try:
                self._write(receipt)
            except Exception:
                _copy_into(receipt, Receipt.from_dict(snapshot))
                raise
            return True

    def store(self, receipt: Receipt) -> None:
        with self._exclusive():
            current = self._read().get(receipt.message_id)
            if current is not None and current.attempt_committed and not receipt.attempt_committed:
                raise AlreadySettled("refusing_to_clear_committed_attempt")
            self._write(receipt)

    def _require(self, message_id: str) -> Receipt:
        current = self._read().get(message_id)
        if current is None:
            raise AlreadySettled("unknown_receipt")
        return current

    @staticmethod
    def _settled(receipt: Receipt) -> bool:
        return bool(
            receipt.attempt_committed or receipt.outcome != "prepared" or receipt.block_code
        )

    @staticmethod
    def _require_same_content(existing: Receipt, incoming: Receipt) -> None:
        if (
            existing.text != incoming.text
            or existing.session_id != incoming.session_id
            or existing.source != incoming.source
        ):
            raise ConflictingMessage("conflicting_message_id")

    def _read(self) -> dict[str, Receipt]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise LedgerCorrupt("ledger_corrupt") from exc
        if (
            not isinstance(raw, dict)
            or raw.get("version") != 1
            or not isinstance(raw.get("receipts"), dict)
        ):
            raise LedgerCorrupt("ledger_corrupt")
        found: dict[str, Receipt] = {}
        for key, value in raw["receipts"].items():
            if not isinstance(key, str) or not isinstance(value, dict):
                raise LedgerCorrupt("ledger_corrupt")
            receipt = Receipt.from_dict(value)
            if receipt.message_id != key:
                raise LedgerCorrupt("ledger_corrupt")
            found[key] = receipt
        return found

    def _write(self, receipt: Receipt) -> None:
        receipts = {key: item.to_dict() for key, item in self._read().items()}
        receipts[receipt.message_id] = receipt.to_dict()
        payload = json.dumps({"version": 1, "receipts": receipts}, indent=2, sort_keys=True) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        try:
            directory = os.open(self.path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory)
        except OSError:
            pass
        finally:
            os.close(directory)

    @contextmanager
    def _exclusive(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(exist_ok=True)
        handle = self.lock_path.open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def _copy_into(destination: Receipt, source: Receipt) -> None:
    destination.session_id = source.session_id
    destination.source = source.source
    destination.text = source.text
    destination.outcome = source.outcome
    destination.history = list(source.history)
    destination.block_code = source.block_code
    destination.block_detail = source.block_detail
    destination.correlation = dict(source.correlation)
    destination.transport = source.transport
    destination.timeout_s = source.timeout_s
    destination.resend_attempted = False
    destination.attribution_channel = source.attribution_channel
    destination.outbound_text = source.outbound_text
    destination.attempt_committed = source.attempt_committed
    destination.notes = list(source.notes)
    destination.permission = source.permission
