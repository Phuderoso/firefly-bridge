"""Private SQLite ledger: one acceptance/attempt per id, durable veto and quotas.

Bodies are hashed, never stored. Queued messages are closed after restart rather
than replayed. Ambiguous attempts block the target until exact terminal evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from firefly_bridge.audit import LOCAL_ZONE, fingerprint, local_time
from firefly_bridge.errors import PreSendRejected
from firefly_bridge.privacy import safe

# Placeholder roster used when a caller does not pass configured agents.
SENDERS = ("agent-a", "agent-b", "agent-c")


class StoreError(ValueError):
    pass


class BrokerStore:
    def __init__(self, path: Path, target: str, *, now=time.time, senders=SENDERS):
        self.path = path
        self.senders = tuple(senders)
        self.now = now
        self.lock = threading.RLock()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.parent.stat().st_uid != os.getuid():
            raise StoreError("state_directory_not_private")
        os.chmod(path.parent, 0o700)
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS messages(
              id TEXT PRIMARY KEY, sender TEXT NOT NULL, digest TEXT NOT NULL,
              turn_id TEXT UNIQUE NOT NULL, generation INTEGER NOT NULL,
              accepted REAL NOT NULL, attempted REAL, state TEXT NOT NULL,
              receipt TEXT NOT NULL, proof TEXT);
            CREATE TABLE IF NOT EXISTS nonces(principal TEXT, nonce TEXT, ts REAL,
              PRIMARY KEY(principal, nonce));
            CREATE TABLE IF NOT EXISTS permissions(turn_id TEXT, rpc_id TEXT,
              PRIMARY KEY(turn_id, rpc_id));
            CREATE TABLE IF NOT EXISTS audit_events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL,
              sender TEXT, message_id TEXT, data TEXT NOT NULL);
        """)
        if "terminal" not in {row[1] for row in self.db.execute("PRAGMA table_info(messages)")}:
            self.db.execute("ALTER TABLE messages ADD COLUMN terminal REAL")
        if "rejected" not in {row[1] for row in self.db.execute("PRAGMA table_info(messages)")}:
            self.db.execute("ALTER TABLE messages ADD COLUMN rejected REAL")
        with self.tx():
            current = self.get_meta("target")
            if current is not None and current != target:
                raise StoreError("state_target_mismatch")
            self.set_meta("target", target)
            # RC2 had no civil terminal timestamp. Conservatively start its
            # post-terminal cooldown at migration, never invent an old wall time.
            self.db.execute(
                "UPDATE messages SET terminal=? WHERE terminal IS NULL AND attempted IS NOT NULL AND state IN ('delivered','cancelled')",
                (self.now(),),
            )
            if self.get_meta("consent") is None:
                self.set_meta("consent", {"human": [], "recipient": [], "generation": 0})
            # Do not auto-drain an old queue, even after a fresh opt-in.
            for mid, state, receipt in self.db.execute(
                "SELECT id,state,receipt FROM messages WHERE state IN ('queued','in_flight','cancel_requested')"
            ).fetchall():
                r = json.loads(receipt)
                r.update(
                    queue_state="unknown" if state != "queued" else "closed",
                    reason="restart_no_resend",
                )
                self.db.execute(
                    "UPDATE messages SET state=?,receipt=? WHERE id=?",
                    (r["queue_state"], json.dumps(safe(r)), mid),
                )

            # The broker invariant is claim+proof committed BEFORE any RPC write.
            # Old RC3 unknowns without either cannot have reached the leader.
            for mid, receipt in self.db.execute(
                "SELECT id,receipt FROM messages WHERE state='unknown' AND attempted IS NULL AND proof IS NULL"
            ).fetchall():
                try:
                    r = json.loads(receipt)
                    r = r if isinstance(r, dict) else {}
                except (ValueError, TypeError):
                    r = {}
                r.update(queue_state="failed", reason="reconciled_pre_send_rejection")
                self.db.execute(
                    "UPDATE messages SET state='failed',receipt=?,rejected=COALESCE(rejected,?) WHERE id=?",
                    (json.dumps(safe(r)), self.now(), mid),
                )

    @contextmanager
    def tx(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def get_meta(self, key):
        with self.lock:
            row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
            return json.loads(row[0]) if row else None

    def set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))

    def consent(self, sender=None):
        c = self.get_meta("consent")
        return c if sender is None else sender in c["human"] and sender in c["recipient"]

    def control(self, actor, op, senders=None, *, control_seq=None, incarnation=None):
        if senders is None:
            senders = self.senders
        if actor not in ("human", "recipient"):
            raise StoreError("control_authority_required")
        if (
            not isinstance(senders, (list, tuple))
            or len(senders) > len(self.senders)
            or len(set(senders)) != len(senders)
            or any(s not in self.senders for s in senders)
        ):
            raise StoreError("invalid_optin_scope")
        with self.tx():
            if control_seq is not None:
                if type(control_seq) is not int or not isinstance(incarnation, str):
                    raise StoreError("control_sequence_invalid")
                key = "control_sequence:" + incarnation
                seen = self.get_meta(key)
                if seen is not None and control_seq <= seen:
                    raise StoreError("control_replay")
                self.set_meta(key, control_seq)
            c = self.consent()
            if op in ("pause", "basta", "revoke"):
                c = {"human": [], "recipient": [], "generation": c["generation"] + 1}
            elif op == "opt_in":
                c[actor] = list(senders)
            else:
                raise StoreError("control_op_invalid")
            self.set_meta("consent", c)
            at = self.now()
            self._append_audit(
                {
                    "actor": actor,
                    "event": op,
                    "kind": "channel_control",
                    "senders": list(senders) if op == "opt_in" else list(self.senders),
                    "generation": c["generation"],
                    "at": at,
                    "at_local": local_time(at),
                    "timezone": LOCAL_ZONE,
                }
            )
        return c

    def accept_nonce(self, principal, nonce, ts):
        if not isinstance(ts, (float, int)) or not abs(self.now() - ts) <= 60:
            raise StoreError("ipc_request_expired")
        if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
            raise StoreError("ipc_nonce_invalid")
        with self.tx():
            self.db.execute("DELETE FROM nonces WHERE ts < ?", (self.now() - 120,))
            try:
                self.db.execute("INSERT INTO nonces VALUES (?,?,?)", (principal, nonce, ts))
            except sqlite3.IntegrityError as exc:
                raise StoreError("ipc_replay") from exc

    def _receipt_from_row(self, row):
        """Authoritative typed columns win over old/corrupt presentation JSON."""
        try:
            r = json.loads(row[8])
            r = safe(r) if isinstance(r, dict) else {}
        except (ValueError, TypeError):
            r = {}
        r.update(
            message_id=row[0],
            sender=row[1],
            turn_id=row[2],
            generation=row[3],
            accepted_at=row[4],
            attempted_at=row[5],
            queue_state=row[6],
            attempt_committed=row[5] is not None,
            accepted_at_local=local_time(row[4]),
            attempted_at_local=local_time(row[5]),
            terminal_at=row[9],
            terminal_at_local=local_time(row[9]),
            rejected_at=row[10],
            rejected_at_local=local_time(row[10]),
            timezone=LOCAL_ZONE,
        )
        r["permission_events"] = self.audit_history("human", mid=row[0])
        return r

    def lookup(self, mid, sender=None):
        with self.lock:
            row = self.db.execute(
                "SELECT id,sender,turn_id,generation,accepted,attempted,state,proof,receipt,terminal,rejected FROM messages WHERE id=?",
                (mid,),
            ).fetchone()
        if not row or (sender in self.senders and row[1] != sender):
            return None
        return self._receipt_from_row(row)

    def accept(self, mid, sender, body, turn_id, cfg):
        digest = hashlib.sha256((sender + "\0" + body).encode()).hexdigest()
        with self.tx():
            row = self.db.execute(
                "SELECT sender,digest,receipt FROM messages WHERE id=?", (mid,)
            ).fetchone()
            if row:
                if row[0] != sender or row[1] != digest:
                    raise StoreError("conflicting_message_id")
                return self.lookup(mid), False
            if not self.consent(sender):
                raise StoreError("channel_closed_optin_required")
            count = self.db.execute(
                "SELECT COUNT(*) FROM messages WHERE sender=? AND accepted>=?",
                (sender, self.now() // 86400 * 86400),
            ).fetchone()[0]
            if count >= cfg.per_sender_daily_quota:
                raise StoreError("sender_daily_quota")
            c = self.consent()
            receipt = {
                "message_id": mid,
                "sender": sender,
                "turn_id": turn_id,
                "queue_state": "queued",
                "reason": "accepted",
                "accepted_at": self.now(),
                "accepted_at_local": local_time(self.now()),
                "timezone": LOCAL_ZONE,
                "generation": c["generation"],
            }
            self.db.execute(
                "INSERT INTO messages(id,sender,digest,turn_id,generation,accepted,attempted,state,receipt,proof) VALUES (?,?,?,?,?,?,NULL,?,?,NULL)",
                (
                    mid,
                    sender,
                    digest,
                    turn_id,
                    c["generation"],
                    self.now(),
                    "queued",
                    json.dumps(receipt),
                ),
            )
            return receipt, True

    def unresolved(self):
        with self.lock:
            return (
                self.db.execute(
                    "SELECT COUNT(*) FROM messages WHERE state IN "
                    "('in_flight','unknown','cancel_requested')"
                ).fetchone()[0]
                > 0
            )

    def can_dispatch(self, sender):
        return self.consent(sender) and not self.unresolved()

    def interval_ready(self, sender, cfg):
        with self.lock:
            own = self.db.execute(
                "SELECT MAX(attempted) FROM messages WHERE sender=?", (sender,)
            ).fetchone()[0]
            last_start, last_terminal = self.db.execute(
                "SELECT MAX(attempted), MAX(terminal) FROM messages"
            ).fetchone()
        now = self.now()
        return bool(
            not cfg.quiet_now(now)
            and (own is None or now - own >= cfg.applicable_cooldown_s)
            and (last_start is None or now - last_start >= cfg.target_interval_s)
            and (last_terminal is None or now - last_terminal >= cfg.post_turn_interval_s)
        )

    def claim(self, turn, proof, cfg=None):
        rejection = None
        with self.tx():
            row = self.db.execute(
                "SELECT attempted,generation,state FROM messages WHERE id=?", (turn.message_id,)
            ).fetchone()
            if not row or row[0] is not None or row[2] != "in_flight":
                raise StoreError("attempt_already_consumed")
            if row[1] != self.consent()["generation"] or not self.consent(turn.sender):
                rejection = "rejected_consent_revoked"
            elif cfg is not None and not self.interval_ready(turn.sender, cfg):
                rejection = (
                    "rejected_quiet_hours" if cfg.quiet_now(self.now()) else "rejected_pacing"
                )
            if rejection:
                receipt = turn.to_receipt_dict()
                receipt.pop("result", None)
                receipt.update(queue_state="failed", reason=rejection)
                self.db.execute(
                    "UPDATE messages SET state='failed',receipt=?,rejected=? WHERE id=?",
                    (json.dumps(safe(receipt)), self.now(), turn.message_id),
                )
            else:
                self.db.execute(
                    "UPDATE messages SET attempted=?,proof=? WHERE id=?",
                    (self.now(), json.dumps(proof), turn.message_id),
                )
        # Do not raise inside tx(): the durable refusal must survive its exception.
        if rejection:
            raise PreSendRejected(rejection)

    def update(self, turn, event):
        receipt = turn.to_receipt_dict()
        receipt.update(event=event)
        # No model/tool output on disk. Reply available only in the live broker.
        receipt.pop("result", None)
        with self.tx():
            self.db.execute(
                "UPDATE messages SET state=?,receipt=? WHERE id=?",
                (turn.state, json.dumps(safe(receipt)), turn.message_id),
            )
            if turn.state in ("delivered", "cancelled"):
                self.db.execute(
                    "UPDATE messages SET terminal=COALESCE(terminal,?) WHERE id=? AND attempted IS NOT NULL",
                    (self.now(), turn.message_id),
                )

    def reconcile_terminal(self, params, update):
        """Read-only leader terminal proof may settle, NEVER replay/adopt permissions."""
        meta = params.get("_meta", {}).get("agentBridge", {})
        reason = update.get("stopReason")
        if (
            reason not in ("end_turn", "cancelled", "max_tokens", "refusal")
            or meta.get("replay") is True
        ):
            return False
        with self.tx():
            row = self.db.execute(
                "SELECT id,proof,receipt FROM messages WHERE turn_id=? AND state='unknown'",
                (meta.get("turnId"),),
            ).fetchone()
            if not row or not row[1]:
                return False
            proof = json.loads(row[1])
            if not all(meta.get(k) == v for k, v in proof.items()):
                return False
            r = json.loads(row[2])
            r.update(
                queue_state="cancelled" if reason == "cancelled" else "delivered",
                reason="reconciled_terminal_no_resend",
                reply_recovery="reply_recovery_unavailable",
            )
            self.db.execute(
                "UPDATE messages SET state=?,receipt=? WHERE id=?",
                (r["queue_state"], json.dumps(safe(r)), row[0]),
            )
            self.db.execute(
                "UPDATE messages SET terminal=COALESCE(terminal,?) WHERE id=?", (self.now(), row[0])
            )
            return True

    def _append_audit(self, event):
        self.db.execute(
            "INSERT INTO audit_events(actor,sender,message_id,data) VALUES (?,?,?,?)",
            (
                event.get("actor", event.get("sender", "human")),
                event.get("sender"),
                event.get("message_id"),
                json.dumps(safe(event)),
            ),
        )
        self.db.execute(
            "DELETE FROM audit_events WHERE seq NOT IN (SELECT seq FROM audit_events ORDER BY seq DESC LIMIT 1000)"
        )

    def record_permission(self, event):
        with self.tx():
            self._append_audit(event)

    def audit_history(self, principal, *, mid=None, controls_only=False):
        with self.lock:
            rows = self.db.execute(
                "SELECT sender,message_id,data FROM audit_events ORDER BY seq DESC LIMIT 1000"
            ).fetchall()
        result = []
        for sender, message_id, data in reversed(rows):
            if mid is not None and mid != message_id:
                continue
            if controls_only and message_id is not None:
                continue
            event = json.loads(data)
            if (
                principal in self.senders
                and sender != principal
                and not (sender is None and principal in event.get("senders", []))
            ):
                continue
            result.append(safe(event))
        return result[-100:]

    def owns_claim(self, turn, proof):
        """Exact durable initiator claim, not a local prefix/state assertion."""
        with self.lock:
            row = self.db.execute(
                "SELECT sender,turn_id,generation,attempted,proof,state FROM messages WHERE id=?",
                (turn.message_id,),
            ).fetchone()
        try:
            return bool(
                row
                and row[0] == turn.sender
                and row[1] == turn.turn_id
                and row[2] == turn.generation
                and row[3] is not None
                and proof is not None
                and json.loads(row[4]) == proof
                and row[5] in ("in_flight", "unknown", "cancel_requested")
            )
        except (ValueError, TypeError):
            return False

    def permission_once(self, turn_id, rpc_id):
        with self.tx():
            try:
                self.db.execute(
                    "INSERT INTO permissions VALUES (?,?)", (turn_id, fingerprint(rpc_id))
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def close(self):
        self.db.close()
