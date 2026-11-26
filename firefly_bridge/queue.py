"""Bounded one-slot local queue. Timeout/crash retains the remote lease.

Only a correlated terminal result can release an ambiguous active turn.
Agents can withdraw queued work; cancellation of active work is broker-gated.

Presence backoff (optional, ``presence_gate``): this queue is the ONLY re-tryer of a deferred wake.
Before dispatch the gate decides wake | deferred_busy | deferred_unknown | deferred_absent | gated.
busy/unknown => the turn stays queued with ``attempts`` += 1 and ``next_attempt_at`` = now + backoff
(scheduled, not polled; ``next_due_at()`` tells a caller when to pump again). After
``max_deferred_attempts`` refusals it settles ``deferred_expired`` with route ``inbox`` (the message
stays in the PR/inbox; nothing is dropped). absent => settles ``deferred_absent``, route ``inbox``,
never re-tried. Without a gate nothing here changes.

Persistence (optional, ``state_path``): when set, pending and completed turns are written to a
JSON file (see ``firefly_bridge.queue_store``) so a restart reloads the queue. Without a path
the outbox stays memory-only, identical to this module's previous behaviour.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field

from firefly_bridge.bridge import TransportCrash, TransportTimeout
from firefly_bridge.errors import PreSendRejected
from firefly_bridge.privacy import safe

_QUEUE_LOG = logging.getLogger("firefly_bridge.queue")


def _body_sha256(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()


class TurnTimeout(Exception):
    pass


class OutboxFull(Exception):
    pass


class BusyRefused(Exception):
    pass


# Presence-backoff states (only reachable when Outbox(presence_gate=...) is set).
DEFERRED = "deferred"  # still queued, waiting for next_attempt_at
DEFERRED_EXPIRED = "deferred_expired"  # terminal -> inbox
DEFERRED_ABSENT = "deferred_absent"  # terminal -> inbox, never re-tried
ROUTE_INBOX = "inbox"
_RETRY_ACTIONS = ("deferred_busy", "deferred_unknown")
_GATED_ACTIONS = ("gated_non_vip", "suppressed_self_echo")

# Queue/turn states (distinct from the Receipt send-outcome vocabulary).
QUEUED = "queued"
IN_FLIGHT = "in_flight"
DELIVERED = "delivered"
TIMED_OUT = "unknown"
CANCELLED = "cancelled"
FAILED = "failed"
PERMISSION_PENDING = "permission_pending"


@dataclass
class Turn:
    message_id: str
    session_id: str
    body: str
    outbound_text: str
    enqueued_at: float
    sender: str = "agent-a"
    turn_id: str = ""
    generation: int = 0
    wake_origin: bool = False
    state: str = QUEUED
    started_at: float | None = None
    settled_at: float | None = None
    deadline: float | None = None
    reason: str | None = None
    result: dict | None = None
    permission_events: list = field(default_factory=list)
    pending_card: dict | None = None
    cancel_requested: threading.Event = field(default_factory=threading.Event)
    attempts: int = 0  # presence refusals (busy/unknown) so far
    next_attempt_at: float | None = None  # queue clock; None = due now
    presence_action: str = ""  # last presence_gate action
    route: str = ""  # "inbox" when the queue hands the message back to the PR/inbox

    def to_receipt_dict(self) -> dict:
        return safe(
            {
                "sender": self.sender,
                "turn_id": self.turn_id,
                "message_id": self.message_id,
                "session_id": self.session_id,
                "queue_state": self.state,
                "reason": self.reason,
                "enqueued_at": self.enqueued_at,
                "started_at": self.started_at,
                "settled_at": self.settled_at,
                "wake_origin": self.wake_origin,
                "permission_events": list(self.permission_events),
                "pending_card": self.pending_card,
                "result": self.result,
                "attempts": self.attempts,
                "next_attempt_at": self.next_attempt_at,
                "presence_action": self.presence_action,
                "route": self.route,
            }
        )


class Outbox:
    def __init__(
        self,
        runner,
        *,
        turn_timeout_s=600.0,
        busy_wait_s=120.0,
        busy_policy="wait",
        max_outbox=4,
        now=time.monotonic,
        on_receipt=None,
        dispatch_gate=None,
        presence_gate=None,
        max_deferred_attempts=8,
        backoff=None,
        state_path=None,
        on_store_log=None,
        wall=None,
        sign_outbound=None,
    ):
        if busy_policy not in ("wait", "fail"):
            raise ValueError("busy_policy_invalid")
        self._runner = runner
        self._dispatch_gate = dispatch_gate or (lambda turn: True)
        # presence_gate(turn) -> PresenceDecision | str action; None = presence off (old behaviour)
        self._presence_gate = presence_gate
        if int(max_deferred_attempts) < 1:
            raise ValueError("max_deferred_attempts_invalid")
        self._max_deferred_attempts = int(max_deferred_attempts)
        if backoff is None:
            from firefly_bridge.presence import deferred_backoff_s as backoff
        self._backoff = backoff  # attempt (0-based) -> seconds
        self._last_sender = None
        self._turn_timeout_s = float(turn_timeout_s)
        self._busy_wait_s = float(busy_wait_s)
        self._busy_policy = busy_policy
        self._max_outbox = int(max_outbox)
        self._now = now
        self._on_receipt = on_receipt
        self._sign_outbound = sign_outbound
        self._store_log = on_store_log or (lambda msg: _QUEUE_LOG.error("%s", msg))
        self._lock = threading.RLock()
        self._pending: list[Turn] = []
        self._in_flight: Turn | None = None
        self._completed: dict[str, Turn] = {}
        self.journal: list[dict] = []
        self._store = None
        if state_path:
            from firefly_bridge.queue_store import QueueStore

            self._store = QueueStore(state_path, now=now, log=on_store_log, wall=wall)
            self._restore()

    # ------------------------------------------------------------------
    def enqueue(
        self,
        message_id: str,
        session_id: str,
        body: str,
        outbound_text: str,
        *,
        sender="agent-a",
        turn_id="",
        generation=0,
        wake_origin=False,
    ) -> Turn:
        with self._lock:
            for existing in self._known():
                if existing.message_id == message_id:
                    if existing.body_sha256:
                        if existing.body_sha256 != _body_sha256(body):
                            raise ValueError("conflicting_message_id")
                        return existing
                    if existing.body != body or existing.sender != sender:
                        raise ValueError("conflicting_message_id")
                    return existing
            waiting = len(self._pending)
            if self._busy_policy == "fail" and (self._in_flight is not None or waiting):
                raise BusyRefused("slot_busy_fail_policy")
            if waiting >= self._max_outbox:
                raise OutboxFull("max_outbox_reached")
            turn = Turn(
                message_id=message_id,
                session_id=session_id,
                body=body,
                outbound_text=outbound_text,
                enqueued_at=self._now(),
                sender=sender,
                turn_id=turn_id,
                generation=generation,
                wake_origin=bool(wake_origin),
            )
            turn.body_sha256 = _body_sha256(body)
            self._pending.append(turn)
            self._emit(turn, "enqueued")
            return turn

    def cancel(self, message_id: str, *, reason: str = "explicit_cancel") -> Turn | None:
        with self._lock:
            if self._in_flight is not None and self._in_flight.message_id == message_id:
                raise BusyRefused("active_cancel_requires_human_or_recipient")
            for turn in list(self._pending):
                if turn.message_id == message_id:
                    self._pending.remove(turn)
                    self._settle(turn, CANCELLED, reason)
                    return turn
        return None

    def pump_once(self) -> Turn | None:
        """Start the next queued turn if the slot is free; run it to terminal.

        Returns the turn that was processed, or None if nothing to do. The
        busy-wait policy applies while a turn is in flight: a queued message
        waits up to ``busy_wait_s`` before being failed as ``slot_busy``.
        """
        with self._lock:
            self._expire_waiters()
            if self._in_flight is not None:
                return None
            if not self._pending:
                return None
            now = self._now()
            eligible = [
                t
                for t in self._pending
                if (t.next_attempt_at is None or now >= t.next_attempt_at)
                and self._dispatch_gate(t)
            ]
            if not eligible:
                return None
            turn = next((t for t in eligible if t.sender != self._last_sender), eligible[0])
            try:
                if self._sign_outbound is not None:
                    signed = self._sign_outbound(turn)
                    turn.outbound_text = "" if signed is None else str(signed)
            except Exception as exc:  # noqa: BLE001 - signing must fail closed, never send empty
                self._pending.remove(turn)
                self._settle(turn, FAILED, f"outbound_sign_failed:{type(exc).__name__}")
                return turn
            if not str(turn.outbound_text or "").strip():
                reason = (
                    "outbound_sign_missing" if self._sign_outbound is None else "outbound_text_empty"
                )
                self._pending.remove(turn)
                self._settle(turn, FAILED, reason)
                return turn
            if self._presence_gate is not None and not self._presence_allows(turn):
                return turn
            self._pending.remove(turn)
            self._last_sender = turn.sender
            self._in_flight = turn
            turn.state = IN_FLIGHT
            turn.started_at = self._now()
            turn.deadline = turn.started_at + self._turn_timeout_s
            self._emit(turn, "in_flight")
        try:
            result = self._runner(turn)
        except PreSendRejected as exc:
            self._finish(turn, FAILED, str(exc))
            return turn
        except (TurnTimeout, TransportTimeout):
            self._hold(turn, "observation_timeout_no_cancel")
            return turn
        except TransportCrash:
            self._hold(turn, "transport_crash_no_resend")
            return turn
        except BusyRefused as exc:
            if self._presence_gate is not None:
                # nothing was sent: same single re-tryer, same backoff as a busy presence read.
                # Give back the nonce this gate granted for the attempt, so the retry is not
                # refused as a replay (the wake was never delivered).
                release = getattr(self._presence_gate, "release", None)
                if release is not None:
                    try:
                        release(turn)
                    except Exception:  # noqa: BLE001 - a failed release only costs the retry
                        pass
                with self._lock:
                    if self._in_flight is turn:
                        self._in_flight = None
                    turn.started_at = turn.deadline = None
                    self._pending.append(turn)
                    self._defer(turn, "deferred_busy", f"peer_busy_not_sent:{exc}")
                return turn
            self._finish(turn, FAILED, f"peer_busy_not_sent:{exc}")
            return turn
        except Exception as exc:  # noqa: BLE001 - record and fail closed
            self._hold(turn, f"runner_error:{type(exc).__name__}")
            return turn
        if isinstance(result, dict) and result.get("stop_reason") == "cancelled":
            self._finish(turn, CANCELLED, turn.reason or "cancelled", result=result)
            return turn
        if isinstance(result, dict) and result.get("error"):
            self._finish(turn, FAILED, "rpc_error_no_resend", result=result)
            return turn
        self._finish(turn, DELIVERED, "terminal_result", result=result)
        return turn

    def drain(self, max_turns: int = 100) -> list[Turn]:
        processed: list[Turn] = []
        for _ in range(max_turns):
            turn = self.pump_once()
            if turn is None:
                break
            processed.append(turn)
        return processed

    def next_due_at(self) -> float | None:
        """Earliest ``next_attempt_at`` among deferred turns (queue clock), or None.

        A caller arms ONE timer for this instant (event-driven), instead of polling a clock."""
        with self._lock:
            due = [t.next_attempt_at for t in self._pending if t.next_attempt_at is not None]
            return min(due) if due else None

    def status(self) -> dict:
        with self._lock:
            out = {
                "in_flight": self._in_flight.message_id if self._in_flight else None,
                "pending": [t.message_id for t in self._pending],
                "pending_count": len(self._pending),
            }
            if self._presence_gate is not None:
                out["deferred"] = {
                    t.message_id: {"attempts": t.attempts, "next_attempt_at": t.next_attempt_at}
                    for t in self._pending
                    if t.next_attempt_at is not None
                }
                out["next_due_at"] = self.next_due_at()
            return out

    # ------------------------------------------------------------------
    def _all(self) -> list[Turn]:
        out = list(self._pending)
        if self._in_flight is not None:
            out.append(self._in_flight)
        return out

    def _known(self) -> list[Turn]:
        # With persist, completed ids stay known so enqueue is idempotent after restart.
        # Without a state_path, only pending + in_flight count (legacy behaviour).
        if self._store is None:
            return self._all()
        return self._all() + list(self._completed.values())

    def _presence_allows(self, turn: Turn) -> bool:
        """Lock held. True = dispatch now. False = turn was deferred or settled here."""
        try:
            decision = self._presence_gate(turn)
            action = decision if isinstance(decision, str) else getattr(decision, "action", "")
            reason = "" if isinstance(decision, str) else getattr(decision, "reason", "")
        except Exception as exc:  # noqa: BLE001 - unreadable presence never forces a wake
            action, reason = "deferred_unknown", f"presence_gate_error:{type(exc).__name__}"
        turn.presence_action = action
        if action == "wake":
            return True
        if action in _RETRY_ACTIONS:
            self._defer(turn, action, reason or action)
            return False
        self._pending.remove(turn)
        if action == "deferred_absent":
            turn.route = ROUTE_INBOX
            turn.next_attempt_at = None
            self._settle(turn, DEFERRED_ABSENT, reason or "absent")
        elif action in _GATED_ACTIONS:
            # gated / replayed_nonce: no wake, but the message is not lost; it goes back to the
            # PR/inbox as unverified content (the nonce stays spent: never released after a wake)
            turn.route = ROUTE_INBOX
            self._settle(turn, FAILED, f"{action}:{reason}")
        else:  # unexpected verdict: fail closed, keep the message for a human/inbox
            turn.route = ROUTE_INBOX
            self._settle(turn, FAILED, f"presence_action_invalid:{action}")
        return False

    def _defer(self, turn: Turn, action: str, reason: str) -> None:
        """Lock held; turn is in _pending. One refusal: count, reschedule or expire to inbox."""
        turn.presence_action = action
        turn.attempts += 1
        if turn.attempts >= self._max_deferred_attempts:
            self._pending.remove(turn)
            turn.route = ROUTE_INBOX
            turn.next_attempt_at = None
            self._settle(turn, DEFERRED_EXPIRED, f"{action}:{reason}:attempts={turn.attempts}")
            return
        turn.next_attempt_at = self._now() + float(self._backoff(turn.attempts - 1))
        turn.state = DEFERRED
        turn.reason = f"{action}:{reason}"
        self._emit(turn, DEFERRED)

    def _expire_waiters(self) -> None:
        now = self._now()
        for turn in list(self._pending):
            if turn.attempts:
                continue  # presence-deferred: bounded by max_deferred_attempts, not busy_wait_s
            if now - turn.enqueued_at > self._busy_wait_s:
                self._pending.remove(turn)
                self._settle(turn, FAILED, "slot_busy_wait_exceeded")

    def _hold(self, turn, reason):
        with self._lock:
            self._settle(turn, TIMED_OUT, reason)
            # Intentionally retain _in_flight. No second prompt after ambiguity.

    def reconcile(self, turn, result):
        with self._lock:
            if self._in_flight is not turn:
                return
            state = CANCELLED if result.get("stop_reason") == "cancelled" else DELIVERED
            self._finish(turn, state, "correlated_terminal", result)

    def _finish(self, turn: Turn, state: str, reason: str, result: dict | None = None) -> None:
        with self._lock:
            if self._in_flight is turn:
                self._in_flight = None
            self._settle(turn, state, reason, result)

    def _settle(self, turn: Turn, state: str, reason: str, result: dict | None = None) -> None:
        turn.state = state
        turn.reason = reason
        turn.settled_at = self._now()
        if result is not None:
            turn.result = result
        if (
            self._store is not None
            and turn not in self._pending
            and self._in_flight is not turn
        ):
            self._remember_completed(turn)
        self._emit(turn, state)

    def _emit(self, turn: Turn, event: str) -> None:
        entry = {
            "event": event,
            "message_id": turn.message_id,
            "state": turn.state,
            "reason": turn.reason,
            "at": self._now(),
        }
        self.journal.append(safe(entry))
        del self.journal[:-100]
        if self._on_receipt is not None:
            self._on_receipt(turn, event)
        try:
            self._persist()
        except Exception as exc:  # noqa: BLE001 - persist must not wedge in-memory state
            self._store_failed(exc)

    MAX_COMPLETED = 1024

    def _remember_completed(self, turn: Turn) -> None:
        digest = turn.body_sha256 or _body_sha256(turn.body)
        slim = Turn(
            message_id=turn.message_id,
            session_id="",
            body="",
            outbound_text="",
            enqueued_at=turn.enqueued_at,
            sender=turn.sender,
            state=turn.state,
            reason=turn.reason,
            settled_at=turn.settled_at,
            attempts=turn.attempts,
            route=turn.route,
        )
        slim.body_sha256 = digest
        self._completed[slim.message_id] = slim
        self._trim_completed()

    def _trim_completed(self, drop: int | None = None) -> None:
        extra = drop if drop is not None else (len(self._completed) - self.MAX_COMPLETED)
        if extra <= 0:
            return
        oldest = sorted(
            self._completed.values(),
            key=lambda t: (t.settled_at is None, t.settled_at or t.enqueued_at),
        )
        for gone in oldest[:extra]:
            self._completed.pop(gone.message_id, None)

    def _store_failed(self, exc: BaseException) -> None:
        self._store_log(f"outbox_state_save_failed err={type(exc).__name__}:{exc}")

    def _turn_to_record(self, turn: Turn) -> dict:
        return {
            "message_id": turn.message_id,
            "session_id": turn.session_id,
            "body": turn.body,
            "outbound_text": "",
            "body_sha256": turn.body_sha256 or _body_sha256(turn.body),
            "sender": turn.sender,
            "turn_id": turn.turn_id,
            "generation": turn.generation,
            "wake_origin": bool(turn.wake_origin),
            "state": turn.state,
            "reason": turn.reason,
            "attempts": turn.attempts,
            "presence_action": turn.presence_action,
            "route": turn.route,
            "enqueued_at": turn.enqueued_at,
            "next_attempt_at": turn.next_attempt_at,
            "started_at": turn.started_at,
            "settled_at": turn.settled_at,
            "deadline": turn.deadline,
        }

    def _record_to_turn(self, rec: dict) -> Turn:
        turn = Turn(
            message_id=str(rec["message_id"]),
            session_id=str(rec.get("session_id") or ""),
            body=str(rec.get("body") or ""),
            outbound_text=str(rec.get("outbound_text") or ""),
            enqueued_at=float(rec.get("enqueued_at") or self._now()),
            sender=str(rec.get("sender") or "agent-a"),
            turn_id=str(rec.get("turn_id") or ""),
            generation=int(rec.get("generation") or 0),
            wake_origin=bool(rec.get("wake_origin")),
            state=str(rec.get("state") or QUEUED),
            reason=rec.get("reason"),
            attempts=int(rec.get("attempts") or 0),
        )
        turn.presence_action = str(rec.get("presence_action") or "")
        turn.route = str(rec.get("route") or "")
        if rec.get("next_attempt_at") is not None:
            turn.next_attempt_at = float(rec["next_attempt_at"])
        if rec.get("started_at") is not None:
            turn.started_at = float(rec["started_at"])
        if rec.get("settled_at") is not None:
            turn.settled_at = float(rec["settled_at"])
        if rec.get("deadline") is not None:
            turn.deadline = float(rec["deadline"])
        turn.body_sha256 = str(rec.get("body_sha256") or _body_sha256(turn.body))
        return turn

    def _persist(self) -> None:
        if self._store is None:
            return
        from firefly_bridge.queue_store import QueueStoreError

        while True:
            try:
                self._store.save(
                    pending=[self._turn_to_record(t) for t in self._pending],
                    completed=[self._turn_to_record(t) for t in self._completed.values()],
                    in_flight=self._turn_to_record(self._in_flight) if self._in_flight is not None else None,
                    clock_now=self._now(),
                )
                return
            except QueueStoreError as exc:
                if "queue_state_too_large" in str(exc) and self._completed:
                    self._trim_completed(drop=max(1, len(self._completed) // 8))
                    continue
                raise

    def _restore(self) -> None:
        if self._store is None:
            return
        data = self._store.load()
        self._pending = [self._record_to_turn(r) for r in data["pending"]]
        self._completed = {}
        for rec in data["completed"]:
            self._remember_completed(self._record_to_turn(rec))
        inflight = data.get("in_flight")
        if inflight is not None:
            # Crash mid-dispatch: do not resend. Remember the id and free the slot.
            turn = self._record_to_turn(inflight)
            if turn.state in (QUEUED, IN_FLIGHT, DEFERRED, PERMISSION_PENDING):
                suffix = "in_flight_at_restart"
                turn.state = TIMED_OUT
                turn.reason = (turn.reason + ":" + suffix) if turn.reason else suffix
                turn.settled_at = self._now()
                turn.next_attempt_at = None
            self._remember_completed(turn)
        self._in_flight = None
        now = self._now()
        floor = float(self._backoff(0))
        for turn in self._pending:
            if turn.next_attempt_at is not None and turn.next_attempt_at <= now:
                # Clock reset + wall elapsed past the due instant: do not fire immediately.
                turn.next_attempt_at = now + floor
                if turn.state == QUEUED:
                    turn.state = DEFERRED
