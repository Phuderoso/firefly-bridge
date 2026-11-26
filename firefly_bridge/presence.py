"""Presence/occupancy of a terminal before a wake/knock, plus the one-shot wake grant.

Question answered: may we knock on terminal X *now*, or would we interrupt it?

Presence itself is read-only (heartbeat files). ``wake_decision`` also consults the replay
ledger (``presence_nonces``): with ``claim=True`` a granted signed ``wake`` spends its
(signer, nonce) durably; with the default ``claim=False`` (dry run) the ledger is only read
under a shared lock and nothing is written. ``queue_gate`` claims; ``channel-knock`` claims
only with ``--claim``.

    presence(name, now, sources, cfg) -> busy | idle | absent | unknown
    wake_decision(sender, target=..., ...) -> wake | gated_non_vip | suppressed_self_echo
                                             | deferred_busy | deferred_absent | deferred_unknown

Order is fixed: ``speaker.wake_gate`` runs FIRST. A non-VIP (or self-echo) never reaches a presence
read. Only a VIP-gated ``wake`` asks about the target's presence, and only ``idle`` knocks.
Everything else is deferred (the message stays in the PR/inbox); unknown/stale never forces.

Sources are injectable callables ``(name) -> PresenceRecord | None``. The only concrete source here
reads a small JSON state file the terminal itself writes (heartbeat). This module never spawns a
process, opens a socket, touches tmux/launchd/TUI or signals anything.

Config (`config.toml`)::

    [channel_presence]
    max_age_s = 120                 # heartbeat older than this => stale => unknown
    future_skew_s = 30              # heartbeat from the future beyond this => unknown
    allow_busy_override = false     # DECIDED: off. Future hook only for an HMAC-verified sender
    busy_override_principals = []   # only used when the flag is on AND sender_verified=True
    max_deferred_attempts = 8       # queue: busy/unknown refusals before deferred_expired (-> inbox)
    backoff_base_s = 30             # queue: first re-try delay; doubles per refusal
    backoff_cap_s = 600             # queue: delay ceiling

    [channel_presence.terminals]  # name -> heartbeat file (read-only)
    peerb = "~/.grok/channel/presence/peerb.json"

Heartbeat file (written by the terminal; any extra keys ignored)::

    {"name": "peerb", "ts": 1763130000, "state": "busy", "task": "draft notes"}

``state`` is one of busy | idle | absent; a non-empty ``task`` or ``"busy": true`` also means busy.
``ts`` is epoch seconds or ISO-8601.
"""

from __future__ import annotations

import json
import math
import os
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from firefly_bridge import speaker as sp
from firefly_bridge.presence_nonces import (
    NonceStoreError,
    ledger_key,
    nonce_transaction,
    release_nonce,
)

BUSY = "busy"
IDLE = "idle"
ABSENT = "absent"
UNKNOWN = "unknown"
STATES = (BUSY, IDLE, ABSENT)

DEFERRED_BUSY = "deferred_busy"
DEFERRED_ABSENT = "deferred_absent"
DEFERRED_UNKNOWN = "deferred_unknown"
DEFERRED = (DEFERRED_BUSY, DEFERRED_ABSENT, DEFERRED_UNKNOWN)

# Retry ownership (user decision 4): a deferred wake is re-tried ONLY by the queue
# (firefly_bridge.queue, BusyRefused path) with backoff; watchers just read and record.
# deferred_absent is not re-tried at all: the message stays in the PR/inbox.
RETRY_OWNER_QUEUE = "queue"
RETRY_OWNER_INBOX = "inbox"

# Terminal queue state when a deferred wake ran out of attempts: it falls back to the PR/inbox.
DEFERRED_EXPIRED = "deferred_expired"

DEFAULT_MAX_DEFERRED_ATTEMPTS = 8  # 30+60+120+240+480+600+600 s ~= 35 min of re-tries, then inbox

HEARTBEAT_CADENCE_S = 30  # documented writer cadence; max_age_s=120 tolerates ~4 missed beats

PRESENCE_SECTION = "channel_presence"
MAX_STATE_BYTES = 4096


@dataclass(frozen=True)
class PresenceRecord:
    name: str
    ts: float  # epoch seconds
    state: str  # busy | idle | absent (anything else -> unknown)
    task: str = ""
    source: str = ""


@dataclass(frozen=True)
class PresenceConfig:
    max_age_s: float = 120.0
    future_skew_s: float = 30.0
    allow_busy_override: bool = False
    busy_override_principals: tuple = ()
    terminals: dict = field(default_factory=dict)  # canonical key -> path
    max_deferred_attempts: int = DEFAULT_MAX_DEFERRED_ATTEMPTS
    backoff_base_s: float = 30.0
    backoff_cap_s: float = 600.0

    @property
    def configured(self) -> bool:
        """Presence is "configured" only when at least one terminal heartbeat is listed."""
        return bool(self.terminals)


@dataclass(frozen=True)
class Presence:
    state: str  # busy | idle | absent | unknown
    reason: str = ""
    task: str = ""
    age_s: float | None = None


@dataclass(frozen=True)
class PresenceDecision:
    action: str
    sender: str
    principal: str
    target: str
    presence: str = ""  # "" when the gate stopped it before any presence read
    reason: str = ""

    @property
    def retry_owner(self) -> str:
        """Who may re-try this later. Never the watcher; "" = nothing to re-try."""
        if self.action in (DEFERRED_BUSY, DEFERRED_UNKNOWN):
            return RETRY_OWNER_QUEUE
        if self.action == DEFERRED_ABSENT:
            return RETRY_OWNER_INBOX
        return ""


def deferred_backoff_s(attempt: int, *, base_s: float = 30.0, cap_s: float = 600.0) -> float:
    """Delay before the next queue re-try of a deferred wake, after ``attempt`` prior refusals
    (0-based: first refusal -> base_s). Pure; used by ``firefly_bridge.queue.Outbox``."""
    n = max(0, int(attempt))
    return float(min(cap_s, base_s * (2 ** min(n, 16))))


Source = Callable[[str], "PresenceRecord | None"]


# --- config ---------------------------------------------------------------------------------


def parse_presence_config_text(text: str) -> PresenceConfig:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # pragma: no cover - py<3.11: presence disabled (fail closed)
        return PresenceConfig()
    try:
        table = tomllib.loads(text).get(PRESENCE_SECTION) or {}
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("config_toml_invalid") from exc
    if not isinstance(table, dict):
        raise ValueError("presence_section_must_be_table")
    terms = table.get("terminals") or {}
    if not isinstance(terms, dict) or not all(isinstance(v, str) for v in terms.values()):
        raise ValueError("presence_terminals_must_map_name_to_path")
    principals = table.get("busy_override_principals") or []
    if not isinstance(principals, list) or not all(isinstance(x, str) for x in principals):
        raise ValueError("busy_override_principals_must_be_list_of_strings")
    override = table.get("allow_busy_override", False)
    if not isinstance(override, bool):
        raise ValueError("allow_busy_override_must_be_bool")
    attempts = table.get("max_deferred_attempts", DEFAULT_MAX_DEFERRED_ATTEMPTS)
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 100:
        raise ValueError("max_deferred_attempts_must_be_int_1_to_100")
    base = table.get("backoff_base_s", 30)
    cap = table.get("backoff_cap_s", 600)
    for v in (base, cap):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
            raise ValueError("backoff_s_must_be_positive_number")
    if cap < base:
        raise ValueError("backoff_cap_s_below_base")
    return PresenceConfig(
        max_age_s=float(table.get("max_age_s", 120)),
        future_skew_s=float(table.get("future_skew_s", 30)),
        allow_busy_override=override,
        busy_override_principals=tuple(p.strip() for p in principals if p.strip()),
        terminals={sp.norm_name(k): v for k, v in terms.items()},
        max_deferred_attempts=attempts,
        backoff_base_s=float(base),
        backoff_cap_s=float(cap),
    )


def load_presence_config(config_path: str | Path | None = None) -> PresenceConfig:
    path = (Path(config_path) if config_path else sp.default_config_path()).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return PresenceConfig()  # no config: no terminals => every presence is unknown
    return parse_presence_config_text(text)


# --- sources (read-only) --------------------------------------------------------------------


def _parse_ts(raw) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str) and raw.strip():
        text = raw.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    return None


def record_from_mapping(obj: dict, source: str = "") -> PresenceRecord | None:
    if not isinstance(obj, dict):
        return None
    ts = _parse_ts(obj.get("ts"))
    name = obj.get("name")
    if ts is None or not isinstance(name, str) or not name.strip():
        return None
    state = obj.get("state")
    state = state.strip().lower() if isinstance(state, str) else ""
    task = obj.get("task") if isinstance(obj.get("task"), str) else ""
    if obj.get("busy") is True or (task.strip() and state != ABSENT):
        state = BUSY
    return PresenceRecord(name.strip(), ts, state, task.strip()[:200], source)


def read_state_file(path: str | Path) -> PresenceRecord | None:
    """Read-only heartbeat read: regular file only (no symlink/FIFO/special file), small, JSON object."""
    p = Path(os.path.expanduser(str(path)))
    try:
        st = os.lstat(p)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_STATE_BYTES:
        return None
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return record_from_mapping(obj, source=f"file:{p.name}")


def state_file_source(cfg: PresenceConfig) -> Source:
    """Source over `[channel_presence.terminals]`; names without a file give None."""

    def _src(name: str) -> PresenceRecord | None:
        path = cfg.terminals.get(sp.norm_name(name))
        return read_state_file(path) if path else None

    return _src


# --- presence (pure given sources + now) ----------------------------------------------------


def presence(name: str, now: float, sources: Iterable[Source], cfg: PresenceConfig | None = None) -> Presence:
    """Merge fresh records conservatively: any busy -> busy; else any absent -> absent;
    else all idle -> idle. No fresh record / stale / future / foreign name -> unknown."""
    cfg = cfg or PresenceConfig()
    fresh: list[PresenceRecord] = []
    reasons: list[str] = []
    for src in sources:
        try:
            rec = src(name)
        except Exception:  # a broken source is just "no information"
            reasons.append("source_error")
            continue
        if rec is None:
            continue
        if sp.norm_name(rec.name) != sp.norm_name(name):
            reasons.append("name_mismatch")
            continue
        age = now - rec.ts
        if age < -cfg.future_skew_s:
            reasons.append("future_ts")
            continue
        if age > cfg.max_age_s:
            reasons.append("stale")
            continue
        if rec.state not in STATES:
            reasons.append("bad_state")
            continue
        fresh.append(rec)
    if not fresh:
        return Presence(UNKNOWN, reasons[0] if reasons else "no_source")
    newest_age = min(now - r.ts for r in fresh)
    for state in (BUSY, ABSENT):
        hit = [r for r in fresh if r.state == state]
        if hit:
            return Presence(state, "fresh", hit[0].task, newest_age)
    return Presence(IDLE, "fresh", "", newest_age)


# --- wake decision = wake_gate (first) + presence (only for VIP wakes) -----------------------


def wake_decision(
    sender: str,
    *,
    target: str,
    own_aliases: list[str],
    roster: list[str],
    now: float,
    sources: Iterable[Source],
    cfg: PresenceConfig | None = None,
    relay_by: str = "",
    auth: str | None = None,  # DEPRECATED, no effect (always verified from body/comment)
    signed_by: str = "",  # DEPRECATED, no effect
    sender_verified: bool = False,  # DEPRECATED, no effect; never a bypass of HMAC
    body: str = "",
    keyring: dict | None = None,
    comment: dict | None = None,
    created_at: str = "",
    legacy_unsigned: bool | None = None,
    nonce_store: str | Path | None = None,
    claim: bool = False,
) -> PresenceDecision:
    """Verify against transport time (or UTC receive ``now``), never the signed ts.

    All signed wake grants claim (signer, nonce) durably before returning. A second
    grant is refused even for the same comment id. The local +/-600 s freshness
    check also applies with a transport timestamp, so expired ledger rows can be
    pruned safely.

    Deprecated, kept only for signature compatibility: ``auth``, ``signed_by`` and
    ``sender_verified`` are IGNORED (no-ops). The decision always comes from
    ``speaker.verify_comment`` over ``body``/``comment``; passing them neither grants
    nor bypasses anything. They will be removed in a future release.

    ``claim=False`` (default, dry-run): the ledger is read under a shared lock and never
    written; a would-be ``wake`` is reported but the nonce stays unspent. Pass ``claim=True``
    to spend it (``queue_gate`` does). ``nonce_store`` defaults to ``presence_nonces.default_nonce_path()``;
    a corrupt, non-private or unwritable ledger fails closed (``nonce_store_error``).
    Only a granted ``wake`` claims the nonce, so a deferred turn can be retried.
    """
    if not isinstance(now, (int, float)) or not math.isfinite(now):
        return PresenceDecision(
            sp.GATED_NON_VIP, sender, sender, target, "", "invalid_receive_time"
        )
    cfg = cfg or PresenceConfig()
    c = dict(comment) if comment is not None else {"body": body}
    c["created_at"] = c.get("created_at") or created_at or datetime.fromtimestamp(
        now, UTC
    ).isoformat()
    # verify_comment permits revisiting the same API comment id. Presence grants
    # are one-shot: use a new candidate id (1), all persisted ids are 0.
    c["id"] = 1
    _, sig = sp.split_signature(c.get("body") or "")
    # Recipient binding (as gate_comment since #21): a comment whose signed `para:` names
    # neither the target nor its own aliases is `wrong_recipient` and never wakes.
    recipient = [a for a in [*own_aliases, target] if a and a.strip()] or None

    def decide(check, legacy=legacy_unsigned):
        return _presence_after_verification(
            sender, target=target, own_aliases=own_aliases, roster=roster,
            now=now, sources=sources, cfg=cfg, relay_by=relay_by,
            auth=check.auth, signed_by=check.signed_by if check.verified else "",
            legacy_unsigned=legacy,
        )

    if sig is None:
        # An unsigned body has no nonce, so the replay ledger cannot make it one-shot:
        # legacy_unsigned never applies behind the presence gate (signature_required).
        return decide(
            sp.verify_comment(c, keyring, seen_nonces={}, expected_recipient=recipient),
            legacy=False,
        )
    nonce = sig.group("nonce")
    key = ledger_key(sig.group("from"), nonce)
    try:
        with nonce_transaction(nonce_store, now, write=claim) as records:
            seen = {nonce: 0} if key in records else {}
            check = sp.verify_comment(c, keyring, seen_nonces=seen, expected_recipient=recipient)
            if check.verified and records.forgotten(key, int(sig.group("ts")) + sp.SIG_MAX_SKEW_S):
                # expired before the newest pruned row: may have been granted and forgotten
                # (receive clock stepped backwards), so it is stale, never a second wake
                check = sp.SigCheck("stale", check.signed_by)
            if check.verified:
                # A replay carrying its original transport time is still old.
                received = dict(c, created_at=datetime.fromtimestamp(now, UTC).isoformat())
                check = sp.verify_comment(
                    received, keyring, seen_nonces=seen, expected_recipient=recipient
                )
            decision = decide(check)
            if claim and check.verified and decision.action == sp.WAKE:
                records[key] = int(sig.group("ts")) + sp.SIG_MAX_SKEW_S
        return decision
    except NonceStoreError:
        return PresenceDecision(sp.GATED_NON_VIP, sender, sender, target, "", "nonce_store_error")


def _presence_after_verification(
    sender, *, target, own_aliases, roster, now, sources, cfg, relay_by,
    auth, signed_by, legacy_unsigned,
) -> PresenceDecision:
    gate = sp.wake_gate(
        sender,
        own_aliases=own_aliases,
        roster=roster,
        relay_by=relay_by,
        auth=auth,
        signed_by=signed_by,
        legacy_unsigned=legacy_unsigned,
    )
    if gate.action != sp.WAKE:
        # non-VIP / self-echo / unsigned / forged stop here: no presence read at all
        reason = auth if auth in sp.AUTH_FORGED else gate.reason
        return PresenceDecision(gate.action, gate.sender, gate.principal, target, "", reason)
    hmac_verified = auth == sp.AUTH_VERIFIED and bool(signed_by)
    pres = presence(target, now, sources, cfg)
    base = (gate.sender, gate.principal, target, pres.state)
    if pres.state == IDLE:
        return PresenceDecision(sp.WAKE, *base, gate.reason)
    if pres.state == BUSY:
        if (
            cfg.allow_busy_override
            and hmac_verified
            and sp.is_vip(gate.principal, list(cfg.busy_override_principals))
        ):
            return PresenceDecision(sp.WAKE, *base, "busy_override")
        return PresenceDecision(DEFERRED_BUSY, *base, "busy")
    if pres.state == ABSENT:
        return PresenceDecision(DEFERRED_ABSENT, *base, "absent")
    return PresenceDecision(DEFERRED_UNKNOWN, *base, pres.reason or "unknown")


# --- queue gate (the ONE re-tryer is firefly_bridge.queue.Outbox) -----------------------------


def queue_gate(
    *,
    target: str,
    own_aliases: list[str],
    roster: list[str],
    sources: Iterable[Source],
    cfg: PresenceConfig | None,
    now: Callable[[], float],
    keyring: dict | None = None,
    legacy_unsigned: bool | None = None,
    nonce_store: str | Path | None = None,
):
    """Build the ``presence_gate`` for ``Outbox``: ``turn -> PresenceDecision``.

    Returns ``None`` when presence is not configured (no terminals): the queue then behaves exactly
    as before. ``now`` is the epoch clock for heartbeat age (injectable; the queue keeps its own
    monotonic clock for scheduling). A turn has no transport time, so the receive clock
    ``now()`` is the reference; signed grants are claimed in ``nonce_store`` (0600 JSON).

    The gate has a ``release(turn)`` attribute: the queue calls it when the runner raised
    ``BusyRefused`` after this gate granted the turn (nothing was sent), so the nonce is
    un-claimed and the same text can be re-tried while it is still fresh."""
    if cfg is None or not cfg.configured:
        return None
    srcs = list(sources)
    granted: dict[int, str] = {}  # id(turn) -> ledger key this gate claimed for it

    def _gate(turn) -> PresenceDecision:
        text = turn.outbound_text or turn.body
        granted.pop(id(turn), None)
        decision = wake_decision(
            turn.sender,
            target=target,
            own_aliases=own_aliases,
            roster=roster,
            now=now(),
            sources=srcs,
            cfg=cfg,
            body=text,
            keyring=keyring,
            nonce_store=nonce_store,
            legacy_unsigned=legacy_unsigned,
            claim=True,
        )
        _, sig = sp.split_signature(text or "")
        if decision.action == sp.WAKE and sig is not None:
            granted[id(turn)] = ledger_key(sig.group("from"), sig.group("nonce"))
        return decision

    def _release(turn) -> bool:
        key = granted.pop(id(turn), None)
        return bool(key) and release_nonce(nonce_store, key, now())

    _gate.release = _release  # type: ignore[attr-defined]
    return _gate


def queue_kwargs(cfg: PresenceConfig | None, gate) -> dict:
    """``Outbox(**queue_kwargs(cfg, gate))``: {} when presence is off, so the queue is unchanged."""
    if gate is None or cfg is None or not cfg.configured:
        return {}
    base, cap = cfg.backoff_base_s, cfg.backoff_cap_s
    return {
        "presence_gate": gate,
        "max_deferred_attempts": cfg.max_deferred_attempts,
        "backoff": lambda attempt: deferred_backoff_s(attempt, base_s=base, cap_s=cap),
    }
