# Channel presence/occupancy (dry-run decision layer)

`firefly_bridge/presence.py` answers "may we knock on terminal X now?" before any wake/knock.
It is pure and read-only: injectable sources plus one reader for a small JSON heartbeat file.
No process, socket, tmux, launchd, TUI or `--live` path. Wired only as a DRY-RUN `--presence` flag
(`channel-knock` here; `wake_watch` on its own staged branch) that prints/logs the decision.

## Order (fixed)

1. `speaker.wake_gate(sender, ...)`: non-VIP → `gated_non_vip`, self-echo → `suppressed_self_echo`.
   These stop here; **no presence read happens**.
2. Only for a VIP `wake`: `presence(target, now, sources, cfg)`.

| target presence | action | notes |
|---|---|---|
| `idle` (fresh) | `wake` | the only state that knocks |
| `busy` (fresh) | `deferred_busy` | queue, don't knock; see override below |
| `absent` (fresh) | `deferred_absent` | message stays in PR/inbox |
| `unknown` (no source, stale, future ts, foreign name, bad state, read error) | `deferred_unknown` | fail closed, never forced |

Several sources merge conservatively: any fresh `busy` → busy; else any `absent` → absent; else idle.

## Decisions

1. **Busy is never overridden today, owner included.** `allow_busy_override=false` stays. The hook
   is kept off: it could only ever apply when the flag is on **and** the principal is in
   `busy_override_principals` **and** `wake_decision(..., sender_verified=True)`. Nothing sets
   `sender_verified` yet (it is reserved for canal HMAC). A typed signature never counts.
2. **Each VIP terminal writes its OWN heartbeat** (self-declared) from a passive hook it already runs.
   No writer daemon is shipped and none is installed on the Mac. Spec below; the pure helper is
   `firefly_bridge/presence_heartbeat.py` (`build_heartbeat`, `write_heartbeat`: one call, no loop).
3. **Cadence 30 s, `max_age_s = 120`** (≈ 4 beats; configurable). Older → stale → unknown → deferred.
4. **Re-try of a deferred wake has ONE owner: the queue** (`firefly_bridge.queue`, `BusyRefused`
   path) with backoff (`presence.deferred_backoff_s`: 30 s doubling, cap 600 s). Watchers only read
   and record the decision; they never re-try or schedule. `deferred_absent` is not re-tried at all
   (stays in PR/inbox). `PresenceDecision.retry_owner` says which (`queue` / `inbox` / "").
   Wired into `queue.py`: see "Queue backoff" below.
5. **Presence belongs to the target; VIP is a gate on the sender.** A target outside the VIP roster
   (e.g. peerb) may have presence; a non-VIP sender never reaches the presence read.

## Heartbeat spec

* Path: `<state_dir>/<slug(name)>.json`, slug = lowercase `[a-z0-9._-]`, e.g. `peerb.json`; each reader
  lists it under `[channel_presence.terminals]`.
* Write: temp file in the same directory → `fsync` → `os.replace` (atomic) → best-effort
  directory `fsync`, mode 0644, ≤ 4 KiB.
* Cadence: every 30 s while alive, plus on each state change (turn start → busy, turn end → idle,
  clean exit → absent). Missing writer = unknown = deferred (fail closed).

## Heartbeat writer

The reader is unchanged: `presence()` only looks at the `.json` file. Missing, unreadable, stale
(`age > max_age_s`) or too-far-future (`age < -future_skew_s`) files are **unknown**, not absent.
`absent` is a fresh, explicit `state: "absent"` (clean exit). The queue treats them differently
(unknown is retried; absent goes to the inbox).

`firefly_bridge.presence_heartbeat` is still a one-shot helper (no loop, no daemon). The terminal's
own wrapper calls it, with an injectable clock (`now=`). Tokens stay zero: busy vs idle comes from a
local `<slug>.turn` marker, never from a model or from inspecting another process.

| hook | when | file effect |
|---|---|---|
| `start_session` | session up, not in a turn | clear leftover `.turn`, write `idle` |
| `begin_turn` | turn start | write `.turn` (0600) + `busy` |
| `tick_heartbeat` | every 30 s while alive | refresh `ts` from the marker (busy if present, else idle). Never writes `absent`. Refuses a closed (`absent`) session without reading `.turn`. Ignores a leftover `.turn` whose `ts` or mtime is not newer than the last idle heartbeat. Applies the same `future_skew_s` clamp as `presence()` to the marker's declared ts: a ts beyond the skew is untrusted and cannot become busy. A non-regular `.turn` (symlink, etc.) is refused via `lstat` before any decision. If the heartbeat JSON is unreadable, the tick leaves it alone (`unknown`, fail closed) and does not consult `.turn`. |
| `end_turn` | turn end | write `idle`, then clear `.turn`. Unlink errors other than FileNotFound propagate; `idle` stays. Refuses a closed session. |
| `leave` | clean exit | write `absent` first, then clear `.turn` (an unlink error is raised, but `absent` stays). Only `start_session` reopens. |

Writers share an exclusive `<slug>.lock` (`fcntl.flock`, with compare-before-replace even if flock
is unavailable). Directory must already exist (the helper will not create `~/.grok/...`). Recommended
mode 0700 for the directory, 0644 for the json, 0600 for the marker and lock. One-shot CLI:
`python -m firefly_bridge.presence_heartbeat {start|begin|end|tick|leave} --dir DIR --name NAME`.

No writer is installed by this package. A terminal turns its own writer on only when
that terminal's user asks for it. Do not attach to another session to install it.

## Heartbeat file

Written by the terminal itself (writer not part of this change); read with `lstat` (regular file only,
≤ 4 KiB, no symlinks):

```json
{"name": "peerb", "ts": 1763130000, "state": "busy", "task": "draft notes"}
```

`state` ∈ busy|idle|absent; a non-empty `task` or `"busy": true` also means busy. `ts` = epoch or ISO-8601.
The `name` must match the target (aliases via the roster config), otherwise unknown.

## Config

```toml
[channel_presence]
max_age_s = 120
future_skew_s = 30
allow_busy_override = false      # decided: off (see decision 1)
busy_override_principals = []    # only with the flag AND sender_verified=True
max_deferred_attempts = 8        # queue: busy/unknown refusals before deferred_expired (1..100)
backoff_base_s = 30              # queue: first re-try delay, doubles per refusal
backoff_cap_s = 600              # queue: delay ceiling

[channel_presence.terminals]
peerb = "~/.grok/channel/presence/peerb.json"
```

Busy override would need the flag, the principal in the list and a verified sender; it never covers
absent/unknown. Today: nobody knocks on a busy terminal, owner included.

## Signature freshness and replay (B1)

`wake_decision` / `queue_gate` never derive a transport time from the signed trailer's `ts`.

* Reference time: the transport `created_at` (GitHub API comment object) when the caller has one;
  otherwise the local receive time `now` (UTC). In both cases `|now − ts| ≤ 600 s` is also required,
  so a body signed 30 days ago is `stale` and never wakes, even carrying its original `created_at`.
* Replay: every granted `wake` claims `(signer, nonce)` in a persisted ledger
  (`presence_nonces.nonce_transaction`, JSON `{"v": 1, "nonces": {...}}`, file and `.lock` 0600,
  `O_NOFOLLOW`, `flock`, atomic `os.replace` + `fsync`). A second grant of the same nonce is
  `replayed_nonce`, also across processes and restarts. Only a granted wake claims; a
  `deferred_*` turn can be re-tried by the queue. Rows are pruned once `ts + 600 < now`, which is safe
  because such a body is already `stale`. The ledger also keeps `"watermark"`, the highest expiry
  ever pruned (never lowered): a body whose `ts + 600` is at or below it is `stale` even if the
  receive clock later stepped backwards, so a pruned grant cannot wake twice. Caveats: deleting the
  ledger file resets the watermark; the watermark only rises to expiries of bodies that were
  actually granted, so a forward clock jump does not by itself block later wakes.
* Receive time: a NaN or infinite `now` is `gated_non_vip`, `reason=invalid_receive_time`
  (no ledger access).
* Unsigned bodies: there is no nonce to claim, so behind the presence gate `legacy_unsigned`
  does **not** apply; an unsigned VIP body is `signature_required` in every mode.
* Ledger path (ONE default for the queue and the knock): `nonce_store=` / `--nonce-store`; else
  `$CHANNEL_PRESENCE_NONCES`; else `~/.local/state/firefly-bridge/presence-nonces.json`.
  `channel-knock --presence` also takes `--created-at` (GitHub API `created_at`).
* Dry-run is read-only: `channel-knock --presence` reads the ledger under a shared lock and
  writes nothing (`ledger=read_only`; a fresh body prints `action=wake`, an already granted one
  `reason=replayed_nonce`). Only an explicit `--claim` spends the nonce (`ledger=claimed`).
  `wake_decision` defaults to `claim=False` (read only); pass `claim=True` to spend the nonce.
  `queue_gate` always claims. With `--claim` the knock prints `presence (claim): …` and logs
  `mode=claim` (it still never knocks).
* Fails closed with `gated_non_vip`, `reason=nonce_store_error`: a corrupt, wrong-version,
  oversized (> 1 MiB) or deeply nested, non-private or symlinked ledger or lock; a ledger
  directory that is a symlink, group- or other-writable or not ours; a failed save. Errors from presence sources or the wake gate are
  *not* reported as ledger errors (the queue records them as `presence_gate_error`).
* Ledger key: the signer's base name (`speaker._base_key`, the same name the MAC signs; aliases are
  not applied) plus the nonce.
* `wake_decision`'s `auth=`, `signed_by=` and `sender_verified=` are deprecated no-ops: they are
  kept in the signature but ignored; verification always comes from the body/comment.
* `BusyRefused` after a grant: nothing was sent, so the queue calls the gate's `release(turn)`,
  which un-claims the nonce this gate granted for that turn (exclusive lock, durable save). The
  deferred retry of the same text can then wake while the body is still fresh; a copy of a body
  that was actually delivered stays `replayed_nonce`.

### Known limitation (pre-existing): daemon turns are signed with `msgsig`, not `channel-sig`

The daemon's `sign_outbound` (`daemon.py` `_sign_outbound` → `session.build_outbound` →
`envelope.sign_text`) produces an `msgsig` trailer. `queue_gate` verifies `turn.outbound_text`
(which takes precedence over `body`) as a `channel-sig` canal body, so today **every daemon turn
would be `gated_non_vip signature_required`** under a presence gate. This predates the B1 fix and
is invisible today only because `presence_gate` is not wired into the daemon. It must be resolved
(one signature format the gate verifies, re-signed per attempt) **before** presence is wired to the
daemon. This series does not wire it.

## Dry-run flags

* `channel-knock --presence --from NAME --body SIGNED [--created-at ISO] [--nonce-store F] [--target peerb] [--config F] [--presence-log F.jsonl]`
  prints `presence (dry-run): action=… reason=… retry_owner=…`; shows the knock sequence only for
  `wake`; never attaches. `--presence --live` is refused. Without `--presence` nothing changes.
* `wake_watch.watcher once --dry-run --presence`: after the VIP gate, logs `presence_decision`; deferred
  items are recorded `deferred_*` (owner: queue/inbox) and never re-tried by the watcher.

## Queue backoff (single re-tryer)

`firefly_bridge.queue.Outbox(..., presence_gate=gate, max_deferred_attempts=N, backoff=fn)` is the
**only** place a deferred wake is re-tried. Build the arguments with
`presence.queue_kwargs(cfg, presence.queue_gate(target=..., own_aliases=..., roster=..., sources=..., cfg=cfg, now=time.time))`.
When presence is not configured (no `[channel_presence.terminals]`), `queue_gate` returns `None`,
`queue_kwargs` returns `{}` and the queue behaves exactly as before (no gate, `BusyRefused` from the
runner still settles `failed`, `busy_wait_s` expiry unchanged).

With a gate, before each dispatch the queue asks the gate about the head-eligible turn:

| gate action | queue does | turn state |
|---|---|---|
| `wake` | dispatch as usual | `in_flight` → … |
| `deferred_busy` / `deferred_unknown` / gate error | `attempts += 1`; `next_attempt_at = now + backoff(attempts-1)` | `deferred` (still queued) |
| same, and `attempts == max_deferred_attempts` | removed from the queue, `route = "inbox"` | `deferred_expired` (terminal) |
| `deferred_absent` | removed, `route = "inbox"`; **never re-tried** | `deferred_absent` (terminal) |
| `gated_non_vip` / `suppressed_self_echo` (incl. `stale` / `replayed_nonce`) | removed, `route = "inbox"` (no wake; the message is not lost) | `failed` |
| anything else | removed, `route = "inbox"` (fail closed) | `failed` |

* A `BusyRefused` raised by the runner (nothing was sent) follows the same `deferred_busy` path.
* Only turns with `now >= next_attempt_at` are eligible; a not-yet-due turn is not even re-read and
  does not block other turns. Deferred turns are bounded by `max_deferred_attempts`, not `busy_wait_s`.
* Default schedule (8 attempts): 30, 60, 120, 240, 480, 600, 600 s between reads (~35 min), then
  `deferred_expired` → the message stays in the PR/inbox for the reader; nothing is dropped.
* **Scheduled, not polled:** `Outbox.next_due_at()` gives the earliest `next_attempt_at`; the caller
  arms one timer for it (or pumps on the next real event). The queue never loops or sleeps.
* Receipts carry `attempts`, `next_attempt_at`, `presence_action`, `route`; `status()` lists
  `deferred` items and `next_due_at` when a gate is set.
* **Watchers only read.** `wake_watch.watcher` records `deferred_*` once and afterwards logs only
  `skip_deferred`; it never calls `enqueue_wake` for them, never schedules, never imports the queue.
* Not wired into `daemon.py`'s live Outbox yet (no `--live` path uses presence).
