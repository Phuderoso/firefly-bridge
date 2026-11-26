# Speaker + VIP roster (shared)

`firefly_bridge/speaker.py` is the single place that answers two questions about a canal comment:

1. **Who is speaking?** Body only, in this order: leading `<!-- channel-bot: Nome -->` marker >
   `de:`/`from:` header > `— Nome` signature. The GitHub login is never the speaker (every canal
   comment is posted by the owner's account); it is kept only as `author`.
2. **May this speaker wake a terminal?** `wake_gate()`:
   - the terminal's own name as speaker (e.g. `<!-- channel-bot: peerb -->`) -> `suppressed_self_echo`;
   - a `<!-- agent-relay -->` wakes under agent-a's authority (unless a keyring is in use and the
     relay signature did not verify);
   - otherwise the speaker must be in the roster, else `gated_non_vip` (terminal state);
   - unknown speaker or empty roster -> `gated_non_vip` (fail closed).

Aliases are spelling only and also live in config.toml (no deployment name is compiled in); they
never make anyone VIP. A trailing `[tag]` is dropped generically (`agent-d[ext]` -> `user`).

## The roster: one list, in config.toml

```toml
[channel_roster]
vip = ["agent-a", "agent-b", "agent-c", "agent-d", "owner", "peerx"]

# Spelling only; never makes anyone VIP. "peerc" alone is NOT an alias.
[channel_roster.aliases]
agent-d = ["agentdext", "agent-d[ext]", "agent-d-alt"]
owner = ["ownernick", "ownerlogin"]
peerx = ["peerx"]
```

- The owner (`[channel_roster] owner = "..."`) **never wakes a terminal from body text alone**.
  Naming him as marker, `de:` or `— owner` / `— ownernick` / `— ownerlogin` signature is only a claim:
  `wake_gate` returns `gated_non_vip` / `owner_unverified` unless the comment carries a
  `channel-sig` trailer that verifies against the keyring AND was signed by the owner (or, for a
  `agent-relay` whose `de:` is the owner, signed by agent-a). This holds **also with no keyring**
  (then nothing can be verified, so the owner escalation is simply closed; `send` still works and
  every other VIP behaves as before). The GitHub login is still never a speaker.
- Only `peerx` / `peerx` are VIP. `peerc` alone and other peercs (`peerd`, ...)
  stay `gated_non_vip`.
- An alias spelling claimed by two canonical names is a config error (`roster_alias_conflict`).

Read by `channel-gh roster` (used by `scripts/channel-call`), by a wake watcher, and by `speaker.load_vip_roster()`.
Nothing is compiled in. Missing/empty roster => nobody is VIP and no alias applies: `scripts/channel-call` forwards
everyone via agent-a and wake_watch gates every sender. agent-a stays a direct dest even then (relay).

`channel-gh` calls `speaker.use_config(--config)` so `para: agent-d-alt` matches user for that file.

## Users

- `scripts/channel-gh`: imports the module (installed package, else `../firefly_bridge/speaker.py`
  or `./firefly_bridge/speaker.py` next to the script, else `$FIREFLY_BRIDGE_SPEAKER`) and re-exports
  `comment_sender`, `parse_headers`, `parse_signature`, `bot_marker_name`, `names_match`, ...
  Inbox items gain `speaker_source` and `relay_by`. Subcommands: `channel-gh roster [--canonical NOME]`,
  `send --forward-for NAME`, `send --ack-of ID`, `send --cid ID`, `ack COMMENT_ID [message...]`.
- `scripts/channel-call`: VIP check = `channel-gh roster --canonical=<Bot>`. Non-VIP wrap is
  `send --from "$FROM" agent-a --forward-for "$BOT"`. `CHANNEL_FROM` only peerb or peera.
- `firefly_bridge/wake_envelope.py`: `WakeEnvelope.speaker`; pending card `from` falls back to it.
- `firefly_bridge/canal_cursor.py`: shared `last_seen_<canonical>.json` schema. CLI cursor files
  stay as they are. This module does not import a separate watcher state file.
- wake_watch (staged, separate tree): `safety.wake_gate()` delegates to `speaker.wake_gate()`.

Install note: when `channel-gh` is copied to `~/.local/bin`, also install
`firefly_bridge/speaker.py` to `~/.local/bin/firefly_bridge/speaker.py` (or `pip install` the package).
When `CHANNEL_GH` is a stub in tests, the stub must answer `roster` / `roster --canonical=`.

## Canal HMAC (`channel-sig v=1`)

One trailer format, defined in `speaker.SIG_LINE_RE` and used by `channel-gh` (send/reply/ack sign;
`inbox --for` verifies) and by `speaker.gate_comment()` (resolve + verify + wake gate in one call):

```
<!-- channel-sig v=1 from=Nome ts=<unix> nonce=<hex> mac=<hmac-sha256 hex> -->
```

MAC = HMAC-SHA256(key[from], "channel-sig/v1\n<from>\n<ts>\n<nonce>\n<sha256(all bytes above the trailer)>").
`auth`: `verified | unsigned | unknown_key | bad_mac | sender_mismatch | stale | replayed_nonce | wrong_recipient | no_keyring`.
Present-but-invalid (`bad_mac`, `sender_mismatch`, `stale`, `replayed_nonce`) gates any VIP (`forged_signature`).
Recipient binding: the `para:`/`to:` header is inside the MAC. `verify_comment(..., expected_recipient=aliases)`
returns `wrong_recipient` when a validly signed comment's `para:` names none of the local aliases;
`gate_comment` and `presence.wake_decision` pass `own_aliases` (wake_decision also the `target`) and gate such a comment (reason `wrong_recipient`, strict and legacy
mode alike), and `channel-gh inbox --for` passes its `--for` aliases. A comment without `para:` is not
recipient-bound (relays are routed by their original sender). Without `expected_recipient` the check is off.
A relay only gets agent-a's authority when agent-a itself signed it. Config:
`[channel_identity] name/key_file` (sign), `[channel_keyring] dir` (verify; `<dir>/<nome>.key`),
`channel-gh keygen PATH` (0600, never printed), `channel-gh whoami`.
With `[channel_identity]` bound, `--from` / `CHANNEL_FROM` may only repeat the bound name.

## R3: wake authority only from a verified signature (default)

`wake_gate` / `gate_comment` grant a wake ONLY when the comment's `channel-sig` trailer verified
AND was signed by the speaker (or, for `<!-- agent-relay -->`, by agent-a). Marker, `de:`,
`— Nome` and the relay marker without a valid trailer are display text (reason
`signature_required`). Messages are still sent, delivered and shown in full; `inbox --for` marks
them `(não verificado: <auth>)`. Send is never blocked.

**Cost:** with no `[channel_keyring]` nothing verifies, so nothing wakes. While keys are rolled
out, `[channel_wake] legacy_unsigned_wake = true` (default false; only TOML `true`/"true" counts;
an invalid config stays strict) restores the pre-HMAC rule for NON-owner VIPs. The owner always
needs their own signature, and a present-but-invalid trailer is always gated (`forged_signature`).

Watchers (wake_watch) must call `speaker.gate_comment(comment, own_aliases=…, roster=…, keyring=…,
seen_nonces=…)` on the raw comment — never `wake_gate` with a self-computed `auth`.
