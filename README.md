# firefly-bridge

Built by one human and four Grok agents, with occasional help from Gemini.

Signed (HMAC), deny-by-default IPC and wake bridge for AI agent terminals.

Same-machine broker. One configured agent can message another agent's
already-running terminal session through that session's private leader socket.
An optional GitHub pull-request comment channel (`scripts/channel-gh`) sits on
the same broker.

There is no network listener, no cross-host transport, no new or forked
session, and no forced wake. Live send is off until you set it.

Names in this repository (`agent-a`, `agent-b`, `agent-c`, `peerb`, `owner`)
are placeholders. Put your own in config.

## Install

Python 3.11 or newer. Clone the repository and install it from that checkout:

```bash
git clone https://github.com/Phuderoso/firefly-bridge
cd firefly-bridge
pip install .
```

Once the package is published to PyPI, the install becomes `pip install firefly-bridge`.

For tests, use `pip install -e ".[dev]"`.

## Quickstart

Save this as `quickstart.py` and run `python quickstart.py`. It creates a
mode-0600 key, signs one message with HMAC-SHA256, and verifies that signature.
It does not open a socket or use the network.

```python
import tempfile
from firefly_bridge.envelope import generate_key_file, load_key, sign_text, verify_text

key = load_key(generate_key_file(f"{tempfile.mkdtemp()}/demo.key"))
signed = sign_text(
    key,
    prefix="agent-a: ",
    sender="agent-a",
    session_id="sess-demo-0001",
    message_id="id_demo_0001",
    body="hello",
)
result = verify_text(key, signed, expected_sender="agent-a", expected_session_id="sess-demo-0001")
print(result.valid)
```

The program prints `True`.

## Authors

- Phuderoso (human) — project director
- PHASEONE (Grok agent) — coordinator
- Firefly (Grok agent) — lead developer and maintainer
- Pip (Grok agent) — security reviewer
- Lume (Grok agent) — analyst and reviewer
- Gemini (Google model) — occasional consultant



## Configure

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/firefly-bridge"
cp examples/config.example.toml "${XDG_CONFIG_HOME:-$HOME/.config}/firefly-bridge/config.toml"
cp .env.example .env   # optional; leave secrets empty
```

Every `BridgeConfig` field can also be set as `FIREFLY_BRIDGE_<FIELD>`.
`.env.example` lists those variables plus the channel helpers. Paths may use
`~`. Key fields point at mode-0600 files; do not paste key bytes into config.

Start with `examples/config.example.toml`. `config/example.toml` is a second
profile with the same safe defaults (pending, `live_send = false`).

## Security defaults

| Control | Default |
| --- | --- |
| `live_send` | `false` |
| per-agent permission mode | `pending` (no auto-approve) |
| `allow_all_own_turns` | off; opt in per agent if you accept the warning |
| `protected_tools_enabled` | `true` |
| `strip_grok_sandbox` | `false` |
| VIP roster | empty when config is missing (nobody is VIP) |
| owner HMAC key | refused; owner speaks through a signed relay |
| unsigned wake | off (`legacy_unsigned_wake` defaults false) |
| knock `--live` | refused unless `CHANNEL_KNOCK_LIVE=1` and the gate file exist |

See [THREAT_MODEL.md](THREAT_MODEL.md) for what this does and does not contain.

## Tests

```bash
ruff check .
pytest
```

CI runs ruff, pytest on Python 3.11–3.13, and gitleaks over the branch history.

## Layout

- `firefly_bridge/` — broker, permissions, wake adapter, speaker/roster, HMAC
- `scripts/channel-gh` — GitHub comment channel
- `scripts/channel-keygen` — per-sender HMAC files
- `scripts/channel-call` — send helper (VIP direct, others via `CHANNEL_RELAY`)
- `scripts/channel-knock` — dry-run receive half
- `examples/config.example.toml` — every documented setting, placeholders only

## Start offline

```bash
PYTHONPATH=. uvx pytest -q
python3 -m firefly_bridge doctor --config examples/config.example.toml
python3 -m firefly_bridge enqueue --local --text 'offline example'
```

`doctor` only reads local snapshots/source hashes and socket metadata. It never
attaches, prompts, reads private app databases or queries an invented scheduler
API. Its live state and scheduler/7-day expiry remain **unknown**. A snapshot,
PID or configured session ID is not proof of a live session.

## What changed

* agent-a's ownership contract: initiator-issued random turn ID + nonce, sender,
  message ID, session and incarnation. Only matching **server-attested** live
  `turn_started`, permissions and agent chunks belong to that turn. Prefixes,
  queued/waiting state, OCR, echo and load replay prove nothing.
* One exclusive broker per target, authenticated Unix IPC, separate principal
  credentials and broker-generated `agent-a: ` / `agent-b: ` / `agent-c: ` prefixes.
  These are **agents, never human instructions**; human-user/human/recipient names
  cannot be claimed as senders. Presentation controls are rejected in bodies.
* Private SQLite ledger commits accepted IDs and send attempts durably **before
  write**. Same ID/different sender or body is a conflict. Restart never replays:
  queued IDs close, dispatched IDs become `unknown` and block the target.
* Busy, stale or unknown remote state blocks dispatch. A fresh atomic admission
  revision is required at the write, not just an idle guess. Human and recipient
  opt-ins are both required, scoped to sender and pinned destination.
* Human pause or recipient `/basta` closes the channel, stops auto-approvals and
  removes local waiters durably. No timer resumes it; both must opt in again.
  Text **quoting** `/basta` is not control. Use authenticated control, not OCR.
* Timeout only ends observation. It **never** sends cancel or rejects a pending
  permission. `unknown` retains the remote lease. Agents may only withdraw
  queued messages. Only authenticated human/recipient authority can request
  **own, attested, scoped** cancellation; no slot is released until a matching
  terminal proves the remote turn ended. No global cancel fallback.
* Sender quotas, byte/frame/reply limits, FIFO-with-sender-rotation and capped
  queue. Default: one pending per sender, three accepted IDs/day (UTC window),
  30-minute **per-sender, per-pinned-destination** dispatch cooldown; queue TTL
  1800 seconds. The per-sender floor is independent; an additional **target-wide**
  600-second start interval and 60-second **post-terminal** interval apply to all
  configured agents. Optional zoned quiet hours block new dispatch, not an active turn.
  TTL must cover each configured cooldown (equality is eligible at expiry).
  Quiet time never schedules a ping, retry or automatic opt-in.
* Content-minimal audit and fail-closed redaction. Validated protocol IDs/states
  are independent of the fallible text redactor; ledger lookups reconstruct them
  from authoritative typed columns, including old RC1 marker-contaminated JSON. Only correlated agent-message
  chunks are captured; thought/replay/foreign chunks are ignored. Redacted replies
  are owner-only in memory (last 32), not stored as history. On missing/invalid chunks or redaction failure, the broker tries the bounded,
  origin-bound `ChatHistory` recovery interface. Its shipping implementation is a
  **fail-closed stub**: no proven API => `reply_recovery_unavailable`, never a
  recovery prompt, private-file scrape or resend. See docs/RECOVERY.md.

## Independent per-client permission policies

One line per sender, independently. The public/library defaults all stay
`pending`; a global non-pending `permission_mode` is now rejected instead of
silently affecting other clients:

```toml
agent_a_permission_mode = "pending"
agent_b_permission_mode = "pending"
agent_c_permission_mode = "pending"
```

| Mode | On an attested own turn with active consent |
| --- | --- |
| `pending` (default) | No approval; nonprotected requests remain pending. Protected requests are denied by the independent gate. |
| `allowlist_shared` | `allow_once` for nonprotected edits resolving inside `shared_dir`; legacy `allowlist` is an alias. |
| `allow_all_own_turns` | **DANGER: AUTO-APPROVES ELIGIBLE TOOLS/PATHS** on that client's attested own turn, subject to the protected-tool gate below. Loud sender-labelled warning; `allow_all` is a spelling alias. |

All modes are silent for foreign/unverified turns, replay and observer mode.
None selects `allow_always` or changes trust/sandbox. Permission delivery back
to the human TUI is **not implemented/supported here**. Pending can leave a turn
waiting indefinitely; it is not magically interactive. Do not enable live
conversations requiring tools until a supported human-decision surface exists.
Tool permissions already granted by the leader are outside this client's control.
Both shipped examples keep every agent at `pending` and `live_send = false`.
`allow_all_own_turns` is off unless you set it for one agent in your own config.

## Runtime authority fencing (RC5)

Permission modes are unchanged, including deployment `allow_all_own_turns`.
Before **every own permission decision**, the broker now requires its current
active target authority and the exact durable initiator claim for that in-flight
turn. It checks again after audit, at the approval response action; response and
authority close are serialized. Foreign/unattested requests remain silent.
A lost authority selects only an offered `reject_once`, otherwise stays silent;
it never approves, force-cancels, invents terminal proof or retries a message.

The key is the pinned session plus the socket's resolved path, conservatively
Unicode/case-normalized (possibly overblocking distinct Linux paths). It is
independent of state DB and runtime selection. Two private, nonblocking exclusive
locks are held: the runtime `<target-digest>.lock` and a stable per-UID fence under
`/tmp/firefly-bridge-authority-<uid>`. Thus unlinking just the runtime file still
cannot let a second broker claim the target, even with another DB/runtime.
Different targets can run concurrently. Lock files are 0600 and roots 0700; public
random generation markers are coordination metadata, **not credentials**.

Every check validates directory/file ownership, mode, device/inode, generation,
PID and exclusive-lock possession. Missing/replaced/tampered/downgraded locks latch
the incarnation closed; no silent reacquisition. Status `authority` reflects this
health, not merely a non-None descriptor. Dispatch/claim/pre-write checks also
fail closed. Unknown committed turns remain unknown and consumed on authority loss.

Both lock files and their **whole runtime/fence directories**, including
ancestors and canonical aliases, are protected from structured read/write/delete/
move requests. This authority-path check and runtime ownership requirement remain
mandatory even with `protected_tools_enabled=false` (`laws.authority_required=true`);
`laws.enforced` still describes the configurable general protected-tool gate.
Opaque execution with that gate disabled, preauthorized tools and hostile same-UID
filesystem changes are **not** contained by this check. It is not an OS sandbox.

Never unlink lock files on shutdown: closing owned descriptors releases authority.
Stop old broker versions before upgrade; no mixed-version/live rolling handoff is
validated. Do not change DBs to recover unknown attempts: fencing does not merge
ledgers or transfer durable anti-resend history. Actual leader admission/attestation
and filesystem behavior on the Mac still require separately authorized validation.

## Protected tools and useful receipts (RC4)

`protected_tools_enabled = true` is independent of permission mode, including
every configured permission mode. A mode or embedded policy cannot bypass the
broker-owned gate. It denies requests involving TCC/macOS permission dialogs,
credentials/secret stores, external messages/posts, Funnel/network exposure,
tmux injection/send-keys, duplicate-agent merges, and the closed placeholder
orders `closed_order_alpha` and `closed_order_beta`. These are enforced on **received permission
requests**, not just listed in status.

A keyword scan is **not a shell sandbox**: opaque execution/scripts, indirect
MCP/network tools, unknown kinds and unclassifiable input fail closed. Locally
classifiable file read/edit/delete requests require structured paths; known
protected paths and symlink aliases are denied. Broad mode can still approve
nonprotected file operations **outside** `shared_dir`; this gate is not a switch
to `allowlist`. It relies on honest leader tool metadata and cannot recognize
arbitrary secrets in arbitrary files or control already-authorized tools.
Use actual executor isolation for stronger containment.

RC4 also protects **known bridge resources by configured path identity**, even
when their filenames contain no secret-related keyword: the entire IPC key and
state/ledger directories, HMAC/client key files, the loaded configuration source,
default config directory and conventional local ledger directory. Read, edit and
delete are denied. Comparison retains lexical and real paths (symlinks before
`..` resolution), normalized Unicode/case, relative session paths and configured
paths resolved against the daemon cwd. Ancestors are conservatively protected
against recursive reads/deletes; sibling filename prefixes are not. Only path
metadata is inspected, never key contents. `load_config` records the actual
`config_path`; a TOML/env field cannot disguise its source. Embedders must supply
`config_path` for a custom source not loaded through that function. Case-insensitive
comparison intentionally overblocks on case-sensitive filesystems. These checks
are not hostile-filesystem/TOCTOU or arbitrary-hardlink isolation.

Explicit single-line opt-out: `protected_tools_enabled = false`. This disables
the mandatory tool gate **without changing any sender's mode**, and status shows
`laws.enforced=false` (mandatory RC5 authority checks still apply). Broad mode can then approve unrestricted shell/network
requests; no OS/hostile-same-UID containment is claimed. The shipped examples
leave protection on and live sending off.

On a protected own request the broker records denial intent and uses only the
offered `reject_once`. If absent, it sends no response. Both cases suspend further
automatic approvals for that turn; there is no approval fallback, global cancel
or answer to a foreign permission. Ordinary `pending` is still silent.

Private receipts/audit include tool kind, tool/RPC identifiers and canonical
**target SHA256 fingerprints**, not raw commands/paths/addresses. `decision_intent`
is durable before a permission response; `response_sent` means a transport write,
**not tool execution**. Missing that marker is ambiguous, never permission to
retry. Epoch times have ISO local equivalents with offset and
`timezone="UTC"`; monotonic queue timestamps remain duration-only.
Authenticated pause, `/basta`, revoke and scoped opt-ins have transactional actor /
scope / generation / local-time history, exposed via filtered `status`; receipts
include the owner's permission events. Audit retains the latest **1000** events
per target and exposes at most **100**; approval JSONL rotates at 1 MiB plus one
previous segment. Deduplication claims are not pruned. Fingerprints are correlators,
not anonymization of guessable filenames. No prompt/reply history is added.

## Experimental leader adapter — fail closed without it

The attestation contract is **experimental and unvalidated against real grok-tui**.
The package does NOT assert that the installed leader implements these extensions.
See [the exact proposed contract](docs/ATTESTATION.md). In particular, the leader
must advertise turn attestation and **atomic** admission, echo the initiator's
proof on live events/terminal results, and attest session incarnation. Scoped
cancel is separately negotiated. Missing support => no `session/prompt`, no
permission response, no global cancel. No configuration boolean pretends support.

Until that contract is implemented/verified, stay offline. No live migration or
Mac cutover was performed. The user's opt-in is a coordinated human window,
not detection of draft typing; the bridge never inspects the compositor.

## Configuration and local IPC

Copy `examples/config.example.toml` to a private file, using placeholders for the
leader socket/session/cwd and a **different state_dir per destination**. TOML
`[bridge]` and `FIREFLY_BRIDGE_<FIELD>` environment overrides are supported.
`live_send=false` is a strict observer: never prompt, cancel or approve.
`strip_grok_sandbox=false` stays the default; do not change sandbox to make tests pass.

RC1 configuration migration: replace global auto-approval with the explicit
`agent_a_permission_mode` / `agent_b_permission_mode` / `agent_c_permission_mode` lines.
The legacy `global_interval_s` name is accepted only as an extra **per-sender**
cooldown floor; it no longer serializes different clients. New configs use
`sender_interval_s` and leave that legacy field at zero. The **new**
`target_interval_s` is the real target-wide start floor; `post_turn_interval_s`
starts after any confirmed terminal, including a long turn or reconciliation.
These timestamps persist across restart. RC2 completed attempts without a civil
terminal time conservatively start their post-terminal floor at migration.
`busy_wait_s` must cover the maximum of the sender/legacy, target-wide and
post-terminal floors; it does not promise delivery during quiet hours or busy
periods. A waiter that expires is closed, never accumulated for tomorrow.

```toml
pacing_minimums_enabled = true
post_turn_interval_s = 60
target_interval_s = 600
quiet_hours_start = "22:00"  # both empty strings disables quiet hours
quiet_hours_end = "08:00"
quiet_hours_timezone = "UTC"
```

With `pacing_minimums_enabled=true` (default), 60/600 seconds are **minimums**:
smaller values, including zero, require the explicit user opt-out
`pacing_minimums_enabled=false`. Status exposes that flag. Opt-out does not bypass
finite-value/bounds validation, consent, sender cooldown or any leader guard.

Quiet ranges are start-inclusive/end-exclusive, may cross midnight and follow
civil DST (both repeated hours are quiet). Equal endpoints, partial ranges,
invalid HH:MM/zones and nonfinite/negative/out-of-range timers are rejected.
Quiet hours prevent new dispatch/claims, never cancel a running turn or revoke
consent. If quiet time starts between queue admission and the durable claim,
RC4 commits a local `failed / rejected_quiet_hours` receipt with `rejected_at_local`,
no attempt/proof/RPC, clears local ownership and releases the local slot. That ID
remains consumed: no automatic retry. Restart reconciles old unknown rows lacking
**both** attempted timestamp and proof as `reconciled_pre_send_rejection`; committed
or ambiguous attempts remain unknown and blocked. Only the typed durable
pre-write refusal takes this path, never an arbitrary IO/transport exception. An open window still requires the unchanged live/consent/leader gates.

Provision distinct 0600 keys outside the repository, one each for `agent-a`,
`agent-b`, `agent-c`, `human`, `recipient` using `keygen --path <private-file>`. The daemon
uses `ipc_keys_dir`; each CLI client uses its own `ipc_principal` and
`ipc_key_file`. The human/recipient credentials must never be handed to agents.
Optional outbound `auth_mode="hmac"` signing is separate from mandatory IPC auth;
it is not turn ownership and does not replace a trusted leader channel.

Only after approved lab validation and adapter support:

```bash
python3 -m firefly_bridge daemon --config daemon.toml
python3 -m firefly_bridge status --config agent-client.toml
# Each opt-in is performed by its actual authenticated authority:
python3 -m firefly_bridge control --action opt_in --senders agent-a --config human.toml
python3 -m firefly_bridge control --action opt_in --senders agent-a --config recipient.toml
python3 -m firefly_bridge enqueue --message-id example-unique-id --text 'hello' --config agent-client.toml
python3 -m firefly_bridge receipt --message-id example-unique-id --config agent-client.toml
python3 -m firefly_bridge control --action basta --config recipient.toml
```

IPC is a 0600 Unix socket inside a 0700 state directory. HMAC covers version,
principal, target, operation, args, timestamp and nonce. Nonce replay defence is
durable. No TCP bind, HTTP proxy or Funnel exists. Same-UID code can steal keys;
this is **not** isolation from malicious processes under the same OS account.

Do not point an empty ledger at an old installation: nonempty legacy receipts
require explicit migration/reconciliation and are refused, not discarded. Preserve
old IDs, claims, vetoes and backups. New databases cannot know IDs outside them.

## Reply integrity and public API (RC4)

The proposed adapter now requires **1-based contiguous** agent `chunkSeq` values.
Gaps, missing starts, invalid sequences and mismatched terminal `chunkCount` never
produce verified partial content; they use only bounded, origin-exact history
recovery (still a stub here), otherwise return reply unavailable without resend.
Duplicates/replay/foreign/thought chunks never duplicate content.
`reply_origin_verified` concerns attested origin;
`reply_stream_contiguous` concerns observed capture;
`reply_verified` means origin-bound content rendered without detected loss, **not**
a proof that an unseen suffix does not exist. `reply_complete=true` additionally
requires an attested matching terminal `chunkCount`, or a successful trusted
history adapter returning the complete logical reply. Without either, completeness
is unproven/false. No real leader capability or history API was added/validated.

Backward-compatible `from firefly_bridge import Bridge, Receipt` exports are
restored lazily; runtime/project/doctor/initialize version is `0.4.0`.

Wake versus tool is documented in [docs/WAKE_VS_TOOL.md](docs/WAKE_VS_TOOL.md).
`kind: recado` is the default and is text only. `kind: tool_request` is also
text. The channel profile stays `pending`. Another agent's
`allow_all_own_turns` is not applied to a wake.

## GitHub comment channel

`scripts/channel-gh` posts and reads comments on a GitHub pull request used as
an async channel. Point it at your own repository and pull request.

Configure a local, uncommitted file (`~/.config/firefly-bridge/config.toml`):

```toml
[github_canal]
repo = "Owner/channel-canal"
pr = "1"
```

Or set `FIREFLY_BRIDGE_GITHUB_CANAL_REPO` and `FIREFLY_BRIDGE_GITHUB_CANAL_PR`.

```
channel-gh send agent-a "hello from the TUI" --from peerc
channel-gh inbox --since 2026-01-01T00:00:00Z
channel-gh inbox --wait 120
channel-gh inbox --for peerb,peera --mark-read   # only what is addressed to this name, once
channel-gh reply 1001 "thanks" --from peerb
```

`inbox --for NAME[,ALIAS]` lists comments addressed to that terminal (a leading
`para:`/`to:` naming it, or relay replies to messages it signed) as compact text
in UTC time (`$CHANNEL_TZ` overrides). `--mark-read` advances a
per-name cursor in `~/.grok/channel/last_seen_<name>.json`
(`$CHANNEL_STATE_DIR` overrides) so nothing is delivered twice. Output is empty
with exit 0 when nothing is new. `reply <id>` answers the author of that comment
and appends `<!-- reply-to: <id> -->`. The id is the comment id printed by
`inbox`, not a fixed value.

Outbound comments use a first line `para: <BotName>`, then the message, signed
`— <sender>` (`--from` or `$CHANNEL_FROM`, otherwise `hostname-user`).
Inbound agent-a relays start with `<!-- agent-relay -->` and `**de: <Bot>**`.
`channel-gh relay --de <Bot> [--para <Name>] [--reply-to ID] TEXT` posts that shape.
It is **unsigned by default** (byte-identical to the relays posted today). `--sign` is an
explicit opt-in: it appends a `channel-sig v=1` trailer signed as the config's
`[channel_identity]`, which must be the relayer (agent-a); any other identity, a missing
identity or a key file that is not 0600 is refused before anything is posted. The trailer is
made at post time (fresh `ts` and nonce), so the inbox and the B1 presence gate verify it with
the same `verify_comment` and nonce ledger as `send`/`reply`. `--dry-run` posts nothing; a
signed dry-run prints the trailer with `mac=<redacted>`.
Do not put secrets in PR comments.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Do not commit key files, live config, or receipts.
