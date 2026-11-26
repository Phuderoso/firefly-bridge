# Threat model — 0.4.0-rc1

Same-machine, same-user Unix broker; the local OS account and actual ACP leader
are trusted. No cross-host or hostile-same-UID isolation is promised. No public
listener, proxy/Funnel, terminal injection, session creation/fork, scheduler
repair, force wake or duplicate merge is implemented or authorized.

## Assets and authority

Protect the live session, human compositor, permission decisions, credentials,
reply privacy and the durable history of **attempts**, opt-ins and vetoes.
Distinct 0600 IPC credentials bind sender roles and never grant human authority
to an agent. Broker-generated visible labels are attribution, not human commands.
Untrusted text, tool output, quotes, OCR and load replay cannot grant permission,
claim sender identity, open a channel or act as recipient control.
Same-UID malware can steal keys/modify state/connect to the leader anyway.

## Ownership and admission

Use agent-a's exact origin tuple: initiator-issued turn ID, nonce, message ID,
sender, pinned session and server-issued incarnation. Permissions require a
matching live turn-start attestation; waiting/prefixes do not suffice. Silence on
foreign/unverified turns includes cleanup and observer (`live_send=false`).

[Experimental contract](docs/ATTESTATION.md) requires an authenticated trusted
leader, capability negotiation and atomic idle-revision enforcement. **Not yet
validated on real grok-tui.** No adapter support => live dispatch unavailable.
Fresh idle alone is not an atomic guarantee and never proves no human draft.
A coordinated opt-in window is required; the bridge never watches keystrokes,
screens, tmux or compositor contents. One target-wide lock prevents competing
brokers even with different state directories. It does not arbitrate unrelated
clients that ignore this broker; the leader must enforce admission.

## Durable attempts and recovery

SQLite FULL synchronous transactions commit IDs/digests, sender, generation and
origin **before** send. A crash can consume an attempt without delivery: at-most
one attempt per known ID, **not exactly-once remote delivery**. No automatic
retries/new-ID substitution. Queue closure, vetoes, nonces, attempts and quota
history survive restart; queued work is not rehydrated. Known durable pre-write
refusals are local failed receipts, not remote unknowns. Restart can reconcile
legacy unknowns with neither attempted timestamp nor proof under the invariant
that both commit before every RPC write. Any committed/ambiguous claim still holds;
no general StoreError/IO exception is interpreted as safe pre-write failure. Unknown attempts hold the
remote lease until exact fresh terminal evidence. New incarnations remain unknown.
Legacy state is refused pending explicit claim-preserving migration; replacing
the database or pointing at a fresh directory is not safe recovery.

## Cancel and consent

agent-c's stricter cancellation authority supersedes the old timeout design. An
agent can remove its own local waiter only. Timeout records unknown and stops
new dispatch, never cancels a remote turn or replies `cancelled` to permissions.
Only authenticated human/recipient can request an exact attested own-turn cancel,
and only with negotiated **atomic scoped cancel**. Notification/write is not ACK;
matching terminal alone releases the lease. No global-session fallback.

Both human and recipient opt-ins are required for the scoped channel. Either
pause/revoke or authenticated `/basta` clears both, advances generation and removes
local queued work. Reopening needs fresh opt-ins; no timer/prompt auto-opens.
Quoting `/basta` is not authenticated control. A supported leader control surface
is necessary to hear recipient veto; plain text cannot impersonate it.

## Permissions: policy conflict is explicit

`pending` remains default independently for agent-a/agent-b/agent-c. Each policy uses
`<sender>_permission_mode`; the old global non-pending switch is rejected so it
cannot auto-approve for clients that did not select it. For nonprotected requests,
pending never approves/rejects, even after timeout. The independent hard gate may
reject protected own requests in every mode. Missing
human permission routing is an honest availability limitation, not an invitation
to auto-approve. `allowlist_shared` (legacy alias `allowlist`) only selects
`allow_once` for edits resolving inside the configured shared root. Realpath
checks are not a hostile filesystem sandbox and cannot prevent all TOCTOU races.

**DANGER: per-client `allow_all_own_turns` (alias `allow_all`) auto-approves eligible tools/paths on that client's attested bridge-initiated turns**,
subject to the broker-owned protected-tool gate. Disabling that gate permits
unrestricted shell/network requests. It warns loudly and is off unless a config
sets it for one agent. Shipped examples stay `pending`. No `allow_always`, global
trust change or bypass of OS/application approvals is used. Policy only applies
to requests the leader actually routes to this client; previously granted tools
and agent conduct remain outside it. Consent/ownership do not authorize arbitrary
external actions, reveal secrets or suspend channel prohibitions.

## Enforced protected tools, not a sandbox

Default `protected_tools_enabled=true` blocks requests concerning TCC/macOS
permission dialogs, known credential/secret stores, external sends/posts,
Funnel/network exposure, tmux injection, duplicate merge and CLOSE_ORDERS. The same
law table is reflected by status. This gate precedes every sender mode and
cannot be bypassed by an injected broad policy. A tool's arguments cannot turn it
off. Explicit user config `protected_tools_enabled=false` disables enforcement
and is exposed in status; the deployment mode choices themselves do not change.

Names/paths/content are normalized and protected symlink targets checked, but
matching keywords is not proof that arbitrary code is safe. Generic shell/scripts,
indirect MCP/network and unknown/unclassifiable requests therefore fail closed.
Classifiable structured file operations rely on trustworthy leader kind/schema.
No claim is made to detect arbitrary secrets in arbitrary files, stop pre-approved
tools, confine a hostile filesystem or prevent a malicious same-UID/leader process.
This is not OS sandboxing, capability signing or per-action human authorization.
Use actual executor restrictions for a stronger boundary.

RC4 binds the guard to configured IPC-key/state/ledger roots, HMAC/client-key files
and the actual loaded config source/default config directory, not just keywords.
Read/write/delete and parent traversal/recursive-parent targets are blocked by
conservative lexical+real Unicode/case-normalized path comparison. Realpath sees
symlinks before '..' collapse; session-relative request paths and daemon-relative
resource paths are distinguished. No key content is opened for classification.
Sibling-prefix names remain distinct. Case folding may overblock on Linux.
TOCTOU, malicious same-UID/leader, arbitrary hardlinks and pre-authorized tools
still require executor/OS containment. Embedders must identify a custom config
source through config_path if they bypass load_config.


Protected own requests are audited and select only server-offered `reject_once`;
without it the broker is silent. Either way automatic approvals stop for the
current turn. No denial/cleanup is sent for foreign/unverified requests. Denial
never becomes global cancellation or an invented approval option.

## Privacy and bounded resources

Private 0700 state, 0600 socket/database/audit. IPC HMAC binds operation, principal,
args, target, timestamp and nonce; nonce replay ledger persists. Separate keys
are mandatory and duplicate keys refused. Nonces older than their validity window
are purged, not accepted again. IPC and ACP frames cap at 128 KiB. Limits cover
body bytes/chars, queue bytes/count, sender pending/day/interval, the target-wide
cross-agent start interval, post-terminal interval and zoned quiet hours,
reply bytes and in-memory audit/replies. Slow IPC client timeout is 2 seconds.

Tool commands/titles/paths and prompt bodies are omitted from daemon logs; tool
kind, hashed tool/RPC identity, canonical target fingerprint and local zoned time
are retained. Decision intent precedes response; a response-sent marker proves
only a transport write, never tool execution. Controls have transactional actor,
scope, generation and local-time history. This audit is capped at 1000 events per
target/100 per query; JSONL rotates at 1 MiB plus one previous segment. Fingerprints
can reveal equality and be guessed for known filenames; they are not anonymization.
No
unbounded raw JSONL receipts. SQLite holds digests and minimal receipts, not
prompt/reply history. Correlated message chunks only: no thoughts or replay.
Owner-only replies stay in memory (32); known secret formats/paths are redacted.
Protocol IDs, enum states and validated status codes bypass free-text redaction;
opaque content does not. Authoritative ledger columns reconstruct core metadata
if an older receipt JSON contains failed-redaction markers. Terminal completion
and the consumed attempt never depend on content rendering succeeding.
Heuristic redaction cannot identify every arbitrary secret: do not request or
send secrets. A redactor failure returns a safe marker, never raw fallback.
Audit failure prevents new auto-approval; postprocessing cannot reopen attempts.
Child stderr is discarded, not piped unbounded. Claim/nonce receipts are retained
for deduplication; storage grows with accepted IDs over time. There is no unsafe
automatic ledger pruning. Monitor disk; exhaustion fails closed. The older mock
`send/prepare` demonstration emits/stores its supplied example text: it is not a
production ingress, and must not be fed private live content.

No supported history API is assumed. The ChatHistory interface attempts bounded,
read-only, origin-exact recovery for missing/malformed chunks or content-rendering
failure after a terminal has already been attested. The shipped adapter is a
fail-closed stub. A future proven/authorized adapter must return the exact session,
incarnation, turn, initiator, nonce, message and sender; wrong proof/oversize/errors
are discarded. Recovered content must still redact successfully. History cannot
establish terminal ownership, approve tools, release an unknown turn by itself,
search other sessions or supply a new prompt. Never scrape app databases, pane
text or credentials. Without an API, reply recovery remains unavailable.

Queue TTL defaults to 1800 seconds, covering the unchanged 1800-second sender
cooldown. Configurations with shorter TTL are rejected; equal TTL is eligible
at the boundary. Long busy/unknown turns can still expire waiters safely; no
retry or escalation follows. Legacy global_interval_s is only a per-sender floor;
new target_interval_s defaults to 600 seconds globally between starts, and
post_turn_interval_s to 60 seconds after each confirmed terminal. Both are durable.
They are validated floors while pacing_minimums_enabled=true; smaller/zero values
require explicit pacing_minimums_enabled=false. That opt-out does not bypass
bounds, consent, ownership or the independent protected-tool gate.
RC2 terminal timestamps missing on migration conservatively use migration time.
TTL must cover each configured interval. Quiet HH:MM ranges use a validated zone,
may span midnight/DST, and prevent new dispatch, never cancel an active turn or
implicitly opt in again. Empty endpoints disable quiet hours; equal/partial ranges
are invalid. All configured timers reject NaN and infinities.

## Sandbox, publication, live validation

`strip_grok_sandbox=false` stays default. Enabling it removes GROK_SANDBOX from
the child environment and can broaden access; it is not a compatibility fix to
activate silently. The broker never changes TCC/trust or clicks approval dialogs.
No Mac cutover, build installation, send or publish occurred for this candidate.

Tests use fake peers. They do not prove live ownership/metadata, atomic admission,
scoped cancellation, compositor preservation or recipient control. Those remain
release blockers until demonstrated in an approved lab and a coordinated canary.

## RC4 reply completeness and deferred intent routing

Observed reply sequences must be contiguous from 1. Gaps/malformed content/count
mismatches trigger bounded history recovery or unavailable reply, never resend.
Origin-verified/rendered content is not automatically complete: reply_complete
requires an attested matching terminal chunkCount or full logical history reply
from a separately trusted adapter. No real API/leader implementation is asserted.

Channel has no keyword listener or dispatch
implementation. AI text, quotes, relays and tool output never authenticate human
intent. The word "channel" does not grant tool approval. Wake bodies default to
`kind: recado` (text); `kind: tool_request` is still text and must not auto-answer
`session/request_permission`. The peerb/channel client defaults to
`permission_mode=pending` and `answer_permissions=false`; wake-origin permission
requests on that client are denied (`wake_origin_tool_denied`) rather than left
as a clickable Allow. Daemon IPC enqueue of a channel/knock turn is tagged
`wake_origin`; the broker permission path uses the same deny, so deployment
agent-a `allow_all_own_turns` cannot Allow a wake. A mode set on one agent
is not applied to a wake for another.
Knock (`docs/KNOCK.md`) is an ephemeral stdio client + `[channel-wake]`
prompt. It is dry-run in this tree and does not dispatch tool actions. The document
does not authorize Mac use, force-wake or keystrokes. See docs/WAKE_VS_TOOL.md.

## RC5 authority integrity

The bridge now checks the current authority on every owned permission decision,
not just daemon construction. Exact durable turn/sender/generation/proof and
in-flight identity must match. It rechecks at response after required audit;
response and authority close share a mutex. No authority means reject_once if
offered, otherwise silence; foreign requests are never answered. Dispatch, claim
and pre-write also check. Lost authority cannot imply a remote terminal ACK.

Authority uses a stable per-UID, canonical-target fence independent of DB and
runtime selection plus the runtime lock. Path replacement/unlink of the runtime
lock cannot split the still-held stable fence. Directory/file identity, private
ownership/modes, generation, PID and exclusive lock possession are checked;
shared/unlocked/replaced/tampered handles latch closed. Target realpaths receive
conservative Unicode/case normalization; distinct paths may overblock.

Whole effective runtime/fence directories and files join protected paths, including
read/write/delete/move and ancestor/alias checks. Authority-path and current-owner
checks are non-configurable broker invariants, even if the general protected-tools
gate is explicitly disabled. Opaque code in that opt-out, preauthorized tools,
hardlink aliases, arbitrary simultaneous replacement of both fences and hostile
same-UID filesystem/FD manipulation remain outside OS-containment guarantees.
Path verification cannot atomically bind the executor's later file access (TOCTOU).
The generation strings are public coordination markers, not authentication secrets.

Files are never unlinked during normal release. Stop all old versions before
upgrade: cross-version fencing and real Mac behavior are not live-validated.
Different DBs cannot be simultaneously active for a target, but a later DB switch
does not transfer receipts, quotas or consumed IDs. Preserve the authoritative DB;
fencing is not a global durable ledger or authorization to recover by replacement.
