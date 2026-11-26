# Experimental agent-a leader contract (v1)

**Proposed adapter contract, NOT standard ACP and NOT live validated.** No new
RPC method is invented. Existing ACP methods carry negotiated private metadata;
`session/update` event variants below require explicit leader implementation.
An unmodified leader must fail readiness, not fall back to prefix ownership.

## Negotiation and trust

`initialize.result.capabilities.agentBridge` must include `turnAttestation: 1`
and `atomicAdmission: true`. `scopedCancel: true` is optional. Session load must
return `_meta.sessionId` exactly equal to the pin and
`_meta.agentBridge.incarnation` as a nonempty leader-issued incarnation.
Authenticated, same-user stdio/leader socket is trusted as the attester, not the
model or a string it writes. A compromised leader/same-UID process can forge this;
this is a protocol correlation contract, not remote cryptographic identity.

## Origin (agent-a's design)

Before dispatch the broker durably records an initiator-issued random `turnId`,
`nonce`, `initiator: "firefly-bridge"`, `messageId`, authenticated `sender`, and
leader-issued `incarnation`. These exact fields live in
`params._meta.agentBridge` of `session/prompt` and must be echoed on every live
`turn_started`, `session/request_permission`, agent-message chunk and terminal.
Events also require the pinned `params.sessionId`; terminal RPC results require
`result.sessionId` and `result._meta.agentBridge` with the same origin.
`replay: true` is always rejected. Replay must never be mislabelled as live.

A local waiter alone grants no ownership. Permission ownership starts only with
a matching `session/update` / `update.sessionUpdate="turn_started"`. A foreign
turn-start clears that proof. No orphan permission adoption occurs after restart.

## Atomic admission

Leader sends `session/update` with `update.sessionUpdate="bridge_state"`,
`update.state="idle"|"busy"`, pinned `sessionId` and metadata
`{incarnation, stateSeq, revision}`. `stateSeq` strictly increases; `revision` is
a nonempty one-use leader admission token. Broker only uses fresh idle evidence
(default <=5 monotonic seconds), and sends `admissionRevision` alongside origin.
The leader MUST atomically reject stale/used tokens or busy state **without
queueing the prompt**. It must not grant tools or treat metadata as model text.

This removes the client-side check/write race only when enforced by the leader.
It does not detect a human's unfinished draft. Human opt-in is a coordinated
window; user pause has priority, and the bridge never reads/edits the draft.
After terminal, a fresh idle revision is required before the next dispatch.

## Replies, terminal and recovery

Live agent-message chunks require `update.sessionUpdate="agent_message_chunk"`,
`update.content={type:"text", text:...}`, origin metadata and **contiguous 1-based** `chunkSeq` (agent-message
chunks only). Duplicates are ignored; gaps/invalid starts cannot claim a verified
captured reply. An optional terminal `_meta.agentBridge.chunkCount` must be an
integer matching the last contiguous sequence to attest full capture, including
a possibly missing suffix. A missing count leaves completeness unproven; an
invalid/mismatched count triggers recovery/unavailable. This is an experimental
contract change, not a claim that a real leader supports it. No thoughts, tools, user echoes, screens or load history are replies.
Terminal RPC results must include origin and `stopReason` from
`end_turn/cancelled/max_tokens/refusal`. RPC error alone leaves `unknown`.

After restart an authorized fresh `turn_ended` update may reconcile an orphan:
origin must match the ledger exactly, with matching live session/incarnation and
`update.stopReason`. This settles the old claim without reissuing a prompt or
adopting permissions. Incarnation mismatch remains unknown. The client now has an injected read-only `ChatHistory` recovery interface (see
RECOVERY.md), but its shipping adapter is a fail-closed stub: no documented API
is assumed. It never probes private files or invents a `chat_history` RPC. Content
parse/redaction failure does not corrupt typed receipt IDs, state or consumed claim.

## Cancellation

agent-c's stricter rule wins: agents/timeouts never cancel dispatched work, even if
they started it. An authenticated `human` or `recipient` principal may request
cancel of an exact broker-owned active message. Only if `scopedCancel` was
negotiated will the broker send `session/cancel` with pinned session and full
origin metadata. The leader MUST atomically scope cancellation to that origin.
The notification is **not** confirmation. The lease remains held until matching
terminal evidence; an ordinary `end_turn` also proves completion, without falsely
claiming the cancel caused it. Without scope support: no cancel is sent.

## Consent/control

Unix IPC uses distinct human/recipient credentials, separate from agent keys.
A leader may additionally emit fresh `bridge_control` updates with metadata
`{incarnation, actor:"human"|"recipient", controlSeq}` and
`update={sessionUpdate:"bridge_control", op:"opt_in"|"basta"|"pause"|"revoke", senders:[...]}`.
Control must originate from the authenticated principal/approved recipient UI,
not from tool/model text. Sequence is strictly increasing within incarnation;
`replay: true` is ignored. `/basta` typed/confirmed on that supported surface maps
to `op="basta"`; quoted `/basta` in a message is not a command. Plain-text stop
intent cannot be reliably authenticated without this surface: no claim otherwise.

Channel opt-in is initially absent and scoped by sender+destination. Either veto
clears both opt-ins, increments a durable generation and closes queued work.
Only fresh explicit opt-ins from both authorities rearm; closed IDs remain closed.
Control does not cancel an active turn or reject its permissions.

## Live acceptance gate

Test every field/replay/sequence/atomic revision with a disposable, explicitly
authorized session before a user-approved canary against a pinned test session.
Missing leader support, stale status, unknown ownership or absent human-decision
surface is a compatibility blocker, **not** a reason to remove the guard.

## RC2 policy and timing isolation

Each authenticated sender has its own `<sender>_permission_mode`, all publicly
pending. `allow_all_own_turns` requires this same origin contract for that sender;
no other client's setting or visible prefix grants permission authority. The
separate deployment example records the owner's explicit broad-policy choice for
all three clients; it does not change the protocol or activate live use.
Cooldown is per sender and pinned destination, not shared across the three.
TTL must cover that cooldown; a valid boundary is not expired before eligibility.

## Local authority prerequisite (RC5)

Origin attestation is necessary, not sufficient, for permission approval. The
broker must still hold the target's healthy runtime lock and independent stable
fence, with the same durable turn claim. Checks occur at decision and after audit
at response, serialized with authority close. Missing/replaced/token-changed or
non-exclusive locks deny/silence, never become permission authority from prefix,
local waiting state or a non-None FD. This is local cooperative fencing, not a
claim that the real leader implements the experimental attestation contract.
