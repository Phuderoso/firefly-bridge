# Wake vs tool

A wake delivers text. It does not click tools.

Do not enable `allow_all_own_turns` on the channel profile. That mode stays off
unless a single agent's config sets it.

## Envelope

Canal/wake bodies are parsed by `firefly_bridge.wake_envelope.parse_wake_envelope`.

| `kind` | Meaning |
| --- | --- |
| `recado` (default) | Text delivery only. Plain bodies, canal `para:` wraps, and unknown kinds. |
| `tool_request` | Text request that peerb may honour **after** she is awake. Must **not** auto-answer `session/request_permission`. |

The word "channel" does not grant tool approval.

Examples:

```
kind: recado
from: agent-a

oi peerb
```

```
kind: tool_request
from: agent-c
tool: read_file

please read note.md when you can
```

JSON `{"kind":"tool_request","text":"…"}` is also accepted. Delivery is still
the original body as text (`agent-a: …`). The parser only classifies; it does
not turn a recado into a tool click.

## Adapter (`channel` → peerb)

1. Wake = recado. Not a click on peerb's tools.
2. If ACP/wake reaches `session/request_permission` on this client's connection:
   deny with reason `wake_origin_tool_denied`. Write a named card (who asked,
   which tool) to `pending_card_path` (placeholder `~/.grok/channel/pending_card.json`).
   agent-a never Allow. Missing `reject_once` becomes **cancelled**, not silence,
   so a clickable Allow does not sit on the TUI.
3. Tools peerb starts **after** she is awake are her own-turn HITL. This client
   does not answer those.
4. Other agents who want a tool ask in text (`kind: tool_request`). peerb decides.
5. Default `permission_mode` for `ChannelConfig` is `pending`. Default
   `answer_permissions` is `false`. Even if a user passes
   `--answer-permissions`, wake-origin is still denied. Never enable
   `allow_all_own_turns` on the peerb/channel profile.

The shipped examples keep every agent at `pending`. This client does not retarget
sockets and does not attach to a live ACP socket on its own.

## Daemon IPC

`channel` IPC enqueue sets `wake_origin: true`. The daemon permission path
denies `session/request_permission` for those turns with the same result as
`wake_origin_permission_result`. Another agent's `allow_all_own_turns` is
not applied to a wake. Receipt `wake_origin_denied_n` is counted from
permission_events. Bodies starting `[channel-wake` are also wake-origin.

Live hold processes that are not this client remain outside this patch.
Knock docs: `docs/KNOCK.md`. No launchd. No `--live` ACP from knock.

## Where this sits

Wake delivery is text. Tool permission stays pending unless that agent's own
config opts into a narrower allowlist or, explicitly, `allow_all_own_turns`.
See `docs/KNOCK.md` and `THREAT_MODEL.md`. Knock does not attach live unless
`CHANNEL_KNOCK_LIVE=1` and the configured gate file both exist.
