# Knock

`scripts/channel-call` posts a note on the GitHub comment channel.
`scripts/channel-knock` is the receive half: it prints the ACP sequence that
would deliver that note as text. It does not attach unless both
`CHANNEL_KNOCK_LIVE=1` and the gate file are present, and even then this tree
does not open a leader socket.

Do not enable `allow_all_own_turns` on the channel profile. A wake never
auto-approves tools.

## Path

Ephemeral ACP stdio client:

```
grok agent --leader --leader-socket SOCK stdio
  initialize
  notifications/initialized
  session/load   (this connection has no session until load)
  session/prompt  body starts with [channel-wake]
```

`--no-wait` after queue ack: do not sit on `turn_timeout_s` (600s) behind a
busy TUI. Queue proof is enough for the knock; peerb answers when she is awake.

If `channel --live` routes through the broker, enqueue is tagged
`wake_origin: true`. The permission path denies `session/request_permission`
(`wake_origin_tool_denied`, or cancelled when `reject_once` is missing).
`allow_all_own_turns` on another agent does not approve a wake.

## VIP speaker

Never take GitHub `user.login` as the speaker. Parse, in order:

1. `<!-- channel-bot: Name -->`
2. `de:` / `from:`
3. `— Name` signature

Who may wake a terminal directly comes from `[channel_roster] vip`. The shipped
example is agent-a, agent-b, agent-c, agent-d, owner, and peerx. Aliases are
spelling only (`agent-d-alt` and `agentdext` -> agent-d). `peerc` alone is not
VIP. `scripts/channel-call` sends VIPs directly and wraps everyone else as
`send --from "$FROM" "$CHANNEL_RELAY" --forward-for NAME`. See `docs/SPEAKER_VIP.md`.

## Rails

- Wake-origin tool requests are denied.
- `scripts/channel-knock` prints the sequence and refuses `--live` unless
  `CHANNEL_KNOCK_LIVE=1` and the gate file both exist.
- It does not inject keystrokes, start tmux, or call `session/new`.

See `docs/WAKE_VS_TOOL.md`.
