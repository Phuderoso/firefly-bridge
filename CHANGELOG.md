# Changelog

## 0.4.0rc1

Public tree of the same-machine ACP broker and the optional GitHub comment channel.

- Agent names, wake filenames, channel repo/PR, paths, and the relay principal
  come from config. Shipped defaults are placeholders (`agent-a`, `agent-b`,
  `agent-c`) with `permission_mode` pending.
- `allow_all_own_turns` remains available per agent and is off unless set.
- `live_send` defaults to false. Knock stays dry-run unless
  `CHANNEL_KNOCK_LIVE=1` and the gate file both exist.
- HMAC and IPC secrets are files (mode 0600) referenced by config, not values
  in the repository.
