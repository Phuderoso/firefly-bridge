# Channel HMAC keys

Keys are per sender, mode `0600`, and never printed. Generate them outside the
git worktree.

```bash
python3 scripts/channel-keygen gen --keyring ~/.config/firefly-bridge/keyring \
  --config ~/.config/firefly-bridge/config.toml agent-a
```

Rules, all from config (nothing is hard-coded):

- `[channel_roster] owner` and that name's aliases cannot receive a key. The
  owner speaks through a relay signed by `relay_principal`.
- Names listed in `[channel_roster] pending` are refused until the same person
  passes `--allow-pending-identity`.
- A missing config fails closed: the tool will not guess who the owner is.
- `check` reports open permissions, leftover temp files, and
  `legacy_unsigned_wake = true`.

`render-config` writes a terminal config that points at an existing key file.
It copies paths only.

See `examples/config.example.toml` for the roster, identity, and keyring tables.
Do not commit `*.key` files.
