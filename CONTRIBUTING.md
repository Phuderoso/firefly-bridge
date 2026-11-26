# Contributing

## Ground rules

1. **No live send in CI or unit tests.** Use the mock transport and the fake
   outbox runner.
2. **No real paths, session ids, pids, or reply text** in docs, samples, or
   commit messages. Use placeholders (`sess-example-0001`, `~/.grok/…`).
3. **Do not weaken the defaults:** `live_send = false`,
   `permission_mode = "pending"`, `strip_grok_sandbox = false`.
4. **Do not add network listeners** or cross-host transports under the guise of
   "just a small patch". That is a different project (see A2A).

## Dev setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check .
```

## Pull requests

- Keep the change focused.
- Add or update unit tests with fakes.
- Update `CHANGELOG.md`.
- If you touch permissions or the socket attach path, update `THREAT_MODEL.md`.
