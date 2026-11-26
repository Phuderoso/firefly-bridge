"""Dry-run knock and channel-call wrapper. No ACP attach, no network."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KNOCK = ROOT / "scripts" / "channel-knock"
CALL = ROOT / "scripts" / "channel-call"

_loader = importlib.machinery.SourceFileLoader("channel_knock", str(KNOCK))
_spec = importlib.util.spec_from_loader("channel_knock", _loader)
assert _spec is not None
knock = importlib.util.module_from_spec(_spec)
_loader.exec_module(knock)

OWNER = "owner"
OWNER_LOGIN = "ownerlogin"


def _write_tg_stub(path: Path) -> None:
    """Stub channel-gh: answers roster / roster --canonical= and dumps send argv."""
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, re, sys\n"
        f"VIP = ['agent-a', 'agent-b', 'agent-c', 'agent-d', '{OWNER}', 'peerx']\n"
        "ALIASES = {\n"
        "    'agent': 'agent-a', 'agent-b': 'agent-b', 'agentc': 'agent-c',\n"
        "    'agent-d': 'agent-d', 'agentdext': 'agent-d', 'agent-d-alt': 'agent-d',\n"
        f"    '{OWNER.lower()}': '{OWNER}', 'ownernick': '{OWNER}', '{OWNER_LOGIN.lower()}': '{OWNER}',\n"
        "    'peerc-guestc': 'peerx', 'peercguestc': 'peerx',\n"
        "}\n"
        "args = sys.argv[1:]\n"
        "if args and args[0] == 'roster':\n"
        "    want = None\n"
        "    rest = args[1:]\n"
        "    i = 0\n"
        "    while i < len(rest):\n"
        "        a = rest[i]\n"
        "        if a.startswith('--canonical='):\n"
        "            want = a.split('=', 1)[1]\n"
        "        elif a == '--canonical' and i + 1 < len(rest):\n"
        "            want = rest[i + 1]; i += 1\n"
        "        i += 1\n"
        "    if want is not None:\n"
        "        key = re.sub(r'\\s*\\[[^\\]]*\\]$', '', want.strip().lower())\n"
        "        name = ALIASES.get(key)\n"
        "        if name:\n"
        "            print(f'vip: {name}')\n"
        "            sys.exit(0)\n"
        "        sys.exit(1)\n"
        "    print('\\n'.join(VIP))\n"
        "    sys.exit(0)\n"
        "open(os.environ['ARGV_FILE'], 'w', encoding='utf-8').write(json.dumps(args))\n"
        "print('DRY_OK')\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def test_knock_script_is_executable() -> None:
    assert KNOCK.is_file()
    assert CALL.is_file()
    mode = KNOCK.stat().st_mode
    assert mode & stat.S_IXUSR


def test_knock_default_dry_run(capsys: pytest.CaptureFixture[str]) -> None:
    assert knock.main([]) == 0
    out = capsys.readouterr().out
    assert "session/prompt" in out
    assert "[channel-wake]" in out
    assert "agent-a never Allow" in out
    assert "no launchd" in out
    assert "live: not requested" in out


def test_knock_live_without_gates_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHANNEL_KNOCK_LIVE", raising=False)
    rc = knock.main(["--live"])
    assert rc == 2


def test_knock_live_with_gates_still_does_not_attach(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    gate = tmp_path / "LIVE_GATE"
    gate.write_text("pode testar no Mac\n", encoding="utf-8")
    monkeypatch.setenv("CHANNEL_KNOCK_LIVE", "1")
    monkeypatch.setattr(knock, "GATE", gate)
    rc = knock.main(["--live", "--text", "oi"])
    assert rc == 3


def test_call_wraps_non_vip_and_refuses_bad_from(tmp_path: Path) -> None:
    stub = tmp_path / "channel-gh"
    argv_file = tmp_path / "argv.json"
    _write_tg_stub(stub)
    env = {
        **os.environ,
        "CHANNEL_GH": str(stub),
        "ARGV_FILE": str(argv_file),
        "CHANNEL_FROM": "peerb",
    }
    proc = subprocess.run(
        [str(CALL), "guest", "pede um recado"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    assert argv[:4] == ["send", "--from", "peerb", "agent-a"]
    assert "--forward-for" in argv
    assert argv[argv.index("--forward-for") + 1] == "guest"
    assert "pede um recado" in argv
    assert "via agent-a" in proc.stderr

    vip = subprocess.run(
        [str(CALL), "--from", "peera", "agent-a", "oi"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert vip.returncode == 0, vip.stderr
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    assert argv[:4] == ["send", "--from", "peera", "agent-a"]
    assert "--forward-for" not in argv

    bad = subprocess.run(
        [str(CALL), "agent-a", "nope"],
        env={**env, "CHANNEL_FROM": OWNER},
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 4
    assert "CHANNEL_SENDERS" in bad.stderr
