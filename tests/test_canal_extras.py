"""Forward, ack, and cursor markers. No ACP, no network."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

from firefly_bridge import canal_cursor as cc

ROOT = Path(__file__).resolve().parents[1]
CALL = ROOT / "scripts" / "channel-call"
KNOCK = ROOT / "scripts" / "channel-knock"
SCRIPT = ROOT / "scripts" / "channel-gh"
EXAMPLE = ROOT / "examples" / "config.example.toml"

_loader = importlib.machinery.SourceFileLoader("channel_gh_extras", str(SCRIPT))
_spec = importlib.util.spec_from_loader("channel_gh_extras", _loader)
tg = importlib.util.module_from_spec(_spec)
_loader.exec_module(tg)

_kloader = importlib.machinery.SourceFileLoader("channel_knock_extras", str(KNOCK))
_kspec = importlib.util.spec_from_loader("channel_knock_extras", _kloader)
knock = importlib.util.module_from_spec(_kspec)
_kloader.exec_module(knock)

OWNER = "owner"
OWNER_LOGIN = "ownerlogin"


def _canal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[github_canal]\nrepo = "ExampleOwner/example-canal"\npr = "1"\n',
        encoding="utf-8",
    )
    return cfg


def _write_tg_stub(path: Path) -> None:
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, re, sys\n"
        f"VIP = ['agent-a', 'agent-b', 'agent-c', 'agent-d', '{OWNER}', 'peerx']\n"
        "ALIASES = {\n"
        "    'agent': 'agent-a', 'agent-b': 'agent-b', 'agentc': 'agent-c',\n"
        "    'agent-d': 'agent-d', 'agentdext': 'agent-d', 'agent-d-alt': 'agent-d',\n"
        f"    '{OWNER.lower()}': '{OWNER}', 'ownernick': '{OWNER}', '{OWNER_LOGIN.lower()}': '{OWNER}',\n"
        "    'peerx': 'peerx', 'peerxb': 'peerx',\n"
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


# --- format_send_body markers -------------------------------------------------------------


def test_format_send_body_forward_ack_cid_markers() -> None:
    body = tg.format_send_body(
        "agent-a",
        "pede um recado",
        "peerb",
        forward_for="guest",
        ack_of=42,
        client_id="c-1",
    )
    assert body.startswith("para: agent-a\n")
    assert "pede um recado" in body
    assert body.strip().endswith("— peerb") is False
    assert "— peerb" in body
    assert "<!-- channel-forward: para-original=guest -->" in body
    assert "<!-- channel-ack: 42 -->" in body
    assert "<!-- channel-cid: c-1 -->" in body
    assert tg.forward_target(body) == "guest"


def test_format_send_body_keeps_para_agent_when_forwarding() -> None:
    body = tg.format_send_body("agent-a", "oi", "peerb", forward_for="guest")
    assert body.startswith("para: agent-a\n")
    assert "para: guest" not in body
    assert "<!-- channel-forward: para-original=guest -->" in body


def test_format_send_body_without_markers_unchanged() -> None:
    body = tg.format_send_body("agent-a", "teste de canal", "agent-a-setup")
    assert "channel-forward" not in body
    assert "channel-ack" not in body
    assert "channel-cid" not in body
    assert body.strip().endswith("— agent-a-setup")


# --- cmd_send --forward-for / cmd_ack -----------------------------------------------------


def test_cmd_send_forward_for(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _canal_cfg(tmp_path)
    recorded: list[list[str]] = []

    def fake_gh(args: list[str], gh: str) -> str:
        recorded.append(args)
        if args[:2] == ["pr", "comment"]:
            body = args[args.index("--body") + 1]
            assert body.startswith("para: agent-a\n")
            assert "<!-- channel-forward: para-original=guest -->" in body
            assert "oi" in body
            return "https://example.test/pull/1#issuecomment-7\n"
        raise AssertionError(args)

    rc = tg.main(
        [
            "--config",
            str(cfg),
            "send",
            "agent-a",
            "oi",
            "--from",
            "peerb",
            "--forward-for",
            "guest",
        ],
        runner=fake_gh,
    )
    assert rc == 0
    assert capsys.readouterr().out.strip().endswith("issuecomment-7")
    assert recorded


def test_cmd_send_ack_of_and_cid(tmp_path: Path) -> None:
    cfg = _canal_cfg(tmp_path)
    bodies: list[str] = []

    def fake_gh(args: list[str], gh: str) -> str:
        if args[:2] == ["pr", "comment"]:
            bodies.append(args[args.index("--body") + 1])
            return "https://example.test/8\n"
        raise AssertionError(args)

    rc = tg.main(
        [
            "--config",
            str(cfg),
            "send",
            "agent-c",
            "valeu",
            "--from",
            "peerb",
            "--ack-of",
            "99",
            "--cid",
            "abc",
        ],
        runner=fake_gh,
    )
    assert rc == 0
    assert bodies[0].startswith("para: agent-c\n")
    assert "<!-- channel-ack: 99 -->" in bodies[0]
    assert "<!-- channel-cid: abc -->" in bodies[0]


def test_cmd_ack_default_text(tmp_path: Path) -> None:
    cfg = _canal_cfg(tmp_path)
    comments = [
        {
            "id": 42,
            "body": "para: peerb\n\nping\n\n— agent-c\n",
            "created_at": "2026-11-14T12:00:00Z",
            "user": {"login": "x"},
        }
    ]
    bodies: list[str] = []

    def fake_gh(args: list[str], gh: str) -> str:
        if args[0] == "api":
            return json.dumps(comments)
        if args[:2] == ["pr", "comment"]:
            bodies.append(args[args.index("--body") + 1])
            return "https://example.test/ack\n"
        raise AssertionError(args)

    rc = tg.main(["--config", str(cfg), "ack", "42", "--from", "peerb"], runner=fake_gh)
    assert rc == 0
    assert bodies[0].startswith("para: agent-c\n")
    assert "\nack\n" in bodies[0] or "\nack\n\n—" in bodies[0]
    assert "<!-- channel-ack: 42 -->" in bodies[0]
    assert "— peerb" in bodies[0]


def test_cmd_ack_custom_message(tmp_path: Path) -> None:
    cfg = _canal_cfg(tmp_path)
    comments = [
        {
            "id": 7,
            "body": "<!-- channel-bot: agent-b -->\npara: peerb\n\nhey\n",
            "created_at": "2026-11-14T12:00:00Z",
            "user": {"login": "x"},
        }
    ]
    bodies: list[str] = []

    def fake_gh(args: list[str], gh: str) -> str:
        if args[0] == "api":
            return json.dumps(comments)
        if args[:2] == ["pr", "comment"]:
            bodies.append(args[args.index("--body") + 1])
            return "https://example.test/ack2\n"
        raise AssertionError(args)

    rc = tg.main(
        ["--config", str(cfg), "ack", "7", "valeu", "agent-b", "--from", "peerb"],
        runner=fake_gh,
    )
    assert rc == 0
    assert bodies[0].startswith("para: agent-b\n")
    assert "valeu agent-b" in bodies[0]
    assert "<!-- channel-ack: 7 -->" in bodies[0]


def test_cmd_ack_unknown_comment(tmp_path: Path) -> None:
    cfg = _canal_cfg(tmp_path)

    def fake_gh(args: list[str], gh: str) -> str:
        if args[0] == "api":
            return json.dumps([])
        raise AssertionError(args)

    with pytest.raises(SystemExit, match="not_found"):
        tg.main(["--config", str(cfg), "ack", "1", "--from", "peerb"], runner=fake_gh)


# --- canal_cursor -------------------------------------------------------------------------


def test_canal_cursor_path_and_monotonic(tmp_path: Path) -> None:
    path = cc.cursor_path(tmp_path, ["peerb", "peera"])
    assert path.name == "last_seen_peera_peerb.json"
    assert cc.cursor_path(tmp_path, ["peera", "peerb"]) == path
    assert cc.read_cursor(path) is None
    cc.write_cursor(path, 10)
    assert cc.read_cursor(path) == 10
    cc.write_cursor(path, 5)
    assert cc.read_cursor(path) == 10
    cc.write_cursor(path, 10)
    assert cc.read_cursor(path) == 10
    cc.write_cursor(path, 20)
    assert cc.read_cursor(path) == 20
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["last_id"] == 20
    assert "updated_at" in data


def test_canal_cursor_single_alias_and_default(tmp_path: Path) -> None:
    assert cc.cursor_path(tmp_path, ["peerb"]).name == "last_seen_peerb.json"
    assert cc.cursor_path(tmp_path, []).name == "last_seen_default.json"
    assert cc.canonical_alias_key(["peerb", "peera"]) == "peera,peerb"


# --- channel-call roster ------------------------------------------------------------------


def test_call_agent_d_alt_is_direct(tmp_path: Path) -> None:
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
        [str(CALL), "agent-d-alt", "ping"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    assert argv[:4] == ["send", "--from", "peerb", "agent-d"]
    assert "--forward-for" not in argv
    assert "ping" in argv


def test_call_peerc_wraps(tmp_path: Path) -> None:
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
        [str(CALL), "peerc", "oi"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    assert argv[:4] == ["send", "--from", "peerb", "agent-a"]
    assert "--forward-for" in argv
    assert argv[argv.index("--forward-for") + 1] == "peerc"
    assert "via agent-a" in proc.stderr


def test_call_peerx_is_direct(tmp_path: Path) -> None:
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
        [str(CALL), "peerx", "oi"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    assert argv[:4] == ["send", "--from", "peerb", "peerx"]
    assert "--forward-for" not in argv


def test_call_relay_direct_even_if_roster_empty(tmp_path: Path) -> None:
    stub = tmp_path / "channel-gh"
    argv_file = tmp_path / "argv.json"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[1:]\n"
        "if args and args[0] == 'roster':\n"
        "    sys.exit(1)\n"
        "open(os.environ['ARGV_FILE'], 'w', encoding='utf-8').write(json.dumps(args))\n"
        "print('DRY_OK')\n",
        encoding="utf-8",
    )
    stub.chmod(0o700)
    env = {
        **os.environ,
        "CHANNEL_GH": str(stub),
        "ARGV_FILE": str(argv_file),
        "CHANNEL_FROM": "peerb",
    }
    proc = subprocess.run(
        [str(CALL), "agent-a", "oi"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads(argv_file.read_text(encoding="utf-8"))
    assert argv[:4] == ["send", "--from", "peerb", "agent-a"]
    assert "--forward-for" not in argv


# --- knock still dry-run / live refused ---------------------------------------------------


def test_knock_still_dry_run(capsys: pytest.CaptureFixture[str]) -> None:
    assert knock.main([]) == 0
    out = capsys.readouterr().out
    assert "session/prompt" in out
    assert "live: not requested" in out


def test_knock_live_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHANNEL_KNOCK_LIVE", raising=False)
    assert knock.main(["--live"]) == 2
