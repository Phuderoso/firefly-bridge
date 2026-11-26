"""Tests for RC6 fixes: Python 3.9/3.14 compat, oversized frame resilience, and channel/wake."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from firefly_bridge.channel import (
    ChannelConfig,
    ChannelLedger,
    recover_reply_from_updates_jsonl,
    run_channel_turn,
    sync_late_replies,
    write_wake_artifacts,
)
from firefly_bridge.config import BridgeConfig, ConfigError, parse_toml_text
from firefly_bridge.messages import utc_now
from firefly_bridge.rpc import JsonRpcConnection

ROOT = Path(__file__).resolve().parents[1]


class Rc6CompatibilityAndFrameTests(unittest.TestCase):
    def test_utc_now_and_toml_parser_work_across_pythons(self) -> None:
        stamp = utc_now()
        self.assertTrue(stamp.endswith("+00:00") or stamp.endswith("Z"))
        parsed = parse_toml_text(
            '[bridge]\nsocket_path = "~/.grok/test.sock" # comment\nlive_send = false\n'
        )
        self.assertEqual(parsed["bridge"]["socket_path"], "~/.grok/test.sock")
        self.assertFalse(parsed["bridge"]["live_send"])

    def test_rpc_default_fails_closed_at_128k_when_skip_disabled(self) -> None:
        conn = JsonRpcConnection(
            io.BytesIO(b"x" * 131073 + b"\n"), io.BytesIO(), max_frame=131072
        )
        conn._read_loop()
        self.assertTrue(conn.closed.is_set())
        self.assertEqual(conn.oversized_lines, 1)

    def test_rpc_skips_oversized_frame_and_processes_subsequent_valid_frame(self) -> None:
        received: list[dict] = []
        oversized = b'{"method":"session/update","data":"' + (b"A" * 300_000) + b'"}\n'
        valid = b'{"jsonrpc":"2.0","method":"session/update","params":{"ok":true}}\n'
        stream = io.BytesIO(oversized + valid)
        conn = JsonRpcConnection(
            stream,
            io.BytesIO(),
            on_notification=received.append,
            max_frame_bytes=131072,
            skip_oversized=True,
        )
        conn._read_loop()
        self.assertEqual(conn.oversized_lines, 1)
        self.assertEqual(len(received), 1)
        self.assertTrue(received[0]["params"]["ok"])

    def test_config_frame_bounds(self) -> None:
        cfg = BridgeConfig().validate(require_target=False)
        self.assertEqual(cfg.max_frame_bytes, 8388608)
        self.assertTrue(cfg.skip_oversized_frames)
        with self.assertRaises(ConfigError):
            BridgeConfig(max_frame_bytes=1024).validate(require_target=False)


class ChannelAndWakeTests(unittest.TestCase):
    def test_dry_run_writes_no_bytes_and_checks_socket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ChannelConfig(
                socket_path=str(Path(tmp) / "missing.sock"),
                session_id="sess-example-0001",
                ledger_path=str(Path(tmp) / "ledger.json"),
                wake_dir=str(Path(tmp) / "wake-notes"),
            )
            res = run_channel_turn(cfg, "Oi peerb, teste dry-run", dry_run=True)
            self.assertEqual(res["mode"], "dry_run")
            self.assertFalse(res["live_bytes_written"])
            self.assertTrue(res["prefix_ok"])
            self.assertFalse((Path(tmp) / "ledger.json").exists())

    def test_mock_turn_writes_wake_files_and_prevents_duplicate_resend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ledger_file = tmp_path / "ledger.json"
            joint_dir = tmp_path / "wake-notes"
            env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path)}
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "firefly_bridge",
                    "channel",
                    "--mock",
                    "--message-id",
                    "id_mocktest00001",
                    "--ledger",
                    str(ledger_file),
                    "--wake-dir",
                    str(joint_dir),
                    "--text",
                    "Ping de teste sem tocar na peerb",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = json.loads(proc.stdout)
            self.assertTrue(out["delivered"])
            self.assertEqual(out["stop_reason"], "end_turn")
            self.assertIn("Mock peerb: recebi", out["reply_text_redacted"])
            wake = out["wake_artifacts"]
            self.assertIsNotNone(wake)
            self.assertTrue(Path(wake["resposta_file"]).is_file())
            self.assertTrue(Path(wake["wake_file"]).is_file())
            self.assertIn("Ping de teste", Path(wake["resposta_file"]).read_text(encoding="utf-8"))

            # Re-using the same message-id must refuse to resend
            ledger = ChannelLedger(ledger_file)
            claimed, _, _ = ledger.claim("id_mocktest00001", {"text": "dup"})
            self.assertFalse(claimed)

    def test_live_without_flag_refuses_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "XDG_CONFIG_HOME": tmp}
            proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "firefly_bridge",
                "channel",
                "--text",
                "Nao deve enviar sem --live",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        body = json.loads(proc.stdout)
        self.assertEqual(body["error"], "live_flag_required")
        self.assertFalse(body["live_bytes_written"])

    def test_wake_redacts_secrets_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            art = write_wake_artifacts(
                tmp,
                message_id="id_redact0001",
                prompt_id="p-1",
                stop_reason="end_turn",
                reply_text="Segredo pypi-ABCDEFGHIJKLMNOPQRSTUVWX em /Users/example/.cache/secrets/pypi.json",
            )
            resp_text = Path(art["resposta_file"]).read_text(encoding="utf-8")
            wake_text = Path(art["wake_file"]).read_text(encoding="utf-8")
            self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWX", resp_text)
            self.assertNotIn("/Users/example/.cache/secrets", resp_text)
            self.assertIn("pypi-[REDACTED]", resp_text)
            self.assertIn("[REDACTED-PATH]", wake_text)

    def test_recover_reply_and_sync_late_replies_from_updates_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            updates = tmp_path / "updates.jsonl"
            joint = tmp_path / "wake-notes"
            ws = tmp_path / "ws"
            inbound = ws / "memory" / "shared" / "inbound"
            inbound.mkdir(parents=True)

            now_ts = int(time.time())
            rows = [
                {
                    "timestamp": now_ts - 6,
                    "method": "session/update",
                    "params": {
                        "sessionId": "sess-example-0001",
                        "update": {
                            "sessionUpdate": "user_message_chunk",
                            "content": {"type": "text", "text": "agent-a: Oi peerb, pergunta tardia"},
                        },
                    },
                },
                {
                    "timestamp": now_ts - 2,
                    "method": "session/update",
                    "params": {
                        "sessionId": "sess-example-0001",
                        "_meta": {"promptId": "late-pid-999", "chunkId": 1},
                        "update": {
                            "sessionUpdate": "agent_message_chunk",
                            "content": {"type": "text", "text": "Resposta tardia da peerb!"},
                        },
                    },
                },
                {
                    "timestamp": now_ts - 1,
                    "method": "_x.ai/session/update",
                    "params": {
                        "sessionId": "sess-example-0001",
                        "update": {
                            "sessionUpdate": "turn_completed",
                            "prompt_id": "late-pid-999",
                            "stop_reason": "end_turn",
                        },
                    },
                },
            ]
            updates.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

            rec = recover_reply_from_updates_jsonl(
                updates,
                outbound_text="agent-a: Oi peerb, pergunta tardia",
            )
            self.assertIsNotNone(rec)
            assert rec is not None
            self.assertEqual(rec["prompt_id"], "late-pid-999")
            self.assertEqual(rec["stop_reason"], "end_turn")
            self.assertEqual(rec["reply_text"], "Resposta tardia da peerb!")

            cfg = ChannelConfig(
                session_cwd=str(ws),
                wake_dir=str(joint),
                updates_jsonl_path=str(updates),
            )
            sync1 = sync_late_replies(cfg)
            self.assertEqual(sync1["woken_count"], 1)
            self.assertTrue((joint / "WAKE.md").is_file())

            # Second sync without changes must not duplicate wake
            sync2 = sync_late_replies(cfg)
            self.assertEqual(sync2["woken_count"], 0)

            # New file dropped by peerb in inbound/ triggers wake
            note = inbound / "2026-11-10-peera-to-agent-test.md"
            note.write_text("# Bilhete da peerb para agent-a\nTudo certo.\n", encoding="utf-8")
            sync3 = sync_late_replies(cfg)
            self.assertEqual(sync3["woken_count"], 1)
            self.assertIn("Tudo certo", (joint / "WAKE.md").read_text(encoding="utf-8"))

    def test_streaming_subchunks_concatenate_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mock_script = tmp_path / "mock_subchunk_leader.py"
            sid = "sess-example-0001"
            mock_script.write_text(
                f"""\
import json, sys

SID = {sid!r}
PID = "subchunk-prompt-1"

def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\\n")
    sys.stdout.flush()

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    m = msg.get("method")
    rid = msg.get("id")
    if m == "initialize":
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{"protocolVersion": 1}}}})
    elif m == "session/load":
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{"_meta": {{"sessionId": SID}}}}}})
    elif m == "session/prompt":
        for idx, tok in enumerate(["rece", "bi"], start=1):
            emit({{"jsonrpc": "2.0", "method": "session/update", "params": {{
                "sessionId": SID,
                "_meta": {{"promptId": PID, "chunkId": idx}},
                "update": {{"sessionUpdate": "agent_message_chunk", "content": {{"type": "text", "text": tok}}}},
            }}}})
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{"stopReason": "end_turn", "_meta": {{"sessionId": SID, "promptId": PID}}}}}})
        break
""",
                encoding="utf-8",
            )
            cfg = ChannelConfig(
                session_id=sid,
                ledger_path=str(tmp_path / "ledger.json"),
                wake_dir=str(tmp_path / "wake-notes"),
                updates_jsonl_path="",
            )
            res = run_channel_turn(
                cfg,
                "teste subchunks",
                spawn_cmd=[sys.executable, str(mock_script)],
            )
            self.assertTrue(res["delivered"])
            self.assertEqual(res["reply_text_redacted"], "recebi")

class ChannelConfigLoaderTests(unittest.TestCase):
    def test_placeholders_are_generic(self) -> None:
        from firefly_bridge.channel import (
            DEFAULT_APPROVALS_LOG,
            DEFAULT_HOLD_PID_FILE,
            DEFAULT_LEDGER,
            DEFAULT_SESSION_ID,
            DEFAULT_SOCKET,
            DEFAULT_UPDATES_JSONL,
            DEFAULT_WAKE_NOTES,
            DEFAULT_WORKSPACE,
        )

        self.assertEqual(DEFAULT_SESSION_ID, "sess-example-0001")
        self.assertEqual(DEFAULT_SOCKET, "~/.grok/leader.sock")
        self.assertTrue(DEFAULT_WORKSPACE.startswith("~/.local/share/firefly-bridge"))
        self.assertTrue(DEFAULT_WAKE_NOTES.startswith("~/.local/share/firefly-bridge"))
        self.assertTrue(DEFAULT_LEDGER.startswith("~/.local/state/firefly-bridge"))
        self.assertTrue(DEFAULT_HOLD_PID_FILE.startswith("~/.local/state/firefly-bridge"))
        self.assertTrue(DEFAULT_APPROVALS_LOG.startswith("~/.local/state/firefly-bridge"))
        self.assertEqual(DEFAULT_UPDATES_JSONL, "")

    def test_load_from_toml_and_env_and_derive_updates(self) -> None:
        from firefly_bridge.channel import derive_updates_jsonl, load_channel_config
        from firefly_bridge.config import load_config

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                "[bridge]\n"
                'socket_path = "~/.grok/leader-example.sock"\n'
                'session_id = "sess-example-0001"\n'
                'session_cwd = "/tmp/example-workspace"\n'
                "[channel]\n"
                'ledger_path = "~/.local/state/firefly-bridge/ledger.json"\n'
                'wake_dir = "~/.local/share/firefly-bridge/wake-notes"\n',
                encoding="utf-8",
            )
            daemon = load_config(path, env={}, require_target=False)
            self.assertEqual(daemon.session_id, "sess-example-0001")
            cfg = load_channel_config(
                path,
                env={"FIREFLY_BRIDGE_HOLD_PID_FILE": "/tmp/example-hold.pid"},
            )
            self.assertEqual(cfg.session_id, "sess-example-0001")
            self.assertTrue(cfg.socket_path.endswith("leader-example.sock"))
            self.assertEqual(cfg.hold_pid_file, "/tmp/example-hold.pid")
            derived = derive_updates_jsonl("/tmp/example-workspace", "sess-example-0001")
            self.assertTrue(derived.startswith("~/.grok/sessions/"))
            self.assertIn("%2Ftmp%2Fexample-workspace", derived)
            self.assertTrue(derived.endswith("sess-example-0001/updates.jsonl"))
            resolved = cfg.resolved()
            self.assertEqual(
                resolved.updates_jsonl_path,
                str(Path(derived).expanduser()),
            )

    def test_env_boolean_and_numeric_coercion_in_load_channel_config(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        from firefly_bridge.channel import ChannelError, load_channel_config
        from firefly_bridge.cli import main_channel

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                "[channel]\n"
                "answer_permissions = true\n"
                "strip_grok_sandbox = true\n"
                "protected_tools_enabled = true\n",
                encoding="utf-8",
            )
            # Env "false" / "0" / "no" must coerce to False, never bool("false") == True
            cfg = load_channel_config(
                path,
                env={
                    "FIREFLY_BRIDGE_ANSWER_PERMISSIONS": "false",
                    "FIREFLY_BRIDGE_STRIP_GROK_SANDBOX": "0",
                    "FIREFLY_BRIDGE_PROTECTED_TOOLS_ENABLED": "no",
                    "FIREFLY_BRIDGE_TURN_TIMEOUT_S": "42.5",
                    "FIREFLY_BRIDGE_MAX_BODY_BYTES": "16000",
                },
            ).resolved()
            self.assertIs(cfg.answer_permissions, False)
            self.assertIs(cfg.strip_grok_sandbox, False)
            self.assertIs(cfg.protected_tools_enabled, False)
            self.assertEqual(cfg.turn_timeout_s, 42.5)
            self.assertEqual(cfg.max_body_bytes, 16000)

            # Invalid boolean string in env must raise ChannelError
            with self.assertRaises(ChannelError):
                load_channel_config(
                    path,
                    env={"FIREFLY_BRIDGE_ANSWER_PERMISSIONS": "not-a-bool"},
                )

            # main_channel console entrypoint works in dry-run without touching live
            buf = StringIO()
            with redirect_stdout(buf):
                rc = main_channel(["Ping via main_channel", "--dry-run", "--config", str(path)])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["mode"], "dry_run")
            self.assertEqual(out["permission_handler"], "leader_stdio_wake_deny")


class UnifiedStockDaemonAndIpcTests(unittest.TestCase):
    def test_unified_daemon_stock_grok_and_channel_ipc_roundtrip(self) -> None:
        import threading
        import warnings

        from firefly_bridge.config import BridgeConfig
        from firefly_bridge.daemon import Daemon
        from firefly_bridge.envelope import generate_key_file
        from firefly_bridge.ipc import IpcServer
        from firefly_bridge.rpc import PendingCall

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            keys_dir = tmp_path / "keys"
            keys_dir.mkdir()
            for p in ("agent-a", "agent-b", "agent-c", "human", "recipient"):
                generate_key_file(keys_dir / f"{p}.key")

            joint_dir = tmp_path / "wake-notes"
            state_dir = tmp_path / "state"
            cfg = BridgeConfig(
                socket_path=str(tmp_path / "leader-example.sock"),
                session_id="sess-example-0001",
                session_cwd=str(tmp_path),
                state_dir=str(state_dir),
                wake_dir=str(joint_dir),
                ipc_keys_dir=str(keys_dir),
                live_send=True,
                adapter_mode="stock_grok",
                agent_a_permission_mode="allow_all_own_turns",
                sender_interval_s=0,
                global_interval_s=0,
                pacing_minimums_enabled=False,
                post_turn_interval_s=0,
                target_interval_s=0,
                turn_timeout_s=2.0,
                poll_interval_s=0.01,
            ).validate()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                daemon = Daemon(cfg)

            class StockPeer:
                def __init__(self, session) -> None:
                    self.session = session
                    self.closed = threading.Event()
                    self.calls = []
                    self.responses = []

                def request(self, method, params, rpc_id=None):
                    self.calls.append((method, params))
                    call = PendingCall(rpc_id)
                    if method == "session/prompt":
                        text = params["prompt"][0]["text"]
                        pid = "stock-prompt-9001"
                        self.session._on_notification(
                            {
                                "method": "_x.ai/queue/changed",
                                "params": {
                                    "sessionId": self.session.cfg.session_id,
                                    "entries": [],
                                    "runningPromptId": pid,
                                    "runningText": text,
                                },
                            }
                        )
                        # Safe edit inside session_cwd -> approved by allow_all_own_turns
                        self.session._on_request(
                            {
                                "id": "perm-safe-1",
                                "method": "session/request_permission",
                                "params": {
                                    "sessionId": self.session.cfg.session_id,
                                    "toolCall": {
                                        "kind": "edit",
                                        "name": "edit_file",
                                        "rawInput": {"path": str(tmp_path / "note.md")},
                                    },
                                    "options": [{"kind": "allow_once", "optionId": "allow-once"}],
                                },
                            }
                        )
                        # Protected TCC request -> denied even in allow_all_own_turns!
                        self.session._on_request(
                            {
                                "id": "perm-tcc-2",
                                "method": "session/request_permission",
                                "params": {
                                    "sessionId": self.session.cfg.session_id,
                                    "toolCall": {
                                        "kind": "execute",
                                        "rawInput": {"command": "osascript -e 'tell app \"System Events\"'"},
                                    },
                                    "options": [
                                        {"kind": "allow_once", "optionId": "allow-once"},
                                        {"kind": "reject_once", "optionId": "reject-once"},
                                    ],
                                },
                            }
                        )
                        for idx, part in enumerate(["Unificado ", "com sucesso!"], start=1):
                            self.session._on_notification(
                                {
                                    "method": "session/update",
                                    "params": {
                                        "sessionId": self.session.cfg.session_id,
                                        "_meta": {"promptId": pid, "chunkId": idx},
                                        "update": {
                                            "sessionUpdate": "agent_message_chunk",
                                            "content": {"type": "text", "text": part},
                                        },
                                    },
                                }
                            )
                        self.session._on_notification(
                            {
                                "method": "_x.ai/session/update",
                                "params": {
                                    "sessionId": self.session.cfg.session_id,
                                    "update": {
                                        "sessionUpdate": "turn_completed",
                                        "prompt_id": pid,
                                        "stop_reason": "end_turn",
                                    },
                                },
                            }
                        )
                        call._resolve(
                            {
                                "result": {
                                    "stopReason": "end_turn",
                                    "_meta": {
                                        "sessionId": self.session.cfg.session_id,
                                        "promptId": pid,
                                    },
                                }
                            }
                        )
                    return call

                def respond(self, rid, result):
                    self.responses.append((rid, result))

                def _mark_closed(self):
                    self.closed.set()

            peer = StockPeer(daemon.session)
            daemon.session.conn = peer
            daemon.session.loaded_session_id = cfg.session_id
            daemon.session.incarnation = "stock-grok-test"
            daemon.session.remote_state = "idle"
            daemon.session.state_observed_at = time.monotonic()
            daemon.control("human", "opt_in")
            daemon.control("recipient", "opt_in")

            ipc_server = IpcServer(state_dir / "broker.sock", daemon)
            ipc_server.start()
            pump_stop = threading.Event()

            def pump_loop():
                while not pump_stop.is_set():
                    daemon.pump_once()
                    time.sleep(0.01)

            pumper = threading.Thread(target=pump_loop, daemon=True)
            pumper.start()
            try:
                t_cfg = ChannelConfig(
                    socket_path=cfg.socket_path,
                    session_id=cfg.session_id,
                    session_cwd=cfg.session_cwd,
                    state_dir=str(state_dir),
                    ipc_key_file=str(keys_dir / "agent-a.key"),
                    ipc_principal="agent-a",
                    wake_dir=str(joint_dir),
                    use_daemon_ipc=True,
                )
                dry = run_channel_turn(t_cfg, "Teste IPC dry", dry_run=True)
                self.assertTrue(dry["daemon_ipc_ready"])
                self.assertEqual(dry["permission_handler"], "wake_origin_deny")

                res = run_channel_turn(t_cfg, "Oi peerb via daemon unificado", message_id="id_unif00001")
                self.assertEqual(res["mode"], "daemon_ipc")
                self.assertTrue(res["delivered"])
                self.assertEqual(res["stop_reason"], "end_turn")
                self.assertEqual(res["prompt_id"], "stock-prompt-9001")
                self.assertEqual(res["reply_text_redacted"], "Unificado com sucesso!")
                self.assertIsNotNone(res["wake_artifacts"])
                self.assertTrue(Path(res["wake_artifacts"]["resposta_file"]).is_file())
                self.assertTrue((joint_dir / "WAKE.md").is_file())

                # Channel IPC is wake-origin: agent-a allow_all must not Allow.
                self.assertEqual(
                    peer.responses,
                    [
                        ("perm-safe-1", {"outcome": {"outcome": "cancelled"}}),
                        ("perm-tcc-2", {"outcome": {"outcome": "selected", "optionId": "reject-once"}}),
                    ],
                )
                self.assertGreaterEqual(res["wake_origin_denied_n"], 2)
                self.assertEqual(res["pending_card"]["reason"], "wake_origin_tool_denied")
                # Prompt sent in stock_grok mode has no _meta.agentBridge requirement
                self.assertNotIn("_meta", peer.calls[0][1])
            finally:
                pump_stop.set()
                pumper.join(1)
                ipc_server.close()
                daemon.close()


if __name__ == "__main__":
    unittest.main()
