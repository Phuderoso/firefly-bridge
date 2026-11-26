"""Tests for the publication-ready refinements: config, HMAC, permissions, outbox."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from firefly_bridge.config import BridgeConfig, ConfigError, load_config
from firefly_bridge.daemon import AcpSession, Daemon
from firefly_bridge.envelope import (
    KeyFileError,
    generate_key_file,
    load_key,
    sign_text,
    verify_text,
)
from firefly_bridge.permissions import PermissionPolicy, extract_paths, path_inside
from firefly_bridge.queue import (
    CANCELLED,
    DELIVERED,
    TIMED_OUT,
    BusyRefused,
    Outbox,
    OutboxFull,
    TurnTimeout,
)
from firefly_bridge.rpc import JsonRpcConnection


class ConfigTests(unittest.TestCase):
    def test_defaults_do_not_require_target_when_asked(self) -> None:
        cfg = load_config(env={}, require_target=False)
        self.assertFalse(cfg.live_send)
        self.assertFalse(cfg.strip_grok_sandbox)
        self.assertEqual(cfg.permission_mode, "pending")
        self.assertEqual(cfg.auth_mode, "prefix")
        self.assertEqual(cfg.shared_dir, "shared/")

    def test_toml_and_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.toml"
            path.write_text(
                "[bridge]\n"
                'socket_path = "~/.grok/leader-example.sock"\n'
                'session_id = "sess-example-0001"\n'
                "live_send = false\n"
                'agent_a_permission_mode = "allowlist"\n'
                'shared_dir = "shared/"\n'
                "turn_timeout_s = 12.5\n",
                encoding="utf-8",
            )
            env = {
                "FIREFLY_BRIDGE_LIVE_SEND": "true",
                "FIREFLY_BRIDGE_BUSY_POLICY": "fail",
                "HOME": tmp,
            }
            cfg = load_config(path, env=env)
            self.assertTrue(cfg.live_send)
            self.assertEqual(cfg.busy_policy, "fail")
            self.assertEqual(cfg.agent_a_permission_mode, "allowlist")
            self.assertEqual(cfg.turn_timeout_s, 12.5)
            self.assertTrue(cfg.socket_path.endswith("leader-example.sock"))
            self.assertNotIn("/Users/", cfg.socket_path)

    def test_hmac_requires_key_file(self) -> None:
        with self.assertRaises(ConfigError):
            BridgeConfig(
                auth_mode="hmac",
                session_id="sess-example-0001",
                socket_path="/tmp/x.sock",
            ).validate()

    def test_strip_sandbox_is_opt_in(self) -> None:
        cfg = BridgeConfig().validate(require_target=False)
        self.assertFalse(cfg.strip_grok_sandbox)

    def test_unknown_key_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cfg.toml"
            path.write_text('weird = "no"\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path, env={}, require_target=False)


class EnvelopeTests(unittest.TestCase):
    def test_round_trip_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "hmac.key"
            generate_key_file(key_path)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            key = load_key(key_path)
            text = sign_text(
                key,
                prefix="agent-a: ",
                sender="agent-a",
                session_id="sess-example-0001",
                message_id="id_abcdef0123456789",
                body="hello peer",
                ts=1_700_000_000,
                nonce="aabbccddeeff001122334455",
            )
            self.assertTrue(text.startswith("agent-a: hello peer"))
            self.assertIn("[msgsig v=1 from=agent-a", text)
            ok = verify_text(
                key,
                text,
                expected_sender="agent-a",
                expected_session_id="sess-example-0001",
                max_age_s=None,
            )
            self.assertTrue(ok.valid)
            self.assertEqual(ok.body, "hello peer")
            bad = text.replace("hello peer", "hello stranger", 1)
            self.assertFalse(verify_text(key, bad, max_age_s=None).valid)
            seen: set[str] = set()
            self.assertTrue(verify_text(key, text, max_age_s=None, seen_nonces=seen).valid)
            self.assertEqual(
                verify_text(key, text, max_age_s=None, seen_nonces=seen).reason,
                "replayed_nonce",
            )

    def test_refuses_world_readable_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "open.key"
            key_path.write_bytes(b"x" * 64)
            key_path.chmod(0o644)
            with self.assertRaises(KeyFileError):
                load_key(key_path)


class PermissionTests(unittest.TestCase):
    def _req(self, *, kind="edit", path="shared/note.md", allow_once=True):
        options = []
        if allow_once:
            options.append({"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"})
        options.append({"optionId": "reject-once", "name": "Reject", "kind": "reject_once"})
        return {
            "jsonrpc": "2.0",
            "id": "perm-1",
            "method": "session/request_permission",
            "params": {
                "sessionId": "sess-example-0001",
                "toolCall": {
                    "toolCallId": "call_001",
                    "kind": kind,
                    "title": "Edit file",
                    "locations": [{"path": path}],
                    "rawInput": {"path": path},
                },
                "options": options,
            },
        }

    def test_default_pending_on_own_turn(self) -> None:
        policy = PermissionPolicy(mode="pending")
        d = policy.decide(self._req(), own_turn=True)
        self.assertEqual(d.action, "pending")
        self.assertEqual(d.reason, "policy_pending_approve_nothing")

    def test_foreign_turn_is_ignored(self) -> None:
        policy = PermissionPolicy(mode="allowlist", shared_dir="shared/")
        d = policy.decide(self._req(), own_turn=False)
        self.assertEqual(d.action, "ignore")
        self.assertEqual(d.reason, "not_bridge_turn_first_answer_wins")

    def test_allowlist_approves_edit_inside_shared(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            shared.mkdir()
            (shared / "note.md").write_text("x", encoding="utf-8")
            policy = PermissionPolicy(mode="allowlist", shared_dir=str(shared), base_dir=tmp)
            d = policy.decide(self._req(path=str(shared / "note.md")), own_turn=True)
            self.assertEqual(d.action, "approve")
            self.assertEqual(d.option_id, "allow-once")

    def test_allowlist_keeps_outside_paths_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            shared.mkdir()
            policy = PermissionPolicy(mode="allowlist", shared_dir=str(shared), base_dir=tmp)
            d = policy.decide(self._req(path=str(Path(tmp) / "outside" / "x")), own_turn=True)
            self.assertEqual(d.action, "pending")
            self.assertEqual(d.reason, "path_outside_shared_dir")

    def test_allowlist_rejects_non_edit(self) -> None:
        policy = PermissionPolicy(
            mode="allowlist", shared_dir="shared/", protected_tools_enabled=False
        )
        d = policy.decide(self._req(kind="execute"), own_turn=True)
        self.assertEqual(d.action, "pending")
        self.assertEqual(d.reason, "tool_kind_not_allowlisted")

    def test_allow_all_approves_any_tool_on_own_turn(self) -> None:
        policy = PermissionPolicy(mode="allow_all", base_dir="/tmp", protected_tools_enabled=False)
        req = {
            "method": "session/request_permission",
            "params": {
                "toolCall": {
                    "kind": "execute",
                    "title": "Run command",
                    "rawInput": {"command": "echo hi"},
                },
                "options": [
                    {"optionId": "allow-once", "kind": "allow_once"},
                    {"optionId": "reject-once", "kind": "reject_once"},
                ],
            },
        }
        d = policy.decide(req, own_turn=True)
        self.assertEqual(d.action, "approve")
        self.assertEqual(d.reason, "allow_all_own_turn")
        self.assertEqual(d.option_id, "allow-once")

    def test_allow_all_still_ignores_foreign_turns(self) -> None:
        policy = PermissionPolicy(mode="allow_all", base_dir="/tmp", protected_tools_enabled=False)
        req = {
            "method": "session/request_permission",
            "params": {
                "toolCall": {
                    "kind": "edit",
                    "title": "Edit `/tmp/x`",
                    "rawInput": {"file_path": "/tmp/x"},
                },
                "options": [{"optionId": "allow-once", "kind": "allow_once"}],
            },
        }
        d = policy.decide(req, own_turn=False)
        self.assertEqual(d.action, "ignore")

    def test_symlink_escape_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            shared.mkdir()
            outside = Path(tmp) / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            link = shared / "escape"
            link.symlink_to(outside)
            self.assertFalse(path_inside(str(link), str(shared), tmp))

    def test_extract_paths_from_raw_input(self) -> None:
        paths = extract_paths({"rawInput": {"file_path": "/a/b", "paths": ["/c", {"path": "/d"}]}})
        self.assertEqual(paths, ["/a/b", "/c", "/d"])


class QueueTests(unittest.TestCase):
    def test_single_in_flight_and_timeout_holds_unknown(self) -> None:
        clock = {"t": 0.0}

        def runner(turn):
            while True:
                if turn.cancel_requested.is_set() or (
                    turn.deadline is not None and clock["t"] >= turn.deadline
                ):
                    turn.cancel_requested.set()
                    raise TurnTimeout("turn_timeout_cancelled")
                clock["t"] += 1
                if clock["t"] > 10_000:
                    raise AssertionError("runaway")

        box = Outbox(runner, turn_timeout_s=5, busy_wait_s=100, now=lambda: clock["t"])
        box.enqueue("id_one", "sess-example-0001", "a", "agent-a: a")
        box.enqueue("id_two", "sess-example-0001", "b", "agent-a: b")
        first = box.pump_once()
        self.assertIsNotNone(first)
        assert first is not None
        self.assertEqual(first.message_id, "id_one")
        self.assertEqual(first.state, TIMED_OUT)
        self.assertEqual(first.reason, "observation_timeout_no_cancel")
        box._runner = lambda turn: {"stop_reason": "end_turn"}  # noqa: SLF001
        clock["t"] = first.settled_at or clock["t"]
        self.assertIsNone(box.pump_once())
        self.assertEqual(box.status()["in_flight"], "id_one")
        box.reconcile(first, {"stop_reason": "end_turn"})
        second = box.pump_once()
        self.assertEqual(second.message_id, "id_two")
        self.assertEqual(second.state, DELIVERED)

    def test_busy_fail_refuses_second(self) -> None:
        gate = threading.Event()

        def runner(turn):
            gate.wait(2)
            return {"stop_reason": "end_turn"}

        box = Outbox(runner, turn_timeout_s=30, busy_policy="fail", max_outbox=4)
        box.enqueue("id_a", "sess-example-0001", "a", "agent-a: a")
        t = threading.Thread(target=box.pump_once, daemon=True)
        t.start()
        for _ in range(100):
            if box.status()["in_flight"] == "id_a":
                break
            time.sleep(0.01)
        self.assertEqual(box.status()["in_flight"], "id_a")
        with self.assertRaises(BusyRefused):
            box.enqueue("id_b", "sess-example-0001", "b", "agent-a: b")
        gate.set()
        t.join(3)

    def test_max_outbox(self) -> None:
        box = Outbox(lambda t: {"stop_reason": "end_turn"}, max_outbox=1, busy_policy="wait")
        box.enqueue("id_1", "sess-example-0001", "a", "agent-a: a")
        with self.assertRaises(OutboxFull):
            box.enqueue("id_2", "sess-example-0001", "b", "agent-a: b")

    def test_explicit_cancel_of_queued(self) -> None:
        box = Outbox(lambda t: {"stop_reason": "end_turn"})
        box.enqueue("id_x", "sess-example-0001", "a", "agent-a: a")
        turn = box.cancel("id_x", reason="user_cancel")
        self.assertIsNotNone(turn)
        assert turn is not None
        self.assertEqual(turn.state, CANCELLED)
        self.assertEqual(box.status()["pending"], [])

    def test_busy_wait_expires_queued(self) -> None:
        clock = {"t": 0.0}
        hold = threading.Event()

        def runner(turn):
            hold.wait(2)
            return {"stop_reason": "end_turn"}

        box = Outbox(
            runner,
            turn_timeout_s=100,
            busy_wait_s=5,
            busy_policy="wait",
            now=lambda: clock["t"],
        )
        box.enqueue("id_hold", "sess-example-0001", "a", "agent-a: a")
        box.enqueue("id_wait", "sess-example-0001", "b", "agent-a: b")
        t = threading.Thread(target=box.pump_once, daemon=True)
        t.start()
        for _ in range(100):
            if box.status()["in_flight"] == "id_hold":
                break
            time.sleep(0.01)
        clock["t"] = 10
        box.pump_once()
        self.assertEqual(box.status()["pending"], [])
        hold.set()
        t.join(3)


class RpcAndDaemonUnitTests(unittest.TestCase):
    def test_rpc_request_response(self) -> None:
        r_fd, w_fd = os.pipe()
        reader = os.fdopen(r_fd, "rb", buffering=0)
        peer_writer = os.fdopen(w_fd, "wb", buffering=0)
        captured: list[bytes] = []

        class CapturingWriter:
            def write(self, data: bytes) -> None:
                captured.append(data)

            def flush(self) -> None:
                return None

        conn = JsonRpcConnection(reader, CapturingWriter())
        conn.start()
        call = conn.request(
            "initialize",
            {
                "protocolVersion": "0.1.0",
                "clientInfo": {"name": "t"},
                "capabilities": {},
            },
        )
        peer_writer.write(b'{"jsonrpc":"2.0","id":"ffb-1","result":{"protocolVersion":"0.1.0"}}\n')
        peer_writer.flush()
        self.assertTrue(call.wait(2))
        self.assertIsNone(call.error)
        self.assertEqual(call.result["protocolVersion"], "0.1.0")
        self.assertTrue(captured[0].startswith(b'{"jsonrpc":"2.0"'))
        peer_writer.close()
        reader.close()

    def test_daemon_enqueue_refuses_without_live_send(self) -> None:
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        cfg = BridgeConfig(
            socket_path="/tmp/does-not-exist.sock",
            session_id="sess-example-0001",
            live_send=False,
            state_dir=state.name,
        ).validate()
        daemon = Daemon(cfg, session=AcpSession(cfg))
        self.addCleanup(daemon.close)  # releases the per-UID dispatch authority and the store
        result = daemon.enqueue("id_deadbeefcafe", "hello")
        self.assertEqual(result["reason"], "live_send_disabled")
        self.assertEqual(result["queue_state"], "refused")

    def test_build_outbound_hmac(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "k"
            generate_key_file(key_path)
            cfg = BridgeConfig(
                socket_path="/tmp/x.sock",
                session_id="sess-example-0001",
                auth_mode="hmac",
                hmac_key_file=str(key_path),
                state_dir=tmp,
            ).validate()
            session = AcpSession(cfg)
            session._hmac_key = load_key(key_path)  # noqa: SLF001
            text = session.build_outbound("id_deadbeefcafe01", "ping")
            self.assertTrue(verify_text(load_key(key_path), text, max_age_s=None).valid)


class CliRefinedTests(unittest.TestCase):
    def test_keygen_verify_roundtrip_via_cli(self) -> None:
        from firefly_bridge.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "k"
            buf = StringIO()
            with redirect_stdout(buf):
                rc = main(["keygen", "--path", str(key)])
            self.assertEqual(rc, 0)
            text = sign_text(
                load_key(key),
                prefix="agent-a: ",
                sender="agent-a",
                session_id="sess-example-0001",
                message_id="id_cliroundtrip0001",
                body="via cli",
            )
            buf = StringIO()
            with redirect_stdout(buf):
                rc = main(
                    ["verify", "--key-file", str(key), "--text", text, "--max-age", "999999999"]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(buf.getvalue())["valid"])


if __name__ == "__main__":
    unittest.main()
