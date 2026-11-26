"""Isolated policy tests. No grok binary and no network."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

from firefly_bridge.acp import ForbiddenMethod, defer_permission, deny_permission, session_prompt
from firefly_bridge.bridge import Bridge
from firefly_bridge.ledger import LedgerCorrupt
from firefly_bridge.messages import (
    FORBIDDEN_CLIENT_METHODS,
    AlreadySettled,
    AttributionError,
    ConflictingMessage,
    DuplicateMessage,
    SessionPinError,
)
from firefly_bridge.preflight import (
    ALLOWLIST,
    PreflightRefused,
    _subprocess_runner,
    contract_report,
    evaluate_observation,
    execute_readonly,
)
from firefly_bridge.transport import DisabledLiveTransport, MockTransport

PIN = "sess-example-0001"
ROOT = Path(__file__).resolve().parents[1]


_SCRATCH = tempfile.TemporaryDirectory(prefix="ffb-test-bridge-")


def tearDownModule() -> None:  # noqa: N802 - unittest hook name
    _SCRATCH.cleanup()


def _ledger() -> Path:
    """Fresh ledger path per call, under one module scratch dir removed at module teardown."""
    return Path(tempfile.mkdtemp(dir=_SCRATCH.name)) / "receipts.json"


def _send(
    script: str,
    session: str = PIN,
    busy: bool | None = False,
    text: str = "olá",
    message_id: str | None = None,
    ledger_path: Path | None = None,
):
    transport = MockTransport(pinned_session_id=PIN, script=script, busy_precondition=busy)
    bridge = Bridge(transport, timeout_s=0.5, ledger_path=ledger_path or _ledger())
    receipt = bridge.prepare(session, text, message_id=message_id)
    bridge.send(receipt)
    return bridge, transport, receipt


class PolicyTests(unittest.TestCase):
    def test_correlated_mock_round_trip(self) -> None:
        _, transport, receipt = _send("ok")
        self.assertEqual(receipt.outcome, "responded")
        self.assertEqual(
            receipt.history,
            ["prepared", "unknown", "transport-accepted", "responded"],
        )
        self.assertTrue(receipt.attempt_committed)
        self.assertEqual(receipt.outbound_text, "agent-a: olá")
        self.assertIsNone(receipt.block_code)
        self.assertTrue(receipt.correlation["ids_match"])
        self.assertEqual(receipt.correlation["result_id"], receipt.message_id)
        self.assertEqual(receipt.correlation["assistant_text"], "mock reply correlated")
        self.assertFalse(receipt.correlation["acp_acceptance_ack_documented"])
        self.assertEqual(receipt.source, "agent-a")
        self.assertIsNone(receipt.acp_speaker_field)
        self.assertEqual(transport.methods, ["session/prompt"])
        self.assertFalse(receipt.resend_attempted)

    def test_wrong_session_does_not_create(self) -> None:
        _, transport, receipt = _send("ok", session="sess-other-9999")
        self.assertEqual(receipt.outcome, "prepared")
        self.assertEqual(receipt.block_code, "session_rejected")
        self.assertNotIn("transport-accepted", receipt.history)
        self.assertEqual(transport.methods, ["session/prompt"])
        self.assertFalse(transport.created_session)
        self.assertFalse(transport.loaded_history)

    def test_missing_and_unpinned_session_never_writes(self) -> None:
        transport = MockTransport()
        bridge = Bridge(transport, timeout_s=0.5, ledger_path=_ledger())
        for bad in (None, "", "latest", "continue", "new", "resume", "fork", "short", "has space"):
            with self.assertRaises(SessionPinError):
                bridge.prepare(bad, "x")
        self.assertEqual(transport.written, [])

    def test_source_must_match_sender(self) -> None:
        bridge = Bridge(MockTransport(), timeout_s=0.5, ledger_path=_ledger())
        with self.assertRaises(AttributionError):
            bridge.prepare(PIN, "x", source="peerb")

    def test_no_create_across_scripts(self) -> None:
        for script in ("ok", "timeout", "crash", "malformed", "permission", "mismatch"):
            _, transport, _ = _send(script)
            self.assertTrue(set(transport.methods).issubset({"session/prompt"}))
            for method in FORBIDDEN_CLIENT_METHODS:
                self.assertNotIn(method, transport.methods)

    def test_forbidden_method_does_not_load_or_create(self) -> None:
        transport = MockTransport()
        for method in ("session/new", "session/load", "session/fork", "session/cancel"):
            frame = {"jsonrpc": "2.0", "id": "id_deadbeef0000", "method": method, "params": {}}
            result = transport.exchange(frame, 0.2, lambda request: {})
            self.assertEqual(result.error["data"]["agentMock"], "forbidden")
        self.assertFalse(transport.created_session)
        self.assertFalse(transport.loaded_history)

    def test_prompt_builder_rejects_setup_fields(self) -> None:
        frame = session_prompt(PIN, "x", "id_abc123456789")
        self.assertEqual(frame["method"], "session/prompt")
        frame["params"]["cwd"] = "/tmp"
        with self.assertRaises(ForbiddenMethod):
            from firefly_bridge.acp import check_client_frame

            check_client_frame(frame)

    def test_busy_before_write_and_unknown_busy(self) -> None:
        _, transport, receipt = _send("ok", busy=True)
        self.assertEqual(receipt.block_code, "busy_fail_closed")
        self.assertEqual(receipt.outcome, "prepared")
        self.assertEqual(transport.methods, [])
        _, transport, receipt = _send("ok", busy=None)
        self.assertEqual(receipt.block_code, "busy_unknowable_fail_closed")
        self.assertEqual(transport.methods, [])

    def test_timeout_crash_malformed_are_unknown_and_not_resent(self) -> None:
        for script, code in (
            ("timeout", "timeout_no_resend"),
            ("crash", "crash_no_resend"),
            ("malformed", "malformed_rpc_no_resend"),
        ):
            bridge, transport, receipt = _send(script)
            self.assertEqual(receipt.outcome, "unknown", script)
            self.assertEqual(receipt.block_code, code)
            self.assertEqual(len(transport.written), 1)
            with self.assertRaises(AlreadySettled):
                bridge.send(receipt)
            self.assertEqual(len(transport.written), 1)
            self.assertFalse(receipt.resend_attempted)

    def test_duplicate_message_id(self) -> None:
        bridge = Bridge(MockTransport(), timeout_s=0.5, ledger_path=_ledger())
        with self.assertRaises(DuplicateMessage):
            bridge.prepare(PIN, "a", message_id="not-an-ff-id")

    def test_hanging_transport_hits_deadline_without_cancel(self) -> None:
        started = threading.Event()

        class Hang:
            name = "mock"
            enabled = True
            busy_precondition = False

            def __init__(self) -> None:
                self.methods = []

            def exchange(self, frame, timeout_s, on_server_request):
                self.methods.append(frame["method"])
                started.set()
                threading.Event().wait(2)
                raise AssertionError("should have been abandoned at the deadline")

        transport = Hang()
        bridge = Bridge(transport, timeout_s=0.15, ledger_path=_ledger())
        receipt = bridge.prepare(PIN, "x")
        bridge.send(receipt)
        self.assertTrue(started.wait(1))
        self.assertEqual(receipt.outcome, "unknown")
        self.assertEqual(receipt.block_code, "timeout_no_resend")
        self.assertEqual(transport.methods, ["session/prompt"])

    def test_correlation_mismatch_is_unknown(self) -> None:
        _, _, receipt = _send("mismatch")
        self.assertEqual(receipt.outcome, "unknown")
        self.assertEqual(receipt.block_code, "correlation_mismatch_no_resend")
        self.assertFalse(receipt.correlation["ids_match"])

    def test_permission_deferred_to_human_tui(self) -> None:
        _, transport, receipt = _send("permission")
        self.assertEqual(receipt.outcome, "responded")
        self.assertEqual(receipt.permission["how"], "deferred_to_human_tui")
        self.assertIsNone(receipt.permission["outcome"])
        self.assertEqual(receipt.permission["tools_executed"], [])
        self.assertFalse(receipt.permission["privileges_changed"])
        self.assertFalse(receipt.permission["bridge_wrote_permission_result"])
        self.assertFalse(transport.always_approve)
        self.assertNotIn("session/cancel", transport.methods)

    def test_allow_only_permission_also_deferred(self) -> None:
        _, transport, receipt = _send("permission-allow-only")
        self.assertEqual(receipt.permission["how"], "deferred_to_human_tui")
        self.assertIsNone(receipt.permission["outcome"])
        self.assertEqual(transport.tools_executed, [])
        self.assertFalse(receipt.permission["bridge_wrote_permission_result"])
        # deny_permission helper still exists for solo/tests, not used on shared leader
        response = deny_permission(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "session/request_permission",
                "params": {
                    "options": [
                        {"optionId": "allow-once", "kind": "allow_once", "name": "Allow"}
                    ]
                },
            }
        )
        self.assertEqual(response["result"]["outcome"]["outcome"], "cancelled")

    def test_defer_permission_returns_none(self) -> None:
        self.assertIsNone(
            defer_permission(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "session/request_permission",
                    "params": {"options": [{"optionId": "allow-once", "kind": "allow_once"}]},
                }
            )
        )

    def test_live_transport_writes_nothing(self) -> None:
        transport = DisabledLiveTransport()
        bridge = Bridge(transport, timeout_s=1, ledger_path=_ledger())
        receipt = bridge.prepare(PIN, "não enviar")
        bridge.send(receipt)
        self.assertEqual(receipt.outcome, "prepared")
        self.assertEqual(receipt.block_code, "live_transport_disabled")
        self.assertEqual(transport.calls, 0)

    def test_timeout_bounds_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Bridge(MockTransport(), timeout_s=0)
        with self.assertRaises(ValueError):
            Bridge(MockTransport(), timeout_s=31)


class LedgerTests(unittest.TestCase):
    def test_reopen_does_not_exchange_again(self) -> None:
        ids = {"timeout": "id_timeout0001", "crash": "id_crash000001", "ok": "id_ok000000001"}
        for script, outcome in (("timeout", "unknown"), ("crash", "unknown"), ("ok", "responded")):
            path = _ledger()
            message_id = ids[script]
            _, first, receipt = _send(script, message_id=message_id, ledger_path=path, text="nota")
            self.assertEqual(receipt.outcome, outcome, script)
            self.assertTrue(receipt.attempt_committed)
            self.assertEqual(len(first.written), 1)

            second = MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=False)
            reopened = Bridge(second, timeout_s=0.5, ledger_path=path)
            again = reopened.prepare(PIN, "nota", message_id=message_id)
            with self.assertRaises(AlreadySettled):
                reopened.send(again)
            self.assertEqual(second.written, [], script)
            self.assertEqual(again.outcome, outcome, script)
            self.assertFalse(again.resend_attempted)

    def test_prepared_survives_restart_and_sends_once(self) -> None:
        path = _ledger()
        message_id = "id_prepared001"
        first = Bridge(MockTransport(), timeout_s=0.5, ledger_path=path)
        first.prepare(PIN, "nota", message_id=message_id)
        transport = MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=False)
        second = Bridge(transport, timeout_s=0.5, ledger_path=path)
        receipt = second.prepare(PIN, "nota", message_id=message_id)
        second.send(receipt)
        self.assertEqual(len(transport.written), 1)
        self.assertEqual(receipt.outcome, "responded")
        third_transport = MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=False)
        third = Bridge(third_transport, timeout_s=0.5, ledger_path=path)
        loaded = third.prepare(PIN, "nota", message_id=message_id)
        with self.assertRaises(AlreadySettled):
            third.send(loaded)
        self.assertEqual(third_transport.written, [])

    def test_conflicting_id_content_does_not_exchange(self) -> None:
        path = _ledger()
        message_id = "id_conflict001"
        transport = MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=False)
        bridge = Bridge(transport, timeout_s=0.5, ledger_path=path)
        bridge.prepare(PIN, "um", message_id=message_id)
        with self.assertRaises(ConflictingMessage):
            bridge.prepare(PIN, "dois", message_id=message_id)
        with self.assertRaises(ConflictingMessage):
            bridge.prepare("sess-other-9999", "um", message_id=message_id)
        reopened = Bridge(
            MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=False),
            timeout_s=0.5,
            ledger_path=path,
        )
        with self.assertRaises(ConflictingMessage):
            reopened.prepare(PIN, "dois", message_id=message_id)
        self.assertEqual(transport.written, [])

    def test_outbound_attribution_and_json_framing(self) -> None:
        _, transport, receipt = _send("ok", text="nota sintética")
        self.assertEqual(len(transport.written), 1)
        frame = json.loads(transport.written[0])
        self.assertEqual(frame["jsonrpc"], "2.0")
        self.assertEqual(frame["id"], receipt.message_id)
        self.assertEqual(frame["method"], "session/prompt")
        self.assertEqual(set(frame), {"jsonrpc", "id", "method", "params"})
        self.assertEqual(set(frame["params"]), {"sessionId", "prompt"})
        self.assertEqual(
            frame["params"]["prompt"],
            [{"type": "text", "text": "agent-a: nota sintética"}],
        )
        self.assertNotIn("_meta", frame)
        self.assertNotIn("speaker", frame["params"])
        self.assertIsNone(receipt.acp_speaker_field)
        self.assertEqual(receipt.attribution_channel, "outbound-user-content")
        self.assertEqual(transport.methods, ["session/prompt"])

    def test_unknown_is_durable_before_exchange(self) -> None:
        path = _ledger()
        message_id = "id_peek0000001"
        seen: dict = {}

        class Peek:
            name = "mock"
            enabled = True
            busy_precondition = False

            def __init__(self) -> None:
                self.inner = MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=False)
                self.written = self.inner.written
                self.methods = self.inner.methods

            def exchange(self, frame, timeout_s, on_server_request):
                seen["disk"] = json.loads(path.read_text(encoding="utf-8"))
                return self.inner.exchange(frame, timeout_s, on_server_request)

        transport = Peek()
        bridge = Bridge(transport, timeout_s=0.5, ledger_path=path)
        receipt = bridge.prepare(PIN, "nota", message_id=message_id)
        bridge.send(receipt)
        stored = seen["disk"]["receipts"][message_id]
        self.assertEqual(stored["outcome"], "unknown")
        self.assertTrue(stored["attempt_committed"])
        self.assertEqual(stored["block_code"], "attempt_opened")
        self.assertEqual(receipt.outcome, "responded")

    def test_corrupt_ledger_does_not_send(self) -> None:
        path = _ledger()
        path.write_text("{", encoding="utf-8")
        transport = MockTransport()
        bridge = Bridge(transport, timeout_s=0.5, ledger_path=path)
        with self.assertRaises(LedgerCorrupt):
            bridge.prepare(PIN, "nota", message_id="id_corrupt0001")
        self.assertEqual(transport.written, [])


class PreflightTests(unittest.TestCase):
    def test_contract_blocks_live_send(self) -> None:
        report = contract_report()
        self.assertFalse(report["live_send_allowed"])
        self.assertFalse(report["noninterruption_guaranteed"])
        self.assertFalse(report["disk_load_is_live_attachment"])
        self.assertFalse(report["busy_query_documented"])
        ids = {item["id"] for item in report["blockers"]}
        self.assertIn("attach", ids)
        self.assertIn("noninterruption", ids)
        self.assertIn("composer", ids)

    def test_fixture_cannot_force_the_gate_open(self) -> None:
        report = evaluate_observation(
            {
                "live_send_allowed": True,
                "noninterruption_guaranteed": True,
                "leader_list_ran": True,
                "leader_count": 1,
                "sessions_list_ran": True,
                "pinned_session_id_seen": True,
                "sessions_raw": "LEAK private summary",
                "leader_raw": [{"token": "sekrit-value"}],
            }
        )
        self.assertFalse(report["live_send_allowed"])
        self.assertFalse(report["send_authorized_by_passing_gates"])
        self.assertFalse(report["noninterruption_guaranteed"])
        blob = json.dumps(report)
        self.assertNotIn("LEAK", blob)
        self.assertNotIn("sekrit-value", blob)
        self.assertIn("leader_process_listed", report["leader_interpretation"])
        self.assertTrue(all(not gate["pass"] or gate["id"] == "no_restart" for gate in report["gates"]))

    def test_empty_leader_list_is_not_impossibility(self) -> None:
        report = evaluate_observation(
            {"leader_list_ran": True, "leader_count": 0, "leader_json_shape": "list"}
        )
        self.assertIn("not impossibility", report["leader_interpretation"])
        self.assertFalse(report["disk_load_is_live_attachment"])
        self.assertFalse(report["live_send_allowed"])

    def test_allowlist_rejects_mutating_argv_before_spawn(self) -> None:
        for argv in (
            ("grok", "agent", "stdio"),
            ("grok", "--resume", PIN),
            ("grok", "-p", "hi"),
            ("grok", "leader", "kill"),
            ("grok", "sessions", "search", "peerb"),
            ("grok", "sessions", "delete", PIN),
        ):
            with self.assertRaises(PreflightRefused):
                _subprocess_runner(argv, None)

    def test_execute_requires_env_flag(self) -> None:
        with self.assertRaises(PreflightRefused):
            execute_readonly(pinned_session_id=PIN, session_cwd=None, env_execute=None)

    def test_execute_against_fake_grok_redacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "argv"
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            workspace = Path(tmp) / "workspace"
            workspace.mkdir()
            grok = bindir / "grok"
            grok.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    printf '%s\\n' "$*" >> "{log}"
                    case "$*" in
                      version)
                        echo "grok 1.0.70 (f50904eaee6c)"
                        ;;
                      "leader list --help")
                        echo "List discovered leaders"
                        echo "--json"
                        ;;
                      "leader list --json")
                        echo '[{{\"token\":\"sekrit-value\",\"socket\":\"/tmp/leader.sock\"}}]'
                        ;;
                      "sessions list --limit 50")
                        echo "{PIN} LEAK_ME_SUMMARY draft"
                        ;;
                      *)
                        echo "unexpected $*" >&2
                        exit 9
                        ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            grok.chmod(grok.stat().st_mode | stat.S_IEXEC)
            env = os.environ.copy()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            env["AGENT_PREFLIGHT_EXECUTE"] = "1"
            env["PINNED_SESSION_ID"] = PIN
            env["AGENT_SESSION_CWD"] = str(workspace)
            proc = subprocess.run(
                [sys.executable, "-m", "firefly_bridge", "mac-preflight", "--execute"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            report = json.loads(proc.stdout)
            blob = proc.stdout
            self.assertNotIn("sekrit-value", blob)
            self.assertNotIn("leader.sock", blob)
            self.assertNotIn("LEAK_ME_SUMMARY", blob)
            self.assertFalse(report["live_send_allowed"])
            self.assertEqual(report["observation"]["leader_count"], 1)
            self.assertTrue(report["observation"]["secrets_redacted"])
            self.assertTrue(report["observation"]["pinned_session_id_seen"])
            argv = log.read_text(encoding="utf-8")
            self.assertNotIn("kill", argv)
            self.assertNotIn("search", argv)
            self.assertNotIn("--resume", argv)
            self.assertNotIn("agent", argv)

    def test_help_without_json_does_not_list_leaders(self) -> None:
        calls = []

        class Done:
            def __init__(self, code: int, out: bytes) -> None:
                self.returncode = code
                self.stdout = out
                self.stderr = b""

        def runner(argv, cwd):
            calls.append(argv)
            if argv == ("grok", "version"):
                return Done(0, b"grok test")
            if argv == ("grok", "leader", "list", "--help"):
                return Done(0, b"usage: leader list\n")
            raise AssertionError(argv)

        report = execute_readonly(
            pinned_session_id=None,
            session_cwd=None,
            runner=runner,
            env_execute="1",
        )
        self.assertNotIn(("grok", "leader", "list", "--json"), calls)
        self.assertFalse(report["observation"]["leader_list_ran"])
        self.assertFalse(report["live_send_allowed"])

    def test_grok_dir_cwd_is_refused(self) -> None:
        calls = []

        class Done:
            returncode = 0
            stdout = b"grok test"
            stderr = b""

        def runner(argv, cwd):
            calls.append((argv, cwd))
            return Done()

        with tempfile.TemporaryDirectory() as tmp:
            refused = Path(tmp) / ".grok" / "sessions"
            refused.mkdir(parents=True)
            report = execute_readonly(
                pinned_session_id=PIN,
                session_cwd=str(refused),
                runner=runner,
                env_execute="1",
            )
        self.assertNotIn(("grok", "sessions", "list", "--limit", "50"), [c[0] for c in calls])
        self.assertTrue(report["observation"]["session_cwd_refused"])
        self.assertIsNone(report["observation"]["pinned_session_id_seen"])

    def test_missing_binary(self) -> None:
        def runner(argv, cwd):
            raise FileNotFoundError(argv[0])

        report = execute_readonly(
            pinned_session_id=PIN,
            session_cwd="/tmp",
            runner=runner,
            env_execute="1",
        )
        self.assertTrue(report["observation"]["grok_missing"])
        self.assertFalse(report["live_send_allowed"])
        self.assertEqual(ALLOWLIST[0], ("grok", "version"))


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._env = os.environ.copy()
        self._env["AGENT_LEDGER"] = str(Path(self._tmp.name) / "receipts.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "firefly_bridge", *args],
            cwd=ROOT,
            env=self._env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_exits(self) -> None:
        pre = self._run(["preflight"])
        self.assertEqual(pre.returncode, 2)
        self.assertFalse(json.loads(pre.stdout)["live_send_allowed"])
        self.assertIn("exit 2 esperado", pre.stderr)

        live = self._run(
            ["send", "--transport", "live", "--session-id", PIN, "--text", "não"]
        )
        self.assertEqual(live.returncode, 3)
        body = json.loads(live.stdout)
        self.assertEqual(body["block_code"], "live_transport_disabled")

        ok = self._run(
            [
                "send",
                "--transport",
                "mock",
                "--session-id",
                PIN,
                "--mock-session",
                PIN,
                "--text",
                "sintética",
            ]
        )
        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertEqual(json.loads(ok.stdout)["outcome"], "responded")

        missing = self._run(["prepare", "--session-id", "latest", "--text", "x"])
        self.assertEqual(missing.returncode, 1)

    def test_cli_reopen_same_id_does_not_resend(self) -> None:
        message_id = "id_cli00000001"
        args = [
            "send",
            "--transport",
            "mock",
            "--session-id",
            PIN,
            "--mock-session",
            PIN,
            "--text",
            "sintética",
            "--message-id",
            message_id,
            "--script",
            "timeout",
            "--timeout",
            "0.5",
        ]
        first = self._run(args)
        self.assertEqual(first.returncode, 5, first.stdout)
        self.assertEqual(json.loads(first.stdout)["outcome"], "unknown")
        second = self._run(args)
        self.assertEqual(second.returncode, 1, second.stdout)
        body = json.loads(second.stdout)
        self.assertEqual(body["error"], "no_automatic_resend")
        self.assertFalse(body["resend_attempted"])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
