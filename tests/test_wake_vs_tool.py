"""Wake vs tool envelope: recado default, tool_request is text, wake-origin deny."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

from firefly_bridge.channel import ChannelConfig, run_channel_turn
from firefly_bridge.config import BridgeConfig, load_config
from firefly_bridge.daemon import AcpSession, Daemon
from firefly_bridge.permissions import PermissionPolicy
from firefly_bridge.queue import Turn
from firefly_bridge.wake_envelope import (
    KIND_RECADO,
    KIND_TOOL_REQUEST,
    WAKE_ORIGIN_DENY_REASON,
    body_marks_wake_origin,
    count_wake_origin_denied,
    parse_wake_envelope,
    pending_card_from_request,
    wake_origin_permission_decision,
    wake_origin_permission_result,
    write_pending_card,
)

ROOT = Path(__file__).resolve().parents[1]


def _perm_request(*, option_reject="no", option_allow="yes", kind="execute", path=None):
    options = []
    if option_allow:
        options.append({"kind": "allow_once", "optionId": option_allow})
    if option_reject:
        options.append({"kind": "reject_once", "optionId": option_reject})
    tool = {"kind": kind, "title": "synthetic"}
    if path:
        tool["rawInput"] = {"path": path}
    else:
        tool["rawInput"] = {"command": "echo synthetic"}
    return {
        "jsonrpc": "2.0",
        "id": "perm-wake-1",
        "method": "session/request_permission",
        "params": {"toolCall": tool, "options": options},
    }


def _write_perm_mock(tmp_dir: Path, session_id: str) -> Path:
    script = tmp_dir / "mock_leader_perm.py"
    script.write_text(
        f"""\
import json, sys
SID = {session_id!r}
PROMPT_ID = "mock-perm-0001"

def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\\n")
    sys.stdout.flush()

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    msg = json.loads(raw)
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{"protocolVersion": 1, "capabilities": {{}}}}}})
    elif method == "session/load":
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{"_meta": {{"sessionId": SID}}}}}})
    elif method == "session/prompt":
        text = msg["params"]["prompt"][0]["text"]
        emit({{"jsonrpc": "2.0", "method": "_x.ai/queue/changed", "params": {{
            "sessionId": SID, "entries": [], "runningPromptId": PROMPT_ID,
            "runningText": text, "runningKind": "prompt",
        }}}})
        emit({{"jsonrpc": "2.0", "id": "perm-wake-1", "method": "session/request_permission",
              "params": {{
                  "sessionId": SID,
                  "toolCall": {{"kind": "execute", "title": "synthetic",
                                "rawInput": {{"command": "echo synthetic"}}}},
                  "options": [
                      {{"kind": "allow_once", "optionId": "yes"}},
                      {{"kind": "reject_once", "optionId": "no"}},
                  ],
              }}}})
        for raw_in in sys.stdin:
            raw_in = raw_in.strip()
            if not raw_in:
                continue
            ans = json.loads(raw_in)
            if ans.get("id") == "perm-wake-1":
                open({str(tmp_dir / "perm_answer.json")!r}, "w").write(json.dumps(ans))
                break
        emit({{"jsonrpc": "2.0", "method": "session/update", "params": {{
            "sessionId": SID,
            "_meta": {{"promptId": PROMPT_ID, "chunkId": 1}},
            "update": {{"sessionUpdate": "agent_message_chunk",
                        "content": {{"type": "text", "text": "Mock peerb: recado only"}}}},
        }}}})
        emit({{"jsonrpc": "2.0", "method": "_x.ai/session/update", "params": {{
            "sessionId": SID,
            "update": {{"sessionUpdate": "turn_completed", "prompt_id": PROMPT_ID,
                        "stop_reason": "end_turn"}},
        }}}})
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{
            "stopReason": "end_turn",
            "_meta": {{"sessionId": SID, "promptId": PROMPT_ID}},
        }}}})
        break
""",
        encoding="utf-8",
    )
    return script


class ParseEnvelopeTests(unittest.TestCase):
    def test_plain_text_defaults_to_recado(self) -> None:
        env = parse_wake_envelope("Oi peerb, só um recado.")
        self.assertEqual(env.kind, KIND_RECADO)
        self.assertTrue(env.is_recado)
        self.assertFalse(env.is_tool_request)
        self.assertFalse(env.auto_answer_permission)

    def test_empty_and_none_are_recado(self) -> None:
        self.assertEqual(parse_wake_envelope("").kind, KIND_RECADO)
        self.assertEqual(parse_wake_envelope(None).kind, KIND_RECADO)

    def test_kind_recado_header(self) -> None:
        env = parse_wake_envelope("kind: recado\nfrom: agent-a\n\nhello peerb\n")
        self.assertEqual(env.kind, KIND_RECADO)
        self.assertEqual(env.meta.get("from"), "agent-a")
        self.assertIn("hello peerb", env.text)

    def test_kind_tool_request_is_text_not_approval(self) -> None:
        env = parse_wake_envelope(
            "kind: tool_request\ntool: read_file\n\nplease read note.md\n"
        )
        self.assertEqual(env.kind, KIND_TOOL_REQUEST)
        self.assertTrue(env.is_tool_request)
        self.assertFalse(env.auto_answer_permission)
        self.assertIn("please read note.md", env.text)

    def test_json_envelope(self) -> None:
        env = parse_wake_envelope('{"kind": "tool_request", "text": "leia X", "from": "agent-c"}')
        self.assertEqual(env.kind, KIND_TOOL_REQUEST)
        self.assertEqual(env.text, "leia X")
        self.assertEqual(env.meta.get("from"), "agent-c")
        self.assertFalse(env.auto_answer_permission)

    def test_canal_wrap_without_kind_is_recado(self) -> None:
        env = parse_wake_envelope("para: peerb\n\noi do canal\n\n— agent-a\n")
        self.assertEqual(env.kind, KIND_RECADO)
        self.assertIn("oi do canal", env.text)

    def test_canal_wrap_with_tool_request(self) -> None:
        env = parse_wake_envelope(
            "para: peerb\n\nkind: tool_request\nfrom: agent-c\n\npede um read\n\n— agent-c\n"
        )
        self.assertEqual(env.kind, KIND_TOOL_REQUEST)
        self.assertEqual(env.meta.get("from"), "agent-c")
        self.assertFalse(env.auto_answer_permission)

    def test_unknown_kind_fails_closed_to_recado(self) -> None:
        env = parse_wake_envelope("kind: channel\n\nnot a grant\n")
        self.assertEqual(env.kind, KIND_RECADO)
        self.assertEqual(env.meta.get("unknown_kind"), "channel")

    def test_word_channel_in_body_is_not_tool_approval(self) -> None:
        env = parse_wake_envelope("fala telepaticamente com a peerb e usa a tool")
        self.assertEqual(env.kind, KIND_RECADO)
        self.assertFalse(env.auto_answer_permission)


class WakeOriginDenyTests(unittest.TestCase):
    def test_wake_origin_selects_reject_never_allow(self) -> None:
        req = _perm_request()
        decision = wake_origin_permission_decision(req)
        self.assertEqual(decision.action, "deny")
        self.assertEqual(decision.reason, WAKE_ORIGIN_DENY_REASON)
        self.assertEqual(decision.option_id, "no")
        result = wake_origin_permission_result(req)
        self.assertEqual(result["outcome"]["outcome"], "selected")
        self.assertEqual(result["outcome"]["optionId"], "no")

    def test_missing_reject_cancels_instead_of_silent_allow(self) -> None:
        req = _perm_request(option_reject=None, option_allow="yes")
        result = wake_origin_permission_result(req)
        self.assertEqual(result["outcome"]["outcome"], "cancelled")
        self.assertNotIn("optionId", result["outcome"])

    def test_tool_request_envelope_still_denies(self) -> None:
        env = parse_wake_envelope("kind: tool_request\n\nroda a tool\n")
        req = _perm_request()
        card = pending_card_from_request(req, envelope=env, message_id="id_x", sender="agent-a")
        self.assertEqual(card["status"], "denied")
        self.assertEqual(card["reason"], WAKE_ORIGIN_DENY_REASON)
        self.assertEqual(card["envelope_kind"], KIND_TOOL_REQUEST)
        self.assertEqual(card["action"], "deny")

    def test_pending_card_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pending_card.json"
            card = pending_card_from_request(
                _perm_request(),
                envelope=parse_wake_envelope("kind: recado\n\nhi\n"),
                message_id="id_card",
                sender="agent-a",
            )
            written = write_pending_card(path, card)
            loaded = json.loads(written.read_text(encoding="utf-8"))
            self.assertEqual(loaded["reason"], WAKE_ORIGIN_DENY_REASON)
            self.assertEqual(loaded["status"], "denied")
            leftovers = [p for p in Path(tmp).iterdir() if p.suffix == ".tmp"]
            self.assertEqual(leftovers, [])


class PeerbAdapterDefaultTests(unittest.TestCase):
    def test_peerb_channel_default_is_pending_not_allow_all(self) -> None:
        cfg = ChannelConfig()
        self.assertEqual(cfg.permission_mode, "pending")
        self.assertIs(cfg.answer_permissions, False)
        resolved = cfg.resolved()
        self.assertEqual(resolved.permission_mode, "pending")
        self.assertIs(resolved.answer_permissions, False)

    def test_deployment_example_stays_pending(self) -> None:
        deployment = (ROOT / "config" / "example.toml").read_text(encoding="utf-8")
        self.assertIn('agent_a_permission_mode = "pending"', deployment)
        self.assertIn('agent_b_permission_mode = "pending"', deployment)
        self.assertIn('agent_c_permission_mode = "pending"', deployment)
        self.assertNotIn('= "allow_all_own_turns"', deployment)
        cfg = load_config(ROOT / "config" / "example.toml", env={})
        self.assertFalse(cfg.live_send)
        self.assertEqual(cfg.agent_a_permission_mode, "pending")
        self.assertEqual(cfg.agent_b_permission_mode, "pending")
        self.assertEqual(cfg.agent_c_permission_mode, "pending")
        public = load_config(ROOT / "examples" / "config.example.toml", env={})
        self.assertEqual(public.agent_a_permission_mode, "pending")
        self.assertEqual(public.agent_b_permission_mode, "pending")
        self.assertEqual(public.agent_c_permission_mode, "pending")

    def test_dry_run_recado_default_and_tool_request_do_not_auto_answer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = ChannelConfig(
                socket_path=str(Path(tmp) / "missing.sock"),
                session_id="sess-example-0001",
                ledger_path=str(Path(tmp) / "ledger.json"),
                wake_dir=str(Path(tmp) / "wake-notes"),
                pending_card_path=str(Path(tmp) / "pending_card.json"),
            )
            recado = run_channel_turn(cfg, "Oi peerb", dry_run=True)
            self.assertEqual(recado["envelope_kind"], KIND_RECADO)
            self.assertFalse(recado["envelope_auto_answer_permission"])
            self.assertEqual(recado["permission_mode"], "pending")
            tool = run_channel_turn(
                cfg, "kind: tool_request\n\npede um read\n", dry_run=True
            )
            self.assertEqual(tool["envelope_kind"], KIND_TOOL_REQUEST)
            self.assertFalse(tool["envelope_auto_answer_permission"])


class WakeTurnAcpDenyTests(unittest.TestCase):
    def test_wake_turn_denies_even_if_answer_permissions_and_allow_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mock = _write_perm_mock(tmp_path, "sess-example-0001")
            cfg = ChannelConfig(
                socket_path=str(tmp_path / "unused.sock"),
                session_id="sess-example-0001",
                session_cwd=str(tmp_path),
                ledger_path=str(tmp_path / "ledger.json"),
                wake_dir=str(tmp_path / "wake-notes"),
                pending_card_path=str(tmp_path / "pending_card.json"),
                hold_pid_file=str(tmp_path / "missing.pid"),
                answer_permissions=True,
                permission_mode="allow_all_own_turns",
                use_daemon_ipc=False,
                turn_timeout_s=5.0,
                connect_timeout_s=2.0,
                load_timeout_s=2.0,
            )
            res = run_channel_turn(
                cfg,
                "kind: tool_request\n\npede a tool\n",
                message_id="id_wakeperm0001",
                spawn_cmd=[sys.executable, str(mock)],
                write_wake=False,
            )
            self.assertEqual(res["envelope_kind"], KIND_TOOL_REQUEST)
            self.assertGreaterEqual(res["perm_seen_n"], 1)
            self.assertGreaterEqual(res["wake_origin_denied_n"], 1)
            self.assertEqual(res["approvals_n"], 0)
            self.assertFalse(res.get("envelope_auto_answer_permission"))
            answer = json.loads((tmp_path / "perm_answer.json").read_text(encoding="utf-8"))
            outcome = answer["result"]["outcome"]
            self.assertEqual(outcome["outcome"], "selected")
            self.assertEqual(outcome["optionId"], "no")
            self.assertNotEqual(outcome.get("optionId"), "yes")
            card = json.loads((tmp_path / "pending_card.json").read_text(encoding="utf-8"))
            self.assertEqual(card["reason"], WAKE_ORIGIN_DENY_REASON)
            self.assertEqual(card["status"], "denied")

    def test_recado_wake_also_denies_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mock = _write_perm_mock(tmp_path, "sess-example-0001")
            cfg = ChannelConfig(
                socket_path=str(tmp_path / "unused.sock"),
                session_id="sess-example-0001",
                session_cwd=str(tmp_path),
                ledger_path=str(tmp_path / "ledger.json"),
                wake_dir=str(tmp_path / "wake-notes"),
                pending_card_path=str(tmp_path / "pending_card.json"),
                hold_pid_file=str(tmp_path / "missing.pid"),
                answer_permissions=False,
                permission_mode="pending",
                use_daemon_ipc=False,
                turn_timeout_s=5.0,
                connect_timeout_s=2.0,
                load_timeout_s=2.0,
            )
            res = run_channel_turn(
                cfg,
                "só um recado",
                message_id="id_wakerecado01",
                spawn_cmd=[sys.executable, str(mock)],
                write_wake=False,
            )
            self.assertEqual(res["envelope_kind"], KIND_RECADO)
            self.assertGreaterEqual(res["wake_origin_denied_n"], 1)
            answer = json.loads((tmp_path / "perm_answer.json").read_text(encoding="utf-8"))
            self.assertEqual(answer["result"]["outcome"]["optionId"], "no")


class WakeOriginHelpersTests(unittest.TestCase):
    def test_body_marks_wake_origin(self) -> None:
        self.assertTrue(body_marks_wake_origin("[channel-wake cid=1 sha=abc] oi"))
        self.assertTrue(body_marks_wake_origin("  [channel-wake] hello"))
        self.assertFalse(body_marks_wake_origin("Oi peerb"))
        self.assertFalse(body_marks_wake_origin("kind: recado\n\nhi\n"))

    def test_count_wake_origin_denied_prefers_response_sent(self) -> None:
        events = [
            {"reason": WAKE_ORIGIN_DENY_REASON, "phase": "decision_intent", "action": "deny"},
            {"reason": WAKE_ORIGIN_DENY_REASON, "phase": "response_sent", "action": "deny"},
        ]
        self.assertEqual(count_wake_origin_denied(events), 1)
        self.assertEqual(
            count_wake_origin_denied(
                [{"reason": WAKE_ORIGIN_DENY_REASON, "action": "deny"}]
            ),
            1,
        )
        self.assertEqual(count_wake_origin_denied([]), 0)


class _PermCapture:
    def __init__(self) -> None:
        self.responses: list = []

    def respond(self, rid, result) -> None:
        self.responses.append((rid, result))


def _wake_session(tmp: Path, *, wake_origin: bool, allow_all: bool = True) -> AcpSession:
    cfg = BridgeConfig(
        session_id="sess-example-0001",
        live_send=True,
        state_dir=str(tmp),
        agent_a_permission_mode="allow_all_own_turns" if allow_all else "pending",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = AcpSession(
            cfg,
            policy=PermissionPolicy(mode="allow_all" if allow_all else "pending"),
        )
    s.conn = _PermCapture()
    s.loaded_session_id = cfg.session_id
    s.incarnation = "test-incarnation"
    s.turn_attestation_supported = True
    s._own_turn = Turn(
        "message-1",
        cfg.session_id,
        "kind: tool_request\n\npede a tool\n",
        "agent-a: kind: tool_request\n\npede a tool\n",
        0,
        wake_origin=wake_origin,
    )
    s._origin = {
        "turnId": "turn-1",
        "nonce": "synthetic-nonce",
        "initiator": "firefly-bridge",
        "messageId": "message-1",
        "sender": "agent-a",
        "incarnation": s.incarnation,
    }
    s.authority_allowed = lambda turn: True
    s.authority_respond = lambda turn, rid, result: s.conn.respond(rid, result) or True
    s.auto_allowed = lambda sender: True
    s.permission_claim = lambda tid, rid: True
    s.record_permission = lambda record: None
    s._own_turn.turn_id = "turn-1"
    s.approval_receipts_path = tmp / "synthetic-approval.jsonl"
    s._on_notification(
        {
            "method": "session/update",
            "params": {
                "sessionId": s.cfg.session_id,
                "_meta": {"agentBridge": dict(s._origin)},
                "update": {"sessionUpdate": "turn_started"},
            },
        }
    )
    return s


def _owned_perm(s: AcpSession, **kwargs):
    req = _perm_request(**kwargs)
    params = req.setdefault("params", {})
    params["sessionId"] = s.cfg.session_id
    params["_meta"] = {"agentBridge": dict(s._origin)}
    return req


class DaemonWakeOriginDenyTests(unittest.TestCase):
    def test_agent_sender_wake_is_denied_even_when_auto_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s = _wake_session(Path(tmp), wake_origin=True, allow_all=True)
            s._on_request(_owned_perm(s))
            self.assertEqual(len(s.conn.responses), 1)
            rid, result = s.conn.responses[0]
            self.assertEqual(rid, "perm-wake-1")
            self.assertEqual(result["outcome"]["outcome"], "selected")
            self.assertEqual(result["outcome"]["optionId"], "no")
            self.assertNotEqual(result["outcome"].get("optionId"), "yes")
            self.assertEqual(s._own_turn.pending_card["reason"], WAKE_ORIGIN_DENY_REASON)
            card = json.loads((Path(tmp) / "pending_card.json").read_text(encoding="utf-8"))
            self.assertEqual(card["status"], "denied")
            events = s._own_turn.permission_events
            self.assertGreaterEqual(count_wake_origin_denied(events), 1)
            self.assertTrue(any(e.get("action") == "deny" for e in events))
            self.assertFalse(any(e.get("action") == "approve" for e in events))

    def test_wake_origin_missing_reject_cancels_not_silent_allow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            s = _wake_session(Path(tmp), wake_origin=True, allow_all=True)
            s._on_request(_owned_perm(s, option_reject=None, option_allow="yes"))
            self.assertEqual(len(s.conn.responses), 1)
            self.assertEqual(s.conn.responses[0][1]["outcome"]["outcome"], "cancelled")
            self.assertNotIn("optionId", s.conn.responses[0][1]["outcome"])

    def test_non_wake_agent_turn_still_auto_allows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            s = _wake_session(tmp_path, wake_origin=False, allow_all=True)
            s._on_request(_owned_perm(s, kind="edit", path="shared/note.md"))
            self.assertEqual(len(s.conn.responses), 1)
            self.assertEqual(s.conn.responses[0][1]["outcome"]["optionId"], "yes")

    def test_enqueue_wake_origin_flag_and_channel_mark(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cfg = BridgeConfig(
                socket_path=str(tmp_path / "leader.sock"),
                session_id="sess-example-0001",
                live_send=True,
                state_dir=str(tmp_path / "state"),
                sender_interval_s=0,
                global_interval_s=0,
                pacing_minimums_enabled=False,
                post_turn_interval_s=0,
                target_interval_s=0,
                per_sender_daily_quota=100,
                per_sender_pending=8,
                max_outbox=8,
            )
            d = Daemon(cfg)
            d.control("human", "opt_in")
            d.control("recipient", "opt_in")
            try:
                flagged = d.enqueue("w-flag", "plain recado", sender="agent-a", wake_origin=True)
                self.assertEqual(flagged["queue_state"], "queued")
                marked = d.enqueue(
                    "w-mark",
                    "[channel-wake cid=9 sha=abc] oi",
                    sender="agent-a",
                )
                self.assertEqual(marked["queue_state"], "queued")
                local = d.enqueue("w-local", "peer tool turn", sender="agent-a")
                self.assertEqual(local["queue_state"], "queued")
                by_id = {t.message_id: t for t in d.outbox._all()}
                self.assertTrue(by_id["w-flag"].wake_origin)
                self.assertTrue(by_id["w-mark"].wake_origin)
                self.assertFalse(by_id["w-local"].wake_origin)
                ipc = d.handle_ipc(
                    "agent-a",
                    "enqueue",
                    {"message_id": "w-ipc", "body": "via ipc", "wake_origin": True},
                )
                self.assertEqual(ipc["queue_state"], "queued")
                self.assertTrue(next(t for t in d.outbox._all() if t.message_id == "w-ipc").wake_origin)
            finally:
                d.close()


class DeploymentFileRegressionTests(unittest.TestCase):
    def test_no_allow_all_on_peerb_profile_in_source(self) -> None:
        tel = (ROOT / "firefly_bridge" / "channel.py").read_text(encoding="utf-8")
        self.assertIn('permission_mode: str = "pending"', tel)
        self.assertNotIn('permission_mode: str = "allow_all_own_turns"', tel)
        # Deployment example is the only compiled trio of allow_all lines.
        others = list((ROOT / "examples").glob("*.toml")) + list((ROOT / "config").glob("*.toml"))
        allow_files = []
        for path in others:
            text = path.read_text(encoding="utf-8")
            if "agent_a_permission_mode = \"allow_all_own_turns\"" in text:
                allow_files.append(path.name)
        self.assertEqual(allow_files, [])
