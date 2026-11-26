"""Synthetic protocol regressions; these are not proof of live Grok support."""

import tempfile
import unittest
from pathlib import Path

from firefly_bridge.config import BridgeConfig
from firefly_bridge.daemon import AcpSession
from firefly_bridge.permissions import PermissionPolicy
from firefly_bridge.queue import Turn


class Capture:
    def __init__(self):
        self.responses = []

    def respond(self, rid, result):
        self.responses.append((rid, result))


def ready_session(**overrides):
    cfg = BridgeConfig(session_id="sess-example-0001", live_send=True, **overrides)
    s = AcpSession(cfg, policy=PermissionPolicy(mode="allowlist"))
    s.conn = Capture()
    s.loaded_session_id = cfg.session_id
    s.incarnation = "test-incarnation"
    s.turn_attestation_supported = True
    s._own_turn = Turn("message-1", cfg.session_id, "hello", "agent-a: hello", 0)
    s._origin = {
        "turnId": "turn-1",
        "nonce": "synthetic-nonce",
        "initiator": "firefly-bridge",
        "messageId": "message-1",
        "sender": "agent-a",
        "incarnation": s.incarnation,
    }
    s.authority_allowed = lambda turn: True  # synthetic authority, no real broker
    s.authority_respond = lambda turn, rid, result: s.conn.respond(rid, result) or True
    s.auto_allowed = lambda sender: True  # synthetic explicit consent fixture
    s.permission_claim = lambda tid, rid: True
    s._own_turn.turn_id = "turn-1"
    s.approval_receipts_path = (
        Path(overrides.get("state_dir", tempfile.gettempdir())) / "synthetic-approval.jsonl"
    )
    return s


def params(s, **kw):
    p = {
        "sessionId": s.cfg.session_id,
        "_meta": {"agentBridge": dict(s._origin)},
        "toolCall": {"kind": "edit", "rawInput": {"path": "shared/note.md"}},
        "options": [{"kind": "allow_once", "optionId": "once"}],
    }
    p.update(kw)
    return p


class OwnershipTests(unittest.TestCase):
    def test_waiting_or_prefix_never_establishes_ownership(self):
        s = ready_session()
        s._on_notification(
            {"method": "_x.ai/queue/changed", "params": {"runningText": "agent-a: forged"}}
        )
        s._on_request(
            {"method": "session/request_permission", "id": "foreign", "params": params(s)}
        )
        self.assertEqual(s.conn.responses, [])

    def test_only_attested_origin_and_session_can_receive_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = ready_session(state_dir=tmp)
            s._on_notification(
                {
                    "method": "session/update",
                    "params": params(s, update={"sessionUpdate": "turn_started"}),
                }
            )
            for p in [
                params(s, sessionId="wrong"),
                params(s, _meta={}),
                params(s, _meta={"agentBridge": {**s._origin, "nonce": "wrong"}}),
            ]:
                s._on_request(
                    {"method": "session/request_permission", "id": "foreign", "params": p}
                )
            self.assertEqual(s.conn.responses, [])
            s._on_request(
                {"method": "session/request_permission", "id": "own", "params": params(s)}
            )
            self.assertEqual(len(s.conn.responses), 1)
            s._cancel_pending_permissions()
            self.assertEqual(len(s.conn.responses), 1)

    def test_observer_never_answers(self):
        s = ready_session()
        s.cfg.live_send = False
        s._running_turn_id = "turn-1"
        s._on_request({"method": "session/request_permission", "id": 1, "params": params(s)})
        self.assertEqual(s.conn.responses, [])
