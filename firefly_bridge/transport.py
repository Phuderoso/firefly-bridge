"""In-process test double and the disabled live transport.

The mock speaks a tiny scripted subset so tests can show correlation and
fail-closed policy. It is not Grok and it does not prove live queue behavior.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from firefly_bridge.bridge import TransportCrash, TransportTimeout
from firefly_bridge.messages import FORBIDDEN_CLIENT_METHODS


@dataclass
class ExchangeResult:
    malformed: bool = False
    mock_accepted: bool = False
    error: dict | None = None
    result_id: str | None = None
    stop_reason: str | None = None
    assistant_text: str = ""
    permission: dict | None = None
    raw: str = ""


@dataclass
class MockTransport:
    """busy_precondition: True busy, False idle test-double, None unknowable."""

    name: str = "mock"
    enabled: bool = True
    pinned_session_id: str = "sess-example-0001"
    script: str = "ok"
    busy_precondition: bool | None = False
    written: list = field(default_factory=list)
    methods: list = field(default_factory=list)
    tools_executed: list = field(default_factory=list)
    always_approve: bool = False
    privileges_changed: bool = False
    loaded_history: bool = False
    created_session: bool = False
    permission_responses: list = field(default_factory=list)

    def exchange(self, frame: dict, timeout_s: float, on_server_request) -> ExchangeResult:
        if timeout_s <= 0:
            raise TransportTimeout("non_positive_timeout")
        raw = json.dumps(frame, separators=(",", ":"))
        self.written.append(raw)
        method = frame.get("method")
        self.methods.append(method)
        if method in FORBIDDEN_CLIENT_METHODS:
            self._reject_forbidden(method)
            return ExchangeResult(
                error={
                    "code": -32601,
                    "message": "forbidden method refused by mock",
                    "data": {"agentMock": "forbidden"},
                },
                result_id=frame.get("id") if isinstance(frame.get("id"), str) else None,
            )
        if self.script == "crash":
            raise TransportCrash("mock closed after write")
        if self.script == "timeout":
            raise TransportTimeout("mock silent until deadline")
        if self.script == "malformed":
            return ExchangeResult(malformed=True, raw="not-json{")
        if method != "session/prompt":
            return ExchangeResult(
                error={"code": -32601, "message": "method not implemented by mock"},
                result_id=frame.get("id") if isinstance(frame.get("id"), str) else None,
            )

        params = frame.get("params") if isinstance(frame.get("params"), dict) else {}
        session_id = params.get("sessionId")
        rpc_id = frame.get("id") if isinstance(frame.get("id"), str) else None
        if session_id != self.pinned_session_id or self.script == "wrong-session":
            return ExchangeResult(
                error={
                    "code": -32602,
                    "message": "mock session mismatch",
                    "data": {"agentMock": "session_rejected"},
                },
                result_id=rpc_id,
            )
        if self.script == "mismatch":
            return ExchangeResult(
                mock_accepted=True,
                result_id="id_not_the_request",
                stop_reason="end_turn",
                assistant_text="uncorrelated",
            )
        if self.script == "busy-after-write":
            return ExchangeResult(
                error={
                    "code": -32000,
                    "message": "agent.mock busy",
                    "data": {"agentMock": "busy"},
                },
                result_id=rpc_id,
            )

        permission = None
        if self.script == "permission":
            permission = self._permission_round(on_server_request, session_id)
        elif self.script == "permission-allow-only":
            permission = self._permission_round(
                on_server_request,
                session_id,
                options=[{"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"}],
            )

        text = "mock reply correlated"
        return ExchangeResult(
            mock_accepted=True,
            result_id=rpc_id,
            stop_reason="end_turn",
            assistant_text=text,
            permission=permission,
        )

    def _reject_forbidden(self, method: str) -> None:
        if method == "session/new":
            self.created_session = False
        if method == "session/load":
            self.loaded_history = False

    def _permission_round(self, on_server_request, session_id: str, options=None) -> dict:
        if options is None:
            options = [
                {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
                {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
                {"optionId": "reject-always", "name": "Reject always", "kind": "reject_always"},
            ]
        request = {
            "jsonrpc": "2.0",
            "id": "perm-1",
            "method": "session/request_permission",
            "params": {
                "sessionId": session_id,
                "toolCall": {"toolCallId": "call_001"},
                "options": options,
            },
        }
        response = on_server_request(request)
        if response is None:
            # Deferred to human TUI — bridge wrote nothing.
            self.permission_responses.append({"_agent_permission_how": "deferred_to_human_tui"})
            return {
                "how": "deferred_to_human_tui",
                "outcome": None,
                "tools_executed": list(self.tools_executed),
                "privileges_changed": False,
                "always_approve": self.always_approve,
                "bridge_wrote_permission_result": False,
            }
        stored = {k: v for k, v in response.items() if k != "_agent_permission_how"}
        self.permission_responses.append(response)
        outcome = (stored.get("result") or {}).get("outcome") or {}
        selected = outcome.get("optionId")
        kind = None
        for opt in options:
            if opt.get("optionId") == selected:
                kind = opt.get("kind")
        granted = kind in {"allow_once", "allow_always"}
        if granted:
            self.tools_executed.append("call_001")
            self.privileges_changed = True
        how = response.get("_agent_permission_how")
        return {
            "how": how,
            "outcome": outcome,
            "tools_executed": list(self.tools_executed),
            "privileges_changed": self.privileges_changed,
            "always_approve": self.always_approve,
            "bridge_wrote_permission_result": True,
        }


class DisabledLiveTransport:
    name = "live"
    enabled = False
    busy_precondition = None

    def __init__(self) -> None:
        self.calls = 0

    def exchange(self, frame, timeout_s, on_server_request):
        self.calls += 1
        raise RuntimeError("live exchange must not be called")
