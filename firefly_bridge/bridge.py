"""Send policy (Generation 1 offline/mock prototype, deprecated for live use).

For live and unified broker operations, use :class:`firefly_bridge.daemon.Daemon`
(with ``adapter_mode="stock_grok"`` or ``"attested"``) and the ``channel`` CLI.
One attempt. No session creation. No automatic resend.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from firefly_bridge.acp import defer_permission, outbound_user_text, session_prompt
from firefly_bridge.ledger import Ledger
from firefly_bridge.messages import (
    AlreadySettled,
    DuplicateMessage,
    Receipt,
    new_message_id,
    utc_now,
    validate_session_id,
    validate_source,
    validate_text,
)


class TransportTimeout(Exception):
    pass


class TransportCrash(Exception):
    pass


class LiveTransportDisabled(Exception):
    pass


class Bridge:
    def __init__(
        self, transport, timeout_s: float = 2.0, ledger_path: str | Path | None = None
    ) -> None:
        if timeout_s <= 0 or timeout_s > 30:
            raise ValueError("timeout_out_of_bounds")
        self.transport = transport
        self.timeout_s = float(timeout_s)
        if ledger_path is None:
            ledger_path = os.environ.get("AGENT_LEDGER") or ".agent/receipts.json"
        self.ledger = Ledger(Path(ledger_path))

    def prepare(
        self,
        session_id: str,
        text: str,
        *,
        message_id: str | None = None,
        source: str = "agent-a",
    ) -> Receipt:
        pinned = validate_session_id(session_id)
        body = validate_text(text)
        who = validate_source(source)
        mid = message_id or new_message_id()
        if not isinstance(mid, str) or not mid.startswith("id_") or len(mid) < 12:
            raise DuplicateMessage("message_id_invalid")
        receipt = Receipt(
            message_id=mid,
            session_id=pinned,
            source=who,
            text=body,
            outcome="prepared",
            history=["prepared"],
            transport=getattr(self.transport, "name", "unknown"),
            timeout_s=self.timeout_s,
            outbound_text=outbound_user_text(body),
            attribution_channel="outbound-user-content",
            notes=[
                "agent-a attribution is the 'agent-a: ' prefix in the user text block.",
                "No ACP speaker field is sent.",
                "Prepared does not mean a transport write.",
                utc_now(),
            ],
        )
        return self.ledger.prepare(receipt)

    def send(self, receipt: Receipt) -> Receipt:
        if self._already_settled(receipt):
            raise AlreadySettled("no_automatic_resend")
        if not getattr(self.transport, "enabled", False):
            self._block(
                receipt,
                "live_transport_disabled",
                "Live transport stays disabled. Non-interruption, composer "
                "preservation, and live attachment are not in the retrieved contract.",
            )
            receipt.notes.append("no bytes written")
            return receipt

        busy = getattr(self.transport, "busy_precondition", None)
        if busy is None:
            self._block(
                receipt,
                "busy_unknowable_fail_closed",
                "No documented busy query. Refusing before write rather than "
                "inventing an idle flag.",
            )
            return receipt
        if busy is True:
            self._block(
                receipt,
                "busy_fail_closed",
                "Mock precondition says busy. No session/prompt and no session/cancel.",
            )
            return receipt

        if not self.ledger.claim_attempt(receipt):
            raise AlreadySettled("no_automatic_resend")
        frame = session_prompt(receipt.session_id, receipt.outbound_text, receipt.message_id)
        try:
            result = self._exchange_bounded(frame)
        except TransportTimeout:
            receipt.transition("unknown")
            receipt.block_code = "timeout_no_resend"
            receipt.block_detail = "No correlated terminal result before the deadline."
            self.ledger.store(receipt)
            return receipt
        except TransportCrash:
            receipt.transition("unknown")
            receipt.block_code = "crash_no_resend"
            receipt.block_detail = "Transport closed after the request was written."
            self.ledger.store(receipt)
            return receipt

        self._apply_result(receipt, result)
        self.ledger.store(receipt)
        return receipt

    def _already_settled(self, receipt: Receipt) -> bool:
        stored = self.ledger.get(receipt.message_id)
        if stored is None:
            raise AlreadySettled("unknown_receipt")
        return bool(stored.attempt_committed or stored.outcome != "prepared" or stored.block_code)

    def _block(self, receipt: Receipt, code: str, detail: str) -> None:
        if not self.ledger.block_before_attempt(receipt, code, detail):
            raise AlreadySettled("no_automatic_resend")

    def _exchange_bounded(self, frame: dict):
        box: dict = {}

        def run() -> None:
            try:
                box["result"] = self.transport.exchange(
                    frame,
                    self.timeout_s,
                    on_server_request=self._on_server_request,
                )
            except Exception as exc:
                box["error"] = exc

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(self.timeout_s)
        if thread.is_alive():
            # The write may have happened. Do not cancel the peer turn.
            raise TransportTimeout("deadline")
        if "error" in box:
            raise box["error"]
        return box["result"]

    def _on_server_request(self, request: dict):
        if request.get("method") == "session/request_permission":
            # Shared-leader: do not answer; human TUI decides (first-writer-wins).
            return defer_permission(request)
        # Do not answer unknown server methods with approval.
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "error": {"code": -32601, "message": "agent client refuses this request"},
        }

    def _apply_result(self, receipt: Receipt, result) -> None:
        receipt.permission = getattr(result, "permission", None)
        if getattr(result, "malformed", False):
            receipt.transition("unknown")
            receipt.block_code = "malformed_rpc_no_resend"
            receipt.block_detail = "Bytes after the write were not a JSON-RPC object."
            return

        if getattr(result, "mock_accepted", False):
            receipt.transition("transport-accepted")
            receipt.correlation["mock_acceptance"] = True
            receipt.correlation["acp_acceptance_ack_documented"] = False

        error = getattr(result, "error", None)
        if error:
            data = error.get("data") if isinstance(error, dict) else None
            mock = data.get("agentMock") if isinstance(data, dict) else None
            if receipt.outcome == "transport-accepted":
                receipt.transition("unknown")
                receipt.block_code = "error_after_ack_no_resend"
                receipt.block_detail = "Ack then error is ambiguous. Not resent."
                return
            if mock == "session_rejected":
                receipt.transition("prepared")
                receipt.block_code = "session_rejected"
                receipt.block_detail = "Pinned session was refused. session/new was not sent."
                receipt.notes.append(
                    "The request was written and refused. Outcome returns to prepared. "
                    "attempt_committed blocks another exchange."
                )
                return
            if mock == "busy":
                receipt.transition("unknown")
                receipt.block_code = "busy_after_write_unknown"
                receipt.block_detail = (
                    "Busy arrived only after a write. Not cancelled and not resent."
                )
                return
            receipt.transition("unknown")
            receipt.block_code = "rpc_error_no_resend"
            receipt.block_detail = "Correlated error without a documented acceptance ack."
            return

        response_id = getattr(result, "result_id", None)
        if response_id != receipt.message_id:
            if receipt.outcome == "transport-accepted":
                receipt.transition("unknown")
            else:
                receipt.transition("unknown")
            receipt.block_code = "correlation_mismatch_no_resend"
            receipt.correlation["result_id"] = response_id
            receipt.correlation["ids_match"] = False
            return

        receipt.correlation.update(
            {
                "jsonrpc_id": receipt.message_id,
                "result_id": response_id,
                "ids_match": True,
                "stop_reason": getattr(result, "stop_reason", None),
                "assistant_text": getattr(result, "assistant_text", ""),
                "acp_acceptance_ack_documented": False,
                "mock_acceptance": bool(getattr(result, "mock_accepted", False)),
            }
        )
        if receipt.outcome != "transport-accepted":
            receipt.notes.append(
                "Final session/prompt result is completion metadata, not a separate acceptance ack."
            )
        receipt.block_code = None
        receipt.block_detail = None
        receipt.transition("responded")
