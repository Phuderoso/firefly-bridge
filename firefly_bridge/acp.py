"""ACP frames this client is allowed to build.

Shapes follow the public Agent Client Protocol pages retrieved 2026-11-08
and the Grok docs that name session/prompt. No extension methods are invented.
"""

from __future__ import annotations

from firefly_bridge.messages import ALLOWED_CLIENT_METHODS, FORBIDDEN_CLIENT_METHODS


class ForbiddenMethod(RuntimeError):
    pass


# Attribution is ordinary user text. ACP session/prompt has no speaker field.
OUTBOUND_ATTRIBUTION = "agent-a: "


def outbound_user_text(text: str) -> str:
    return OUTBOUND_ATTRIBUTION + text


def session_prompt(session_id: str, text: str, rpc_id: str) -> dict:
    frame = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "session/prompt",
        "params": {
            "sessionId": session_id,
            "prompt": [{"type": "text", "text": text}],
        },
    }
    check_client_frame(frame)
    return frame


def check_client_frame(frame: dict) -> None:
    method = frame.get("method")
    if method in FORBIDDEN_CLIENT_METHODS or method not in ALLOWED_CLIENT_METHODS:
        raise ForbiddenMethod(str(method))
    params = frame.get("params") or {}
    if "cwd" in params or "mcpServers" in params or "_meta" in params:
        raise ForbiddenMethod("prompt_must_not_carry_session_setup_or_meta")


def defer_permission(request: dict) -> None:
    """Do not answer a permission that belongs to someone else's turn.

    Routing (observed on grok shared leader):
    - Turn started by THIS client: permission requests arrive HERE only.
      Rejecting cancels the turn; silence hangs it and blocks the queue.
      Use :class:`firefly_bridge.permissions.PermissionPolicy` instead of
      this helper for bridge-owned turns.
    - Turn started elsewhere (human TUI): requests may still be broadcast
      and the first answer wins. Returning None means the bridge writes no
      JSON-RPC result, so the TUI keeps the approval UI.

    This helper is the safe default for "not our turn". Returning None.
    """
    if request.get("method") != "session/request_permission":
        raise ForbiddenMethod("not_a_permission_request")
    return None


def deny_permission(request: dict) -> dict:
    """Explicit reject helper for tests / solo clients only — NOT for shared TUI.

    On a live shared leader with peerb's TUI, use defer_permission instead.
    ACP v1: select a reject_once option when one is offered. Otherwise return
    outcome cancelled, which the spec says must not proceed. allow_* is never
    selected. reject_always is not selected either: remembering a decision
    would change later prompts, and this bridge returns the session unchanged.
    """

    if request.get("method") != "session/request_permission":
        raise ForbiddenMethod("not_a_permission_request")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    options = params.get("options") if isinstance(params.get("options"), list) else []
    chosen = None
    for opt in options:
        if not isinstance(opt, dict):
            continue
        if opt.get("kind") == "reject_once" and isinstance(opt.get("optionId"), str):
            chosen = opt["optionId"]
            break
    if chosen is None:
        outcome: dict = {"outcome": "cancelled"}
        how = "cancelled_no_reject_once_option"
    else:
        outcome = {"outcome": "selected", "optionId": chosen}
        how = "reject_once"
    if outcome.get("outcome") == "selected":
        match = [o for o in options if isinstance(o, dict) and o.get("optionId") == chosen]
        kind = match[0].get("kind") if match else None
        if kind != "reject_once":
            raise ForbiddenMethod("refusing_non_reject_option")
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {"outcome": outcome},
        "_agent_permission_how": how,
    }
