"""CLI. Prints JSON receipts. Live Grok contact requires an explicit config flag."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from firefly_bridge.bridge import Bridge
from firefly_bridge.messages import (
    AlreadySettled,
    AttributionError,
    ConflictingMessage,
    DuplicateMessage,
    EmptyText,
    SessionPinError,
)
from firefly_bridge.preflight import (
    PreflightRefused,
    contract_report,
    evaluate_observation,
    execute_readonly,
    mac_plan,
)
from firefly_bridge.transport import DisabledLiveTransport, MockTransport


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="firefly_bridge",
        description=(
            "Experimental ACP bridge: one agent messages another agent's live "
            "grok-tui session on the same machine. Live send is off by default."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    pre = sub.add_parser("preflight", help="Print the contract report (exit 2)")
    pre.add_argument("--fixture", help="Evaluate a synthetic observation JSON file")

    mac = sub.add_parser("mac-preflight", help="Read-only Mac plan / execute (exit 2)")
    mac.add_argument("--execute", action="store_true")
    mac.add_argument("--fixture", help="Evaluate an observation instead of running grok")

    send = sub.add_parser("send", help="Dry-run / mock send (live always refuses)")
    send.add_argument("--transport", choices=("mock", "live"), required=True)
    send.add_argument("--session-id", required=True)
    send.add_argument("--text", required=True)
    send.add_argument("--message-id", default=None)
    send.add_argument("--ledger", default=None)
    send.add_argument("--script", default="ok")
    send.add_argument("--timeout", type=float, default=2.0)
    send.add_argument("--mock-session", default="sess-example-0001")
    send.add_argument(
        "--busy",
        choices=("idle", "busy", "unknown"),
        default="idle",
        help="Mock precondition only. Not an ACP status field.",
    )

    prep = sub.add_parser("prepare", help="Write a prepared receipt without exchanging")
    prep.add_argument("--session-id", required=True)
    prep.add_argument("--text", required=True)
    prep.add_argument("--message-id", default=None)
    prep.add_argument("--ledger", default=None)

    sub.add_parser("write-samples", help="Regenerate samples/")

    # --- daemon / authenticity ----------------------------------------------
    cfg_parent = argparse.ArgumentParser(add_help=False)
    cfg_parent.add_argument(
        "--config",
        default=None,
        help="TOML config path (or $FIREFLY_BRIDGE_CONFIG)",
    )

    sub.add_parser(
        "daemon",
        parents=[cfg_parent],
        help="Attach to a leader socket and hold the session (see THREAT_MODEL.md)",
    )

    enq = sub.add_parser(
        "enqueue",
        parents=[cfg_parent],
        help="Enqueue one message for a running daemon (or a local Outbox dry-run)",
    )
    enq.add_argument("--text", required=True)
    enq.add_argument("--message-id", default=None)
    enq.add_argument(
        "--local",
        action="store_true",
        help="Dry-run: run one Outbox turn against a fake runner (no grok)",
    )

    can = sub.add_parser("cancel", parents=[cfg_parent], help="Cancel a queued / in-flight message")
    can.add_argument("--message-id", required=True)
    can.add_argument("--local", action="store_true")

    sub.add_parser("status", parents=[cfg_parent], help="Authenticated broker status")
    sub.add_parser(
        "doctor", parents=[cfg_parent], help="Read-only local diagnostics; never attaches"
    )
    rec = sub.add_parser("receipt", parents=[cfg_parent], help="Read own authenticated receipt")
    rec.add_argument("--message-id", required=True)
    ctl = sub.add_parser(
        "control", parents=[cfg_parent], help="Human/recipient authenticated channel control"
    )
    ctl.add_argument("--action", choices=("opt_in", "pause", "basta", "revoke"), required=True)
    ctl.add_argument(
        "--senders",
        nargs="+",
        default=None,
        help="Agent ids to opt in. Default: every agent in the config.",
    )

    key = sub.add_parser("keygen", help="Create a 0600 HMAC key file")
    key.add_argument("--path", required=True)
    key.add_argument("--overwrite", action="store_true")

    ver = sub.add_parser("verify", help="Verify a signed agent-a message")
    ver.add_argument("--key-file", required=True)
    ver.add_argument("--text", default=None, help="Message text; default reads stdin")
    ver.add_argument("--prefix", default="agent-a: ")
    ver.add_argument("--expected-sender", default=None)
    ver.add_argument("--expected-session", default=None)
    ver.add_argument("--max-age", type=float, default=3600)

    tel = sub.add_parser(
        "channel",
        parents=[cfg_parent],
        help="Send a agent-a message to peerb over the stock ACP leader (or --dry-run / --mock)",
    )
    tel.add_argument("--text", required=True, help="Message body (without 'agent-a: ' prefix)")
    tel.add_argument("--message-id", default=None)
    tel.add_argument("--session-id", default=None)
    tel.add_argument("--socket-path", default=None)
    tel.add_argument("--ledger", default=None)
    tel.add_argument("--wake-dir", dest="wake_dir", default=None)
    tel.add_argument("--timeout", type=float, default=600.0)
    tel.add_argument("--dry-run", action="store_true", help="Check gates/paths without contacting Grok")
    tel.add_argument("--mock", action="store_true", help="Run full ACP handshake + turn against a fake leader")
    tel.add_argument("--live", action="store_true", help="Explicitly authorize live ACP send to peerb")
    tel.add_argument(
        "--answer-permissions",
        action="store_true",
        help="Allow this client to answer permissions on own turn if hold is not running",
    )

    ww = sub.add_parser(
        "watch-wake",
        parents=[cfg_parent],
        help="Scan updates.jsonl and inbound/ for late peerb replies and write reply_* + WAKE.md",
    )
    ww.add_argument("--wake-dir", dest="wake_dir", default=None)
    ww.add_argument("--updates-jsonl", default=None)
    ww.add_argument("--session-cwd", default=None)
    ww.add_argument("--state-file", default=None)

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except (
        SessionPinError,
        AttributionError,
        EmptyText,
        DuplicateMessage,
        ConflictingMessage,
    ) as exc:
        _emit({"error": str(exc)})
        return 1
    except AlreadySettled as exc:
        _emit({"error": str(exc), "resend_attempted": False})
        return 1
    except PreflightRefused as exc:
        _emit({"error": str(exc), "live_send_allowed": False})
        return 2
    except (ValueError, OSError):
        _emit({"error": "configuration_or_local_operation_refused"})
        return 2


def _run(args) -> int:
    if args.cmd == "preflight":
        if args.fixture:
            report = evaluate_observation(_load(args.fixture))
        else:
            report = contract_report()
        _emit(report)
        _closed()
        return 2
    if args.cmd == "mac-preflight":
        if args.fixture:
            report = evaluate_observation(_load(args.fixture))
            _emit(report)
            _closed()
            return 2
        if not args.execute:
            report = {"plan": mac_plan(), "contract": contract_report()}
            _emit(report)
            _closed()
            return 2
        import os

        report = execute_readonly(
            pinned_session_id=os.environ.get("PINNED_SESSION_ID"),
            session_cwd=os.environ.get("AGENT_SESSION_CWD"),
            env_execute=os.environ.get("AGENT_PREFLIGHT_EXECUTE"),
        )
        _emit(report)
        _closed()
        return 2
    if args.cmd == "prepare":
        bridge = Bridge(DisabledLiveTransport(), timeout_s=2.0, ledger_path=_ledger(args))
        _emit(bridge.prepare(args.session_id, args.text, message_id=args.message_id).to_dict())
        return 0
    if args.cmd == "write-samples":
        from firefly_bridge.samples import write_samples

        paths = write_samples("samples")
        _emit({"wrote": paths, "live_send_allowed": False})
        return 0
    if args.cmd == "send":
        return _send(args)
    if args.cmd == "keygen":
        from firefly_bridge.envelope import generate_key_file

        path = generate_key_file(args.path, overwrite=args.overwrite)
        _emit({"path": str(path), "mode": "0600", "key_material_printed": False})
        return 0
    if args.cmd == "verify":
        from firefly_bridge.envelope import load_key, verify_text

        text = args.text if args.text is not None else sys.stdin.read()
        result = verify_text(
            load_key(args.key_file),
            text,
            prefix=args.prefix,
            expected_sender=args.expected_sender,
            expected_session_id=args.expected_session,
            max_age_s=args.max_age,
        )
        _emit(result.to_dict())
        return 0 if result.valid else 1
    if args.cmd == "daemon":
        from firefly_bridge.daemon import load_or_exit, run_daemon

        cfg = load_or_exit(args.config, require_target=True)
        return run_daemon(cfg)
    if args.cmd == "doctor":
        from firefly_bridge.daemon import load_or_exit
        from firefly_bridge.doctor import doctor

        _emit(doctor(load_or_exit(args.config, require_target=False)))
        return 0
    if args.cmd in {"status", "receipt", "control"}:
        from firefly_bridge.daemon import load_or_exit
        from firefly_bridge.ipc import ipc_call

        cfg = load_or_exit(args.config, require_target=True)
        op = args.action if args.cmd == "control" else args.cmd
        payload = (
            {"senders": args.senders}
            if args.cmd == "control"
            else ({"message_id": args.message_id} if args.cmd == "receipt" else {})
        )
        try:
            result = ipc_call(cfg, op, payload)
        except (ValueError, OSError):
            _emit({"error": "broker_unavailable_or_request_refused"})
            return 2
        _emit(result)
        return 1 if "error" in result else 0
    if args.cmd in {"enqueue", "cancel"}:
        return _queue_cmd(args)
    if args.cmd == "channel":
        return _channel_cmd(args)
    if args.cmd == "watch-wake":
        return _watch_wake_cmd(args)
    return 1


def _channel_cmd(args) -> int:
    import tempfile

    from firefly_bridge.channel import ChannelError, load_channel_config, run_channel_turn

    kw: dict = {"turn_timeout_s": args.timeout}
    if args.answer_permissions:
        kw["answer_permissions"] = True
    if args.session_id:
        kw["session_id"] = args.session_id
    if args.socket_path:
        kw["socket_path"] = args.socket_path
    if args.ledger:
        kw["ledger_path"] = args.ledger
    if args.wake_dir:
        kw["wake_dir"] = args.wake_dir

    cfg = load_channel_config(path=getattr(args, "config", None), overrides=kw)
    if args.dry_run:
        try:
            _emit(run_channel_turn(cfg, args.text, message_id=args.message_id, dry_run=True))
            return 0
        except (ChannelError, ValueError) as exc:
            _emit({"error": str(exc), "live_bytes_written": False})
            return 1

    if args.mock:
        with tempfile.TemporaryDirectory() as tmp:
            mock_script = _write_mock_acp_leader(Path(tmp), session_id=cfg.resolved().session_id)
            if not args.ledger:
                cfg.ledger_path = str(Path(tmp) / "mock-ledger.json")
            if not args.wake_dir:
                cfg.wake_dir = str(Path(tmp) / "wake-notes")
            cfg.updates_jsonl_path = ""
            res = run_channel_turn(
                cfg,
                args.text,
                message_id=args.message_id,
                spawn_cmd=[sys.executable, str(mock_script)],
                write_wake=True,
            )
            res["mode"] = "mock_acp"
            _emit(res)
            return 0 if res.get("delivered") and res.get("stop_reason") == "end_turn" else 1

    if not args.live:
        _emit(
            {
                "error": "live_flag_required",
                "detail": "Pass --dry-run, --mock, or --live (only after the human user's explicit OK).",
                "live_bytes_written": False,
            }
        )
        return 2

    try:
        res = run_channel_turn(cfg, args.text, message_id=args.message_id, dry_run=False)
    except (ChannelError, ValueError) as exc:
        _emit({"error": str(exc)})
        return 1
    _emit(res)
    return 0 if res.get("delivered") and res.get("stop_reason") == "end_turn" else 1


def _watch_wake_cmd(args) -> int:
    from firefly_bridge.channel import load_channel_config, sync_late_replies

    kw: dict = {}
    if args.wake_dir:
        kw["wake_dir"] = args.wake_dir
    if args.updates_jsonl:
        kw["updates_jsonl_path"] = args.updates_jsonl
    if args.session_cwd:
        kw["session_cwd"] = args.session_cwd
    cfg = load_channel_config(path=getattr(args, "config", None), overrides=kw)
    res = sync_late_replies(cfg, state_file=args.state_file)
    _emit(res)
    return 0


def _write_mock_acp_leader(tmp_dir: Path, *, session_id: str) -> Path:
    script = tmp_dir / "mock_leader.py"
    script.write_text(
        f"""\
import json, sys

SID = {session_id!r}
PROMPT_ID = "mock-prompt-0001"

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
        # Emit an oversized 200KB frame during load to prove rc6 frame resilience
        emit({{"jsonrpc": "2.0", "method": "session/update", "params": {{
            "sessionId": SID,
            "update": {{"sessionUpdate": "tool_call_update", "rawOutput": "X" * 200000}}
        }}}})
        emit({{"jsonrpc": "2.0", "id": rid, "result": {{"_meta": {{"sessionId": SID}}}}}})
    elif method == "session/prompt":
        text = msg["params"]["prompt"][0]["text"]
        emit({{"jsonrpc": "2.0", "method": "_x.ai/queue/changed", "params": {{
            "sessionId": SID,
            "entries": [],
            "runningPromptId": PROMPT_ID,
            "runningText": text,
            "runningKind": "prompt",
        }}}})
        emit({{"jsonrpc": "2.0", "method": "session/update", "params": {{
            "sessionId": SID,
            "_meta": {{"promptId": PROMPT_ID, "chunkId": 1}},
            "update": {{
                "sessionUpdate": "agent_message_chunk",
                "content": {{"type": "text", "text": "Mock peerb: recebi (" + text + ")"}},
            }},
        }}}})
        emit({{"jsonrpc": "2.0", "method": "_x.ai/session/update", "params": {{
            "sessionId": SID,
            "update": {{"sessionUpdate": "turn_completed", "prompt_id": PROMPT_ID, "stop_reason": "end_turn"}},
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


def _queue_cmd(args) -> int:
    """Authenticated daemon client; --local remains an explicitly offline mock."""
    from firefly_bridge.daemon import load_or_exit
    from firefly_bridge.envelope import load_key, sign_text
    from firefly_bridge.messages import new_message_id
    from firefly_bridge.queue import DELIVERED, Outbox

    cfg = load_or_exit(getattr(args, "config", None), require_target=False)
    if not getattr(args, "local", False):
        from firefly_bridge.ipc import ipc_call

        cfg.validate(require_target=True)
        mid = args.message_id or new_message_id()
        payload = {"message_id": mid}
        if args.cmd == "enqueue":
            payload["body"] = args.text
        try:
            result = ipc_call(cfg, args.cmd, payload)
        except (ValueError, OSError):
            _emit({"error": "broker_unavailable_or_request_refused"})
            return 2
        _emit(result)
        return 1 if "error" in result else 0

    clock = {"t": 0.0}

    def now() -> float:
        return clock["t"]

    def runner(turn):
        # Instant success for offline smoke; real turns live in AcpSession.run_turn.
        if turn.cancel_requested.is_set():
            return {"stop_reason": "cancelled"}
        return {"stop_reason": "end_turn"}

    box = Outbox(
        runner,
        turn_timeout_s=cfg.turn_timeout_s,
        busy_wait_s=cfg.busy_wait_s,
        busy_policy=cfg.busy_policy,
        max_outbox=cfg.max_outbox,
        now=now,
    )
    if args.cmd == "cancel":
        turn = box.cancel(args.message_id)
        _emit({"found": turn is not None, "turn": None if turn is None else turn.to_receipt_dict()})
        return 0 if turn is not None else 1

    mid = args.message_id or new_message_id()
    if cfg.auth_mode == "hmac":
        outbound = sign_text(
            load_key(cfg.hmac_key_file),
            prefix=cfg.prefix,
            sender=cfg.sender,
            session_id=cfg.session_id or "sess-example-0001",
            message_id=mid,
            body=args.text,
        )
    else:
        outbound = cfg.prefix + args.text
    turn = box.enqueue(mid, cfg.session_id or "sess-example-0001", args.text, outbound)
    processed = box.drain()
    _emit(
        {
            "enqueued": turn.to_receipt_dict(),
            "processed": [t.to_receipt_dict() for t in processed],
            "status": box.status(),
            "live_send": cfg.live_send,
            "delivered": any(t.state == DELIVERED for t in processed),
        }
    )
    return 0


def _send(args) -> int:
    if args.transport == "live":
        bridge = Bridge(DisabledLiveTransport(), timeout_s=args.timeout, ledger_path=_ledger(args))
        receipt = bridge.prepare(args.session_id, args.text, message_id=args.message_id)
        bridge.send(receipt)
        _emit(receipt.to_dict())
        return 3
    busy = {"idle": False, "busy": True, "unknown": None}[args.busy]
    transport = MockTransport(
        pinned_session_id=args.mock_session,
        script=args.script,
        busy_precondition=busy,
    )
    bridge = Bridge(transport, timeout_s=args.timeout, ledger_path=_ledger(args))
    receipt = bridge.prepare(args.session_id, args.text, message_id=args.message_id)
    bridge.send(receipt)
    payload = receipt.to_dict()
    payload["methods"] = list(transport.methods)
    _emit(payload)
    if receipt.outcome == "responded" and not receipt.block_code:
        return 0
    if receipt.block_code in {
        "session_rejected",
        "busy_fail_closed",
        "busy_unknowable_fail_closed",
    }:
        return 4
    return 5


def _ledger(args) -> str:
    import os

    return args.ledger or os.environ.get("AGENT_LEDGER") or ".agent/receipts.json"


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise PreflightRefused("fixture_must_be_object")
    return data


def _closed() -> None:
    sys.stderr.write("preflight done; live send remains blocked (exit 2 esperado)\n")


def _emit(payload: dict) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


_SUBCOMMANDS = frozenset(
    {
        "preflight",
        "mac-preflight",
        "send",
        "prepare",
        "write-samples",
        "daemon",
        "enqueue",
        "cancel",
        "status",
        "doctor",
        "receipt",
        "control",
        "keygen",
        "verify",
        "channel",
        "watch-wake",
    }
)


def main_channel(argv: list[str] | None = None) -> int:
    """Console entrypoint for `channel` (mirrors scripts/channel)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return main(["channel", "--help"])
    first = args[0]
    if first in _SUBCOMMANDS:
        return main(args)
    if first.startswith("-"):
        return main(["channel", *args])
    return main(["channel", "--text", first, *args[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
