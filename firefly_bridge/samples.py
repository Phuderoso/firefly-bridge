"""Write synthetic receipts. No live session content."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from firefly_bridge.bridge import Bridge
from firefly_bridge.preflight import contract_report, evaluate_observation, mac_plan
from firefly_bridge.transport import DisabledLiveTransport, MockTransport

PIN = "sess-example-0001"


def write_samples(root: str) -> list[str]:
    ledger_dir = tempfile.TemporaryDirectory()
    ledger_path = Path(ledger_dir.name) / "receipts.json"
    base = Path(root)
    receipts = base / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    def dump(name: str, payload: dict) -> None:
        path = receipts / name if name.endswith(".json") and "/" not in name else base / name
        if name.startswith("receipts/"):
            path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(str(path))

    cases = [
        ("ok.json", "ok", False, PIN),
        ("session-rejected.json", "wrong-session", False, "sess-other-9999"),
        ("busy.json", "ok", True, PIN),
        ("unknown-timeout.json", "timeout", False, PIN),
        ("malformed.json", "malformed", False, PIN),
        ("permission-denied.json", "permission", False, PIN),
        ("crash.json", "crash", False, PIN),
    ]
    for filename, script, busy, session in cases:
        transport = MockTransport(
            pinned_session_id=PIN,
            script=script,
            busy_precondition=True if busy else False,
        )
        bridge = Bridge(transport, timeout_s=0.2, ledger_path=ledger_path)
        receipt = bridge.prepare(session, "synthetic agent note")
        bridge.send(receipt)
        payload = receipt.to_dict()
        payload["methods"] = list(transport.methods)
        dump(filename, payload)

    unknown_busy = MockTransport(pinned_session_id=PIN, script="ok", busy_precondition=None)
    bridge = Bridge(unknown_busy, timeout_s=0.2, ledger_path=ledger_path)
    receipt = bridge.prepare(PIN, "synthetic agent note")
    bridge.send(receipt)
    payload = receipt.to_dict()
    payload["methods"] = list(unknown_busy.methods)
    dump("busy-unknown.json", payload)

    live = Bridge(DisabledLiveTransport(), timeout_s=2.0, ledger_path=ledger_path)
    receipt = live.prepare(PIN, "synthetic agent note")
    live.send(receipt)
    dump("live-disabled.json", receipt.to_dict())

    (base / "preflight.json").write_text(
        json.dumps(contract_report(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.append(str(base / "preflight.json"))
    empty = evaluate_observation(
        {
            "grok_found": True,
            "grok_version": "grok 1.0.70 (f50904eaee6c)",
            "leader_list_ran": True,
            "leader_count": 0,
            "leader_json_shape": "list",
            "sessions_list_ran": True,
            "pinned_session_id_provided": True,
            "pinned_session_id_seen": False,
            "commands": [
                "grok version",
                "grok leader list --help",
                "grok leader list --json",
                "grok sessions list --limit 50",
            ],
        }
    )
    present = evaluate_observation(
        {
            "grok_found": True,
            "leader_list_ran": True,
            "leader_count": 1,
            "leader_json_shape": "list",
            "secrets_redacted": True,
            "sessions_list_ran": True,
            "pinned_session_id_seen": True,
            "live_send_allowed": True,
        }
    )
    (base / "preflight-leader-empty.json").write_text(
        json.dumps(empty, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (base / "preflight-leader-present-still-blocked.json").write_text(
        json.dumps(present, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (base / "mac-plan.json").write_text(
        json.dumps(mac_plan(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.extend(
        [
            str(base / "preflight-leader-empty.json"),
            str(base / "preflight-leader-present-still-blocked.json"),
            str(base / "mac-plan.json"),
        ]
    )
    ledger_dir.cleanup()
    return written
