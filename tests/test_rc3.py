"""RC3 protection/audit/pacing regressions. All peers and clocks are synthetic."""

import json
import math
import tomllib
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from test_rc2 import begin
from test_rc2 import make_broker as make_broker
from test_v030 import permission, ready

from firefly_bridge import __version__
from firefly_bridge.audit import local_time
from firefly_bridge.broker_store import BrokerStore
from firefly_bridge.config import BridgeConfig, ConfigError, load_config
from firefly_bridge.doctor import doctor
from firefly_bridge.permissions import PermissionPolicy

TIMERS = [name for name in BridgeConfig.__dataclass_fields__ if name.endswith("_s")]


@pytest.mark.parametrize("field", TIMERS)
@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_all_timers_reject_nonfinite_direct_env_and_toml(field, value, tmp_path):
    with pytest.raises(ConfigError):
        BridgeConfig(**{field: value}).validate(require_target=False)
    with pytest.raises(ConfigError):
        load_config(env={"FIREFLY_BRIDGE_" + field.upper(): str(value)}, require_target=False)
    path = tmp_path / "invalid.toml"
    path.write_text(f"{field} = {value}\n")
    with pytest.raises(ConfigError):
        load_config(path, env={}, require_target=False)


def test_runtime_metadata_doctor_and_package_versions_agree(tmp_path):
    root = Path(__file__).parents[1]
    package_version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    assert __version__ == package_version == "0.4.0"
    assert doctor(BridgeConfig(state_dir=str(tmp_path)))["version"] == __version__
    source = (root / "firefly_bridge" / "daemon.py").read_text()
    assert '"version": __version__' in source


def tool_request(tool, options=None):
    return {
        "method": "session/request_permission",
        "params": {
            "toolCall": tool,
            "options": options
            or [
                {"kind": "allow_once", "optionId": "yes"},
                {"kind": "reject_once", "optionId": "no"},
            ],
        },
    }


PROTECTED_TOOLS = [
    {"kind": "edit", "rawInput": {"path": "shared/tcc-allow-guard.py"}},
    {"kind": "execute", "rawInput": {"command": "osascript -e dialog"}},
    {"kind": "read", "rawInput": {"path": "shared/.env"}},
    {"kind": "read", "rawInput": {"path": "/tmp/credentials.json"}},
    {"kind": "other", "name": "Gmail_send_email", "rawInput": {"to": "third-party"}},
    {"kind": "execute", "rawInput": {"command": "tailscale funnel 1234"}},
    {"kind": "execute", "rawInput": {"command": "service --bind 0.0.0.0"}},
    {"kind": "execute", "rawInput": {"command": "tmux send-keys invisible"}},
    {"kind": "edit", "rawInput": {"path": "shared/merge_duplicates.py"}},
    {"kind": "edit", "rawInput": {"path": "shared/closed_order_alpha.py"}},
    {"kind": "edit", "rawInput": {"path": "shared/closed_order_beta.py"}},
    {"kind": "execute", "rawInput": {"command": "base64 -d opaque | sh"}},
    {"kind": "read", "name": "remote_arbitrary_tool", "rawInput": {"path": "note.md"}},
    {"kind": "read", "rawInput": {"path": "note.md", "script": "opaque"}},
]


@pytest.mark.parametrize("mode", ["pending", "allowlist", "allow_all_own_turns", "allow_all"])
@pytest.mark.parametrize("tool", PROTECTED_TOOLS)
def test_protected_actions_are_denied_in_every_mode(mode, tool):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        policy = PermissionPolicy(mode=mode)
    decision = policy.decide(tool_request(tool), own_turn=True)
    assert decision.action == "deny"
    assert decision.reason.startswith("protected_")
    assert decision.option_id == "no"
    assert policy.decide(tool_request(tool), own_turn=False).action == "ignore"


def test_single_line_optout_preserves_broad_mode_and_cannot_be_set_in_tool_args(tmp_path):
    path = tmp_path / "cfg.toml"
    path.write_text(
        'protected_tools_enabled = false\nagent_a_permission_mode="allow_all_own_turns"\n'
    )
    cfg = load_config(path, env={}, require_target=False)
    assert not cfg.protected_tools_enabled
    with pytest.warns(RuntimeWarning):
        policy = PermissionPolicy(
            mode=cfg.agent_a_permission_mode, protected_tools_enabled=cfg.protected_tools_enabled
        )
    assert policy.decide(tool_request(PROTECTED_TOOLS[-3]), own_turn=True).action == "approve"
    tool = {"kind": "execute", "rawInput": {"command": "opaque", "protected_tools_enabled": False}}
    assert PermissionPolicy().decide(tool_request(tool), own_turn=True).action == "deny"


def test_symlink_alias_unicode_and_nested_secret_cannot_bypass(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("synthetic only")
    alias = tmp_path / "innocent"
    alias.symlink_to(secret)
    policy = PermissionPolicy()
    for tool in [
        {"kind": "read", "rawInput": {"path": str(alias)}},
        {"kind": "edit", "rawInput": {"path": "shared/ＴＣＣ-allow-guard.py"}},
        {"kind": "edit", "rawInput": {"path": "note.md", "edits": [{"api_key": "synthetic"}]}},
    ]:
        assert policy.decide(tool_request(tool), own_turn=True).action == "deny"


@pytest.mark.parametrize("reject_option", [True, False])
def test_broker_enforces_status_laws_before_allow_all(make_broker, reject_option):
    with pytest.warns(RuntimeWarning):
        d = make_broker(agent_a_permission_mode="allow_all_own_turns")
    begin(d)
    s = d.session
    s.observation_expired = False
    request = permission(s)
    request["params"]["toolCall"] = PROTECTED_TOOLS[5]
    if reject_option:
        request["params"]["options"].append({"kind": "reject_once", "optionId": "reject"})
    s._on_request(request)
    assert not any(r["outcome"].get("optionId") == "once" for _, r in s.conn.responses)
    assert len(s.conn.responses) == int(reject_option)
    assert s.observation_expired
    assert d.snapshot()["laws"]["enforced"] is True
    # A later benign permission cannot accidentally clear the veto.
    s._on_request(permission(s, rid="later"))
    assert len(s.conn.responses) == int(reject_option)


def test_broad_mode_still_approves_classified_nonprotected_files(make_broker):
    with pytest.warns(RuntimeWarning):
        d = make_broker(agent_a_permission_mode="allow_all_own_turns")
    begin(d)
    d.session.observation_expired = False
    request = permission(d.session)
    request["params"]["toolCall"] = {
        "kind": "edit",
        "rawInput": {"path": "/tmp/nonprotected-note.md"},
    }
    d.session._on_request(request)
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "once"


def test_permission_audit_and_receipt_identify_tool_target_and_local_time(make_broker):
    with pytest.warns(RuntimeWarning):
        d = make_broker(agent_a_permission_mode="allow_all_own_turns")
    turn = begin(d)
    d.session.observation_expired = False
    request = permission(d.session)
    request["params"]["toolCall"] = {
        "kind": "edit",
        "toolCallId": "synthetic-call",
        "rawInput": {"path": "shared/note.md"},
    }
    d.session._on_request(request)
    events = d.receipt("agent-a", turn.message_id)["permission_events"]
    assert len(events) == 2
    assert [e["phase"] for e in events] == ["decision_intent", "response_sent"]
    event = events[0]
    assert event["tool"]["kind"] == "edit"
    assert event["target"]["kind"] == "file"
    assert len(event["target"]["sha256"]) == 64
    assert event["at_local"] == local_time(event["at"])
    assert event["timezone"] == "UTC"
    assert "note.md" not in json.dumps(events)
    assert d.receipt("agent-c", turn.message_id) == {"error": "not_found"}
    disk = d.session.approval_receipts_path.read_text()
    assert "target" in disk and "at_local" in disk
    assert "shared" not in disk


def test_controls_have_atomic_bounded_private_history_across_restart(tmp_path):
    path = tmp_path / "state" / "broker.sqlite3"
    store = BrokerStore(path, "synthetic-target", now=lambda: 1800000000)
    store.control("human", "opt_in", ["agent-a"])
    store.control("recipient", "opt_in", ["agent-a"])
    store.control("recipient", "basta")
    store.control("human", "pause")
    events = store.audit_history("human", controls_only=True)
    assert [e["event"] for e in events] == ["opt_in", "opt_in", "basta", "pause"]
    assert events[-1]["actor"] == "human"
    assert events[-1]["at_local"] == local_time(1800000000)
    assert len(store.audit_history("agent-b", controls_only=True)) == 2
    with pytest.raises(ValueError):
        store.control("agent-a", "opt_in")
    store.close()
    store = BrokerStore(path, "synthetic-target")
    assert store.audit_history("human", controls_only=True) == events
    for _ in range(1010):
        store.control("human", "pause")
    assert len(store.audit_history("human", controls_only=True)) == 100
    assert store.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1000
    store.close()


def test_audit_hashes_secrets_and_recovers_typed_times_when_redactor_fails(
    make_broker, monkeypatch
):
    from firefly_bridge import privacy

    with pytest.warns(RuntimeWarning):
        d = make_broker(agent_a_permission_mode="allow_all_own_turns")
    turn = begin(d)
    d.session.observation_expired = False
    request = permission(d.session)
    request["params"]["toolCall"] = {
        "kind": "execute",
        "title": "token=synthetic-private-value",
        "rawInput": {"command": "password=synthetic-private-value"},
    }
    d.session._on_request(request)
    data = json.dumps(d.store.audit_history("human")) + d.session.approval_receipts_path.read_text()
    assert "synthetic-private-value" not in data
    monkeypatch.setattr(privacy, "redact_text", lambda _: (_ for _ in ()).throw(ValueError()))
    receipt = d.receipt("agent-a", turn.message_id)
    assert receipt["message_id"] == turn.message_id
    assert receipt["accepted_at_local"].endswith("+00:00")
    assert receipt["permission_events"][0]["tool"]["identity_sha256"] != "[REDACTION_FAILED]"


@pytest.mark.parametrize(
    "values",
    [
        {"quiet_hours_start": "22:00"},
        {"quiet_hours_end": "08:00"},
        {"quiet_hours_start": "25:00", "quiet_hours_end": "08:00"},
        {"quiet_hours_start": "22:00", "quiet_hours_end": "22:00"},
        {"quiet_hours_start": "9:00", "quiet_hours_end": "10:00"},
        {"quiet_hours_timezone": "Nonexistent/Zone"},
        {"post_turn_interval_s": -1},
        {"target_interval_s": -1},
        {"post_turn_interval_s": 2000, "busy_wait_s": 1800},
        {"target_interval_s": 2000, "busy_wait_s": 1800},
    ],
)
def test_invalid_quiet_hours_and_pacing_are_rejected(values):
    with pytest.raises(ConfigError):
        BridgeConfig(**values).validate(require_target=False)


def wall(value):
    return datetime.fromisoformat(value).replace(tzinfo=ZoneInfo("UTC")).timestamp()


@pytest.mark.parametrize(
    "start,end,moment,quiet",
    [
        ("22:00", "08:00", "2026-11-09T21:59:59", False),
        ("22:00", "08:00", "2026-11-09T22:00:00", True),
        ("22:00", "08:00", "2026-11-10T07:59:59", True),
        ("22:00", "08:00", "2026-11-10T08:00:00", False),
        ("09:00", "12:00", "2026-11-09T10:00:00", True),
        ("09:00", "12:00", "2026-11-09T12:00:00", False),
        ("01:00", "02:00", "2026-11-01T01:30:00", True),  # DST repeated hour remains quiet
    ],
)
def test_quiet_boundaries_and_zone(start, end, moment, quiet):
    cfg = BridgeConfig(quiet_hours_start=start, quiet_hours_end=end)
    assert cfg.validate(require_target=False).quiet_now(wall(moment)) is quiet


def test_quiet_gate_blocks_dispatch_without_writing_or_cancelling(make_broker):
    d = make_broker(quiet_hours_start="22:00", quiet_hours_end="08:00")
    d.store.now = lambda: wall("2026-11-09T23:00:00")
    d.enqueue("quiet-message", "hello")
    assert d.pump_once() is None
    assert d.session.conn.calls == []
    assert d.snapshot()["pacing"]["quiet_now"]
    d.store.now = lambda: wall("2026-11-10T08:00:00")
    ready(d.session)
    assert d.pump_once().message_id == "quiet-message"


def test_post_terminal_floor_starts_at_end_of_long_turn_and_persists(make_broker, tmp_path):
    d = make_broker(post_turn_interval_s=60, target_interval_s=10)
    clock = [1800000000.0]
    d.store.now = lambda: clock[0]
    turn = begin(d)
    assert turn.state == "unknown"
    clock[0] += 5000  # elapsed start cooldown is NOT a post-terminal cooldown
    d.session.conn.finish()
    assert d.pump_once().state == "delivered"
    d.enqueue("sibling", "hello", sender="agent-b")
    ready(d.session)
    assert d.pump_once() is None
    assert not d.store.interval_ready("agent-b", d.cfg)
    cfg = d.cfg
    d.close()
    reopened = BrokerStore(
        Path(cfg.state_dir) / "broker.sqlite3",
        cfg.session_id + "|" + str(Path(cfg.socket_path).resolve()),
        now=lambda: clock[0],
    )
    assert not reopened.interval_ready("agent-c", cfg)
    clock[0] += 59
    assert not reopened.interval_ready("agent-c", cfg)
    clock[0] += 1
    assert reopened.interval_ready("agent-c", cfg)
    reopened.close()
    # make_broker cleanup close() is idempotent.


def test_real_global_interval_between_agents_and_claim_recheck(make_broker):
    d = make_broker(target_interval_s=600)
    clock = [1800000000.0]
    d.store.now = lambda: clock[0]
    d.session.conn.terminal = True
    begin(d)
    d.enqueue("second", "hello", sender="agent-b")
    ready(d.session)
    assert d.pump_once() is None
    clock[0] += 599
    assert not d.store.interval_ready("agent-b", d.cfg)
    clock[0] += 1
    ready(d.session)
    assert d.pump_once().sender == "agent-b"
    # Simulate a quiet-hours boundary crossed after queue admission but before claim.
    d.cfg.quiet_hours_start, d.cfg.quiet_hours_end = "22:00", "08:00"
    clock[0] = wall("2026-11-09T23:00:00")
    d.enqueue("third", "hello", sender="agent-c")
    pending = d.outbox._pending[0]
    pending.state = "in_flight"
    d.store.update(pending, "in_flight")
    with pytest.raises(ValueError, match="rejected_quiet_hours"):
        d.store.claim(pending, {}, d.cfg)


def test_quiet_hours_do_not_cancel_active_turn_or_revoke_optins(make_broker):
    d = make_broker(quiet_hours_start="22:00", quiet_hours_end="08:00")
    clock = [wall("2026-11-09T21:59:59")]
    d.store.now = lambda: clock[0]
    turn = begin(d)
    clock[0] += 2
    assert d.pump_once() is None
    assert d.store.consent("agent-a")
    assert d.session.conn.notifications == []
    assert d.outbox._in_flight is turn


def test_injected_broad_policy_cannot_override_broker_status_laws(make_broker):
    d = make_broker()
    with pytest.warns(RuntimeWarning):
        d.session.policy = PermissionPolicy(
            mode="allow_all_own_turns", protected_tools_enabled=False
        )
    begin(d)
    d.session.observation_expired = False
    request = permission(d.session)
    request["params"]["toolCall"] = PROTECTED_TOOLS[5]
    d.session._on_request(request)
    assert d.session.conn.responses == []
    assert d.session.observation_expired
    assert d.snapshot()["laws"]["enforced"]


def test_explicit_config_optout_disables_broker_guard_not_only_status(make_broker):
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            protected_tools_enabled=False, agent_a_permission_mode="allow_all_own_turns"
        )
    begin(d)
    d.session.observation_expired = False
    request = permission(d.session)
    request["params"]["toolCall"] = PROTECTED_TOOLS[5]
    d.session._on_request(request)
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "once"
    assert not d.snapshot()["laws"]["enforced"]


def test_nested_indirect_execution_and_network_paths_fail_closed():
    for raw in [
        {"path": "note.md", "edits": [{"command": "opaque"}]},
        {"path": "//remote/share"},
        {"path": "note.md", "edits": [{"name": "opaque"}]},
    ]:
        decision = PermissionPolicy().decide(
            tool_request({"kind": "edit", "rawInput": raw}), own_turn=True
        )
        assert decision.action == "deny"


def test_permission_claim_never_persists_arbitrary_rpc_id(tmp_path):
    store = BrokerStore(tmp_path / "state" / "broker.sqlite3", "synthetic-target")
    rid = "password=private-rpc-fixture"
    assert store.permission_once("turn-1", rid)
    assert not store.permission_once("turn-1", rid)
    stored = store.db.execute("SELECT rpc_id FROM permissions").fetchone()[0]
    assert len(stored) == 64 and rid not in stored
    store.close()


@pytest.mark.parametrize(
    "tool",
    [None, "malformed", {"kind": ["opaque"]}, {"kind": "read", "rawInput": {"path": "nul\0path"}}],
)
def test_malformed_protected_request_is_denied_without_audit_crash(make_broker, tool):
    with pytest.warns(RuntimeWarning):
        d = make_broker(agent_a_permission_mode="allow_all_own_turns")
    begin(d)
    d.session.observation_expired = False
    request = permission(d.session)
    request["params"]["toolCall"] = tool
    request["params"]["options"].append({"kind": "reject_once", "optionId": "no"})
    d.session._on_request(request)
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "no"
    assert d.store.audit_history("human")[-1]["phase"] == "response_sent"


def test_quiet_hours_cover_both_dst_folds():
    """A zone with a repeated hour keeps both folds inside the quiet window."""
    zone = ZoneInfo("America/Los_Angeles")
    cfg = BridgeConfig(
        quiet_hours_start="01:00",
        quiet_hours_end="02:00",
        quiet_hours_timezone="America/Los_Angeles",
    )
    first = datetime(2025, 11, 2, 1, 30, tzinfo=zone).replace(fold=0).timestamp()
    second = datetime(2025, 11, 2, 1, 30, tzinfo=zone).replace(fold=1).timestamp()
    assert cfg.quiet_now(first) and cfg.quiet_now(second)


def test_rc2_terminal_migration_sets_conservative_floor_once(tmp_path):
    import sqlite3

    path = tmp_path / "state" / "broker.sqlite3"
    path.parent.mkdir()
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE messages(id TEXT PRIMARY KEY, sender TEXT, digest TEXT, turn_id TEXT, "
        "generation INTEGER, accepted REAL, attempted REAL, state TEXT, receipt TEXT, proof TEXT)"
    )
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("old", "agent-a", "digest", "old-turn", 0, 100, 100, "delivered", "{}", "{}"),
    )
    conn.commit()
    conn.close()
    cfg = BridgeConfig(
        sender_interval_s=0,
        target_interval_s=0,
        post_turn_interval_s=60,
        pacing_minimums_enabled=False,
    )
    store = BrokerStore(path, "synthetic-target", now=lambda: 1000)
    store.control("human", "opt_in")
    store.control("recipient", "opt_in")
    assert store.lookup("old")["terminal_at"] == 1000
    assert not store.interval_ready("agent-b", cfg)
    store.close()
    store = BrokerStore(path, "synthetic-target", now=lambda: 1060)
    assert store.lookup("old")["terminal_at"] == 1000
    assert store.interval_ready("agent-b", cfg)
    store.close()


def test_examples_keep_modes_protected_and_offline():
    root = Path(__file__).parents[1]
    for filename in ("examples/config.example.toml", "config/example.toml"):
        cfg = load_config(root / filename, env={})
        assert cfg.protected_tools_enabled and not cfg.live_send
        assert cfg.post_turn_interval_s == 60 and cfg.target_interval_s == 600
        assert all(
            cfg.permission_mode_for(s) == "pending" for s in ("agent-a", "agent-b", "agent-c")
        )


def test_initial_and_cancel_receipts_have_authoritative_local_time(make_broker):
    d = make_broker()
    receipt = d.enqueue("queued-ack", "hello")
    assert receipt["accepted_at_local"] == local_time(receipt["accepted_at"])
    assert receipt["timezone"] == "UTC"
    cancelled = d.cancel("queued-ack", actor="agent-a")
    assert cancelled["queue_state"] == "cancelled"
    assert cancelled["accepted_at_local"] == receipt["accepted_at_local"]
