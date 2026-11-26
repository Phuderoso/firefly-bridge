"""Authority regressions: disposable paths/fake peers; no real key/leader/socket."""

import fcntl
import hashlib
import json
import multiprocessing
import os
import threading
import warnings
from dataclasses import replace
from pathlib import Path

import pytest
from test_v030 import Peer, permission, ready

from firefly_bridge.authority import canonical_target
from firefly_bridge.config import BridgeConfig
from firefly_bridge.daemon import Daemon, DaemonError
from firefly_bridge.permissions import PermissionPolicy


@pytest.fixture
def make_broker(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    brokers = []

    def make(**overrides):
        values = dict(
            socket_path=str(tmp_path / "leader-never-created.sock"),
            session_id="sess-example-0001",
            state_dir=str(tmp_path / "state-one"),
            live_send=True,
            turn_timeout_s=0.001,
            agent_a_permission_mode="allow_all_own_turns",
        )
        values.update(overrides)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            d = Daemon(BridgeConfig(**values))
        brokers.append(d)
        d.session.conn = Peer(d.session)
        ready(d.session)
        d.control("human", "opt_in")
        d.control("recipient", "opt_in")
        return d

    yield make
    for d in reversed(brokers):
        d.close()


def start(d):
    d.enqueue("fake-turn", "synthetic message")
    turn = d.pump_once()
    d.session.observation_expired = False
    return turn


def request(d, path, *, kind="delete", name="delete_file", reject=True):
    r = permission(d.session)
    r["params"]["toolCall"] = {"kind": kind, "name": name, "rawInput": {"path": str(path)}}
    if reject:
        r["params"]["options"].append({"kind": "reject_once", "optionId": "no"})
    return r


def assert_denied(d, r, reason):
    d.session._on_request(r)
    assert d.session.permission_log[-1]["action"] == "deny"
    assert d.session.permission_log[-1]["reason"] == reason
    assert d.session.conn.responses == [
        (r["id"], {"outcome": {"outcome": "selected", "optionId": "no"}})
    ]
    assert d.session.observation_expired


def test_agent_c_exact_authority_probe_regression(make_broker, tmp_path):
    # Same config, peer, turn, digest, delete_file payload and allow-only options
    # as agent-c's unmodified authority-probe.py. Only expected outcomes differ.
    one = make_broker()
    start(one)
    digest = hashlib.sha256(
        canonical_target(one.cfg.session_id, one.cfg.socket_path).encode()
    ).hexdigest()
    lock = tmp_path / "runtime" / ("firefly-bridge-" + str(os.getuid())) / (digest + ".lock")
    assert str(lock) == one._authority_lease.paths[1]
    one.session._on_request(request(one, lock, reject=False))
    approved = any(
        result["outcome"].get("optionId") == "once" for _, result in one.session.conn.responses
    )
    assert not approved
    assert one.session.conn.responses == []  # no reject_once offered: silence
    assert one.session.permission_log[-1]["reason"] == "protected_bridge_resource"
    # Force only the fixture deletion anyway: the independent target fence stays.
    lock.unlink()
    with (
        warnings.catch_warnings(),
        pytest.raises(DaemonError, match="dispatch_authority_already_held"),
    ):
        warnings.simplefilter("ignore")
        Daemon(replace(one.cfg, state_dir=str(tmp_path / "state-two")))
    assert not one.authority_held()
    assert not (tmp_path / "state-two" / "broker.sqlite3").exists()
    print(
        json.dumps(
            {
                "synthetic_own_permission_approved": approved,
                "gate_enabled": one.cfg.protected_tools_enabled,
                "same_target_two_simultaneous_authorities": False,
                "forced_fixture_unlink_second_claim_blocked": True,
                "real_agents_or_sockets_used": False,
            }
        )
    )


@pytest.mark.parametrize("mode", ["pending", "allowlist", "allow_all_own_turns"])
@pytest.mark.parametrize("resource", ["runtime", "lock", "fence_root", "fence"])
@pytest.mark.parametrize(
    "kind,name",
    [
        ("read", "read_file"),
        ("edit", "write_file"),
        ("delete", "delete_file"),
        ("edit", "move_file"),
    ],
)
def test_authority_resources_denied_in_every_mode(make_broker, mode, resource, kind, name):
    d = make_broker(agent_a_permission_mode=mode)
    start(d)
    lease = d._authority_lease
    path = dict(
        runtime=lease.directories[1],
        lock=lease.paths[1],
        fence_root=lease.directories[0],
        fence=lease.paths[0],
    )[resource]
    r = request(d, path, kind=kind, name=name)
    if name == "move_file":
        r["params"]["toolCall"]["rawInput"] = {
            "source": path,
            "destination": "ordinary-destination",
        }
    assert_denied(d, r, "protected_bridge_resource")
    assert d.authority_held()


@pytest.mark.parametrize(
    "variant", ["symlink", "relative", "dotdot", "case", "parent", "descendant"]
)
def test_runtime_path_aliases_are_protected(make_broker, tmp_path, variant):
    d = make_broker(session_cwd=str(tmp_path))
    start(d)
    lock = Path(d._authority_lease.paths[1])
    if variant == "symlink":
        path = tmp_path / "innocuous"
        path.symlink_to(lock)
    elif variant == "relative":
        path = os.path.relpath(lock, tmp_path)
    elif variant == "dotdot":
        path = str(lock.parent / "absent" / ".." / lock.name)
    elif variant == "case":
        path = str(lock).upper()
    elif variant == "parent":
        path = lock.parent.parent
    else:
        path = lock.parent / "future-child"
    assert_denied(d, request(d, path), "protected_bridge_resource")


@pytest.mark.parametrize("enabled", [False, True])
def test_authority_invariant_is_not_a_protection_opt_out(make_broker, enabled):
    d = make_broker(protected_tools_enabled=enabled)
    start(d)
    # Even an injected policy with its gate disabled cannot touch authority paths.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        d.session.policy = PermissionPolicy(
            mode="allow_all_own_turns", protected_tools_enabled=False
        )
    assert_denied(d, request(d, d._authority_lease.paths[1]), "protected_bridge_resource")


@pytest.mark.parametrize(
    "kind,name", [("read", "read_file"), ("edit", "write_file"), ("delete", "delete_file")]
)
def test_broad_mode_eligible_files_still_approve_with_valid_authority(
    make_broker, tmp_path, kind, name
):
    d = make_broker()
    start(d)
    r = request(d, tmp_path / "ordinary-note", kind=kind, name=name)
    d.session._on_request(r)
    assert d.session.conn.responses[0][1]["outcome"]["optionId"] == "once"
    assert d.authority_held()


@pytest.mark.parametrize(
    "loss",
    [
        "unlink",
        "replace",
        "generation",
        "directory",
        "symlink_directory",
        "unlocked",
        "other_holder",
        "closed_fd",
        "wrong_target",
        "missing_handle",
    ],
)
def test_lost_authority_rejects_ordinary_destructive_permission(make_broker, tmp_path, loss):
    d = make_broker()
    start(d)
    lease = d._authority_lease
    path = Path(lease.paths[1])
    other = None
    if loss == "unlink":
        path.unlink()
    elif loss == "replace":
        replacement = path.with_suffix(".new")
        replacement.write_bytes(lease.generation)
        replacement.chmod(0o600)
        replacement.replace(path)
    elif loss == "generation":
        os.pwrite(d._authority, b"tampered", 0)
    elif loss in ("directory", "symlink_directory"):
        old = path.parent.with_name("previous-runtime")
        path.parent.rename(old)
        if loss == "directory":
            path.parent.mkdir(mode=0o700)
        else:
            path.parent.symlink_to(old, target_is_directory=True)
    elif loss in ("unlocked", "other_holder"):
        fcntl.flock(d._authority, fcntl.LOCK_UN)
        if loss == "other_holder":
            other = os.open(path, os.O_RDWR)
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    elif loss == "closed_fd":
        os.close(d._authority)
    elif loss == "wrong_target":
        # Preserve origin equality to ensure the authority target check is needed.
        d.cfg.socket_path = str(tmp_path / "different-leader.sock")
    else:
        d._authority = None
    try:
        assert_denied(d, request(d, tmp_path / "ordinary-note"), "authority_not_held")
        assert not d.snapshot()["authority"]
        assert not d._dispatch_gate(d.outbox._in_flight)
        assert d.store.unresolved()  # authority loss cannot invent a terminal ACK
    finally:
        if other is not None:
            os.close(other)


def test_lost_authority_never_silently_reacquires(make_broker):
    d = make_broker()
    lease = d._authority_lease
    fcntl.flock(d._authority, fcntl.LOCK_UN)
    assert not d.authority_held()
    # Even restoring the OS lock cannot revive the fenced-out incarnation.
    fcntl.flock(d._authority, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert not lease.held()
    with pytest.raises(DaemonError, match="authority_lost_restart_required"):
        d.acquire_authority()


@pytest.mark.parametrize(
    "corrupt", ["proof", "sender", "turn_id", "generation", "attempted", "state"]
)
def test_current_turn_requires_exact_durable_claim(make_broker, tmp_path, corrupt):
    d = make_broker()
    turn = start(d)
    substitutions = dict(
        proof="{}",
        sender="agent-b",
        turn_id="not-this-turn",
        generation=999,
        attempted=None,
        state="delivered",
    )
    with d.store.tx():
        d.store.db.execute(
            f"UPDATE messages SET {corrupt}=? WHERE id=?", (substitutions[corrupt], turn.message_id)
        )
    assert_denied(d, request(d, tmp_path / "ordinary-note"), "authority_not_held")


def test_authority_rechecked_after_audit_before_response(make_broker, tmp_path, monkeypatch):
    d = make_broker()
    start(d)
    record = d.session.record_permission

    def lose_during_audit(entry):
        record(entry)
        if entry.get("phase") == "decision_intent" and entry.get("action") == "allow_once":
            Path(d._authority_lease.paths[1]).unlink()

    monkeypatch.setattr(d.session, "record_permission", lose_during_audit)
    assert_denied(d, request(d, tmp_path / "ordinary-note"), "authority_not_held")
    events = d.store.audit_history("human")
    assert any(e.get("action") == "deny" for e in events)
    assert not any(
        e.get("action") == "approve" and e.get("phase") == "response_sent" for e in events
    )


def test_foreign_permission_still_silent_after_authority_loss(make_broker, tmp_path):
    d = make_broker()
    start(d)
    Path(d._authority_lease.paths[1]).unlink()
    r = request(d, tmp_path / "ordinary-note")
    r["params"]["_meta"]["agentBridge"]["nonce"] = "foreign"
    d.session._on_request(r)
    assert d.session.conn.responses == []
    assert d.session.permission_log == []


def test_claim_to_write_authority_loss_does_not_send_or_retry(make_broker):
    d = make_broker()
    claim = d.session.persist_claim

    def lose_after_claim(turn, origin):
        claim(turn, origin)
        Path(d._authority_lease.paths[1]).unlink()

    d.session.persist_claim = lose_after_claim
    d.enqueue("race", "synthetic")
    turn = d.pump_once()
    assert turn.state == "unknown"
    assert d.store.lookup("race")["attempt_committed"]
    assert d.session.conn.calls == []
    assert d.store.unresolved()
    assert d.enqueue("race", "synthetic")["queue_state"] == "unknown"


def _contender(values, runtime, start_event, release_event, results):
    os.environ["XDG_RUNTIME_DIR"] = runtime
    if not start_event.wait(10):
        return
    try:
        d = Daemon(BridgeConfig(**values))
    except DaemonError as exc:
        results.put(str(exc))
    else:
        try:
            results.put("acquired")
            release_event.wait(10)
        finally:
            d.close()


def test_concurrent_processes_distinct_dbs_and_runtimes_share_canonical_target(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    context = multiprocessing.get_context("spawn")
    start_event, release_event, results = context.Event(), context.Event(), context.Queue()
    processes = []
    for i, target in enumerate((actual, alias)):
        runtime = tmp_path / f"runtime-{i}"
        runtime.mkdir()
        values = vars(
            BridgeConfig(
                socket_path=str(target / "leader-never-created.sock"),
                session_id="sess-example-0001",
                state_dir=str(tmp_path / f"state-{i}"),
            )
        )
        p = context.Process(
            target=_contender, args=(values, str(runtime), start_event, release_event, results)
        )
        p.start()
        processes.append(p)
    try:
        start_event.set()
        assert sorted([results.get(timeout=10), results.get(timeout=10)]) == [
            "acquired",
            "dispatch_authority_already_held",
        ]
    finally:
        release_event.set()
        for p in processes:
            p.join(10)
            if p.is_alive():
                p.terminate()
                p.join(5)
            assert p.exitcode == 0


def test_distinct_targets_can_hold_authority_concurrently(make_broker, tmp_path):
    one = make_broker()
    two = make_broker(
        socket_path=str(tmp_path / "another-leader.sock"), state_dir=str(tmp_path / "another-state")
    )
    assert one.authority_held() and two.authority_held()


def test_unlinked_runtime_lock_still_fences_another_process(make_broker, tmp_path):
    one = make_broker()
    Path(one._authority_lease.paths[1]).unlink()
    assert not one.authority_held()
    context = multiprocessing.get_context("spawn")
    begin, release, results = context.Event(), context.Event(), context.Queue()
    begin.set()
    values = vars(
        replace(one.cfg, state_dir=str(tmp_path / "other-state"), agent_a_permission_mode="pending")
    )
    process = context.Process(
        target=_contender, args=(values, str(tmp_path / "runtime"), begin, release, results)
    )
    process.start()
    try:
        assert results.get(timeout=10) == "dispatch_authority_already_held"
    finally:
        release.set()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)
        assert process.exitcode == 0


def test_response_action_serializes_with_authority_close(make_broker):
    d = make_broker()
    turn = start(d)
    entered, release, closing, closed = (threading.Event() for _ in range(4))
    responses = []

    def respond(rid, result):
        entered.set()
        assert release.wait(5)

    d.session.conn.respond = respond
    action = threading.Thread(
        target=lambda: responses.append(d._authority_respond(turn, "synthetic-id", {}))
    )

    def close():
        closing.set()
        d._authority_lease.close()
        closed.set()

    closer = threading.Thread(target=close)
    action.start()
    try:
        assert entered.wait(5)
        closer.start()
        assert closing.wait(5)
        assert not closed.wait(0.02)
    finally:
        release.set()
        action.join(5)
        if closer.ident is not None:
            closer.join(5)
    assert not action.is_alive() and not closer.is_alive()
    assert responses == [True] and closed.is_set()
    assert not d.authority_held()


def test_embedded_session_cannot_use_another_target_authority(make_broker, tmp_path):
    d = make_broker()
    start(d)
    # An embedder may supply a distinct session object/config; bind both targets.
    d.session.cfg = replace(d.cfg, socket_path=str(tmp_path / "unclaimed-target.sock"))
    assert_denied(d, request(d, tmp_path / "ordinary-note"), "authority_not_held")
    assert not d.authority_held()
