"""Known bridge resources: path-only fixtures. Never create or read a key."""

from pathlib import Path

import pytest
from test_rc2 import begin
from test_rc2 import make_broker as make_broker
from test_v030 import permission

from firefly_bridge.config import load_config
from firefly_bridge.permissions import PermissionPolicy


def request_for(session, target, kind="read"):
    request = permission(session, meta=session._origin or {})
    request["params"]["toolCall"] = {
        "kind": kind,
        "name": "read_file" if kind == "read" else "write_file",
        "rawInput": {"path": str(target)},
    }
    request["params"]["options"].append({"kind": "reject_once", "optionId": "no"})
    return request


@pytest.mark.parametrize("mode", ["allow_all_own_turns", "allow_all"])
@pytest.mark.parametrize("kind", ["read", "edit", "delete"])
@pytest.mark.parametrize(
    "resource", ["human", "recipient", "hmac", "ipc_client", "ledger", "config"]
)
def test_broker_protects_its_known_resources_in_broad_modes(
    make_broker, tmp_path, mode, kind, resource
):
    root = tmp_path / "ring"
    hmac = tmp_path / "opaque-material.dat"
    client = tmp_path / "opaque-client.dat"
    config = tmp_path / "deployment.toml"
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            ipc_keys_dir=str(root),
            hmac_key_file=str(hmac),
            ipc_key_file=str(client),
            config_path=str(config),
            agent_a_permission_mode=mode,
        )
    targets = {
        "human": root / "human.key",
        "recipient": root / "recipient.key",
        "hmac": hmac,
        "ipc_client": client,
        "ledger": Path(d.cfg.state_dir) / "broker.sqlite3",
        "config": config,
    }
    begin(d)
    d.session.observation_expired = False
    d.session._on_request(request_for(d.session, targets[resource], kind))
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "no"
    assert d.session.permission_log[-1]["reason"] == "protected_bridge_resource"
    assert not hmac.exists() and not client.exists() and not (root / "human.key").exists()


@pytest.mark.parametrize(
    "alias", ["relative", "dotdot", "case", "symlink_file", "symlink_dir", "parent"]
)
@pytest.mark.parametrize("kind", ["read", "edit"])
def test_normalized_and_alias_targets_are_protected(make_broker, tmp_path, alias, kind):
    ring = tmp_path / "ring"
    ring.mkdir()
    workspace = tmp_path / "work"
    workspace.mkdir()
    target = ring / "human.key"  # nonexistent: only symlinks/empty directories below
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            ipc_keys_dir=str(ring),
            session_cwd=str(workspace),
            agent_a_permission_mode="allow_all_own_turns",
        )
    if alias == "relative":
        path = "../ring/human.key"
    elif alias == "dotdot":
        path = str(ring / "unused" / ".." / "human.key")
    elif alias == "case":
        path = str(target).upper()
    elif alias == "symlink_file":
        path = workspace / "unrelated"
        path.symlink_to(target)
    elif alias == "symlink_dir":
        link = workspace / "unrelated-directory"
        link.symlink_to(ring, target_is_directory=True)
        path = link / "human.key"
    else:
        path = ring.parent
    begin(d)
    d.session.observation_expired = False
    d.session._on_request(request_for(d.session, path, kind))
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "no"
    assert not target.exists()


def test_symlink_dotdot_uses_real_not_only_lexical_identity(make_broker, tmp_path):
    ring = tmp_path / "ring"
    (ring / "child").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(ring / "child", target_is_directory=True)
    with pytest.warns(RuntimeWarning):
        d = make_broker(ipc_keys_dir=str(ring), agent_a_permission_mode="allow_all_own_turns")
    begin(d)
    d.session.observation_expired = False
    d.session._on_request(request_for(d.session, str(alias) + "/../human.key"))
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "no"
    assert not (ring / "human.key").exists()


def test_relative_configured_resources_use_daemon_not_session_cwd(
    make_broker, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "work").mkdir()
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            ipc_keys_dir="ring",
            hmac_key_file="opaque.dat",
            session_cwd=str(tmp_path / "work"),
            agent_a_permission_mode="allow_all_own_turns",
        )
    for target in ("../ring/human.key", "../opaque.dat"):
        decision = d.session.protection.protected_decision(request_for(d.session, target))
        assert decision.action == "deny"
    assert not (tmp_path / "opaque.dat").exists()


def test_config_loader_protects_actual_source_even_if_field_env_claim_different_file(tmp_path):
    path = tmp_path / "deployment.toml"
    path.write_text('config_path="pretend.toml"\n')  # synthetic config, no credentials
    cfg = load_config(
        path, env={"FIREFLY_BRIDGE_CONFIG_PATH": "another.toml"}, require_target=False
    )
    assert cfg.config_path == str(path)
    policy = PermissionPolicy(**cfg.protected_resources())
    request = {
        "method": "session/request_permission",
        "params": {
            "toolCall": {"kind": "read", "name": "read_file", "rawInput": {"path": str(path)}}
        },
    }
    assert policy.decide(request, own_turn=True).reason == "protected_bridge_resource"


def test_sibling_prefix_does_not_overblock_public_file(make_broker, tmp_path):
    ring = tmp_path / "ring"
    with pytest.warns(RuntimeWarning):
        d = make_broker(ipc_keys_dir=str(ring), agent_a_permission_mode="allow_all_own_turns")
    begin(d)
    d.session.observation_expired = False
    d.session._on_request(request_for(d.session, tmp_path / "ring-public" / "note.md"))
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "once"


def test_broker_known_resources_still_cannot_be_bypassed_by_injected_policy(make_broker, tmp_path):
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            ipc_keys_dir=str(tmp_path / "ring"), agent_a_permission_mode="allow_all_own_turns"
        )
        d.session.policy = PermissionPolicy(
            mode="allow_all_own_turns", protected_tools_enabled=False
        )
    begin(d)
    d.session.observation_expired = False
    d.session._on_request(request_for(d.session, tmp_path / "ring" / "human.key"))
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "no"


def test_config_flag_optout_remains_explicit(make_broker, tmp_path):
    with pytest.warns(RuntimeWarning):
        d = make_broker(
            ipc_keys_dir=str(tmp_path / "ring"),
            protected_tools_enabled=False,
            agent_a_permission_mode="allow_all_own_turns",
        )
    begin(d)
    d.session.observation_expired = False
    d.session._on_request(request_for(d.session, tmp_path / "ring" / "human.key"))
    assert d.session.conn.responses[-1][1]["outcome"]["optionId"] == "once"
    assert not (tmp_path / "ring" / "human.key").exists()
