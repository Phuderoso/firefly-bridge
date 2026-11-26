"""Low-level cooperative authority tests, all paths disposable and synthetic."""

import fcntl
import os
from pathlib import Path

import pytest

from firefly_bridge.authority import AuthorityError, TargetAuthority


@pytest.fixture
def lease(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    authority = TargetAuthority("synthetic-session", str(tmp_path / "never-created.sock"))
    yield authority
    authority.close()


def test_healthy_private_authority_and_explicit_handoff(lease):
    assert lease.held()
    assert all(Path(p).stat().st_mode & 0o777 == 0o600 for p in lease.paths)
    original = lease.generation
    with pytest.raises(AuthorityError, match="dispatch_authority_already_held"):
        TargetAuthority(*lease.target.split("|", 1))
    assert lease.generation == original and lease.held()
    assert all(Path(p).read_bytes() == original for p in lease.paths)  # only public generations
    lease.close()
    assert not lease.held()
    second = TargetAuthority(*lease.target.split("|", 1))
    try:
        assert second.held() and second.generation != original
    finally:
        second.close()


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("loss", ["unlink", "generation", "unlock", "shared", "replace", "mode"])
def test_either_lock_loss_latches_closed(lease, index, loss):
    path = Path(lease.paths[index])
    if loss == "unlink":
        path.unlink()
    elif loss == "generation":
        os.pwrite(lease.fds[index], b"not-the-generation", 0)
    elif loss == "unlock":
        fcntl.flock(lease.fds[index], fcntl.LOCK_UN)
    elif loss == "shared":
        fcntl.flock(lease.fds[index], fcntl.LOCK_SH | fcntl.LOCK_NB)
    elif loss == "replace":
        new = path.with_suffix(".replacement")
        new.write_bytes(lease.generation)
        new.chmod(0o600)
        new.replace(path)
    else:
        path.chmod(0o644)
    assert not lease.held()
    assert lease.lost
    assert not lease.held()
    if path.exists():
        path.chmod(0o600)  # leave only safe synthetic metadata on disk


def test_cleanup_does_not_close_reused_fd(lease, tmp_path):
    stale = lease.runtime_fd
    os.close(stale)
    foreign = os.open(tmp_path / "ordinary-file", os.O_CREAT | os.O_RDWR, 0o600)
    if foreign != stale:
        os.dup2(foreign, stale)
        os.close(foreign)
        foreign = stale
    try:
        assert not lease.held()
        lease.close()
        assert os.fstat(foreign).st_size == 0
    finally:
        os.close(foreign)


def test_inherited_authority_cannot_be_used_as_own(lease):
    lease.pid = -1  # synthetic fork/PID mismatch, no real child needed
    assert not lease.held()


@pytest.mark.parametrize("variant", ["case", "dotdot", "symlink", "relative"])
def test_canonical_target_aliases_cannot_split_authority(lease, tmp_path, monkeypatch, variant):
    session_id, socket_path = lease.target.split("|", 1)
    if variant == "case":
        candidate = socket_path.upper()
    elif variant == "dotdot":
        candidate = str(tmp_path / "absent" / ".." / Path(socket_path).name)
    elif variant == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        candidate = str(alias / Path(socket_path).name)
    else:
        monkeypatch.chdir(tmp_path)
        candidate = Path(socket_path).name
    with pytest.raises(AuthorityError, match="dispatch_authority_already_held"):
        TargetAuthority(session_id, candidate)
    assert lease.held()
