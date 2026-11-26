"""Regression tests for issue #19: load_key must check and read the same open file.

The swap hook below replaces the key path with a symlink to a different, world-readable
file right after the first metadata call (stat, lstat or fstat). A loader that checks
metadata by path and then re-opens the path reads the swapped file; a loader that opens
once and checks/reads that descriptor keeps reading the original file.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from firefly_bridge import envelope, speaker

GOOD_HEX = "11" * 32
EVIL_HEX = "ee" * 32


def _install_swap(monkeypatch: pytest.MonkeyPatch, target: Path, evil: Path) -> dict:
    state = {"swapped": False}
    real = {"stat": os.stat, "lstat": os.lstat, "fstat": os.fstat}

    def swap() -> None:
        if state["swapped"]:
            return
        state["swapped"] = True
        tmp = target.with_name(target.name + ".swap")
        os.symlink(evil, tmp)
        os.replace(tmp, target)

    def make(name: str):
        def hooked(path, *args, **kwargs):
            result = real[name](path, *args, **kwargs)
            if name == "fstat" or os.fspath(path) == os.fspath(target):
                swap()
            return result

        return hooked

    for name in real:
        monkeypatch.setattr(os, name, make(name))
    return state


def _files(tmp_path: Path, content: str) -> tuple[Path, Path]:
    target = tmp_path / "k.key"
    target.write_text(content)
    os.chmod(target, 0o600)
    evil = tmp_path / "other.key"
    evil.write_text(content.replace(GOOD_HEX, EVIL_HEX))
    os.chmod(evil, 0o644)
    return target, evil


def test_speaker_load_key_reads_the_checked_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, evil = _files(tmp_path, GOOD_HEX + "\n")
    state = _install_swap(monkeypatch, target, evil)
    try:
        key = speaker.load_key(target)
    except speaker.KeyFileError:
        key = None
    assert state["swapped"]
    assert key in (None, bytes.fromhex(GOOD_HEX)), (
        "read a file other than the one whose metadata was checked"
    )


def test_envelope_load_key_reads_the_checked_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, evil = _files(tmp_path, GOOD_HEX + "\n")
    state = _install_swap(monkeypatch, target, evil)
    try:
        key = envelope.load_key(target)
    except envelope.KeyFileError:
        key = None
    assert state["swapped"]
    assert key in (None, GOOD_HEX.encode()), (
        "read a file other than the one whose metadata was checked"
    )


@pytest.mark.parametrize("loader", [speaker.load_key, envelope.load_key])
def test_symlinked_key_file_is_refused(tmp_path: Path, loader) -> None:
    real = tmp_path / "real.key"
    real.write_text(GOOD_HEX + "\n")
    os.chmod(real, 0o600)
    link = tmp_path / "link.key"
    link.symlink_to(real)
    with pytest.raises(
        (speaker.KeyFileError, envelope.KeyFileError), match="^key_file_not_regular"
    ):
        loader(link)


@pytest.mark.parametrize("loader", [speaker.load_key, envelope.load_key])
def test_fifo_key_file_is_refused_without_blocking(tmp_path: Path, loader) -> None:
    fifo = tmp_path / "fifo.key"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(
        (speaker.KeyFileError, envelope.KeyFileError), match="^key_file_not_regular"
    ):
        loader(fifo)


@pytest.mark.parametrize("loader", [speaker.load_key, envelope.load_key])
def test_missing_and_open_mode_still_refused(tmp_path: Path, loader) -> None:
    with pytest.raises((speaker.KeyFileError, envelope.KeyFileError), match="^key_file_missing"):
        loader(tmp_path / "nope.key")
    p = tmp_path / "open.key"
    p.write_text(GOOD_HEX + "\n")
    os.chmod(p, 0o644)
    with pytest.raises(
        (speaker.KeyFileError, envelope.KeyFileError), match="^key_file_(mode|permissions)_too_open"
    ):
        loader(p)


@pytest.mark.parametrize("loader", [speaker.load_key, envelope.load_key])
def test_good_key_loads(tmp_path: Path, loader) -> None:
    p = tmp_path / "ok.key"
    p.write_text(GOOD_HEX + "\n")
    os.chmod(p, 0o600)
    assert loader(p) in (bytes.fromhex(GOOD_HEX), GOOD_HEX.encode())


@pytest.mark.parametrize("loader", [speaker.load_key, envelope.load_key])
def test_oversize_key_file_is_refused_not_truncated(tmp_path: Path, loader) -> None:
    p = tmp_path / "big.key"
    p.write_text("11" * 2500)  # 5000 bytes > 4096
    os.chmod(p, 0o600)
    with pytest.raises((speaker.KeyFileError, envelope.KeyFileError), match="^key_file_too_large"):
        loader(p)


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores mode 000")
@pytest.mark.parametrize("loader", [speaker.load_key, envelope.load_key])
def test_unreadable_own_file_reports_unreadable(tmp_path: Path, loader) -> None:
    p = tmp_path / "zero.key"
    p.write_text(GOOD_HEX + "\n")
    os.chmod(p, 0o000)
    try:
        with pytest.raises(
            (speaker.KeyFileError, envelope.KeyFileError), match="^key_file_unreadable"
        ):
            loader(p)
    finally:
        os.chmod(p, 0o600)
