"""Tests use a temporary replay ledger, never a user's real one."""
import pytest


@pytest.fixture(autouse=True)
def isolated_presence_nonces(tmp_path, monkeypatch):
    monkeypatch.setenv("CHANNEL_PRESENCE_NONCES", str(tmp_path / "presence-nonces.json"))
