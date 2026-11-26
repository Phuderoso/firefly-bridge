"""Backward-compatible exports and RC4 version in fresh import orders."""

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "import firefly_bridge.daemon\n",
        "import firefly_bridge.bridge\n",
        "import firefly_bridge.config\n",
    ],
)
def test_public_exports_in_fresh_process_have_no_import_cycle(prefix):
    script = (
        prefix
        + """
import firefly_bridge
from firefly_bridge import Bridge, Receipt
from firefly_bridge.bridge import Bridge as InternalBridge
from firefly_bridge.messages import Receipt as InternalReceipt
assert Bridge is InternalBridge and Receipt is InternalReceipt
assert {"Bridge", "Receipt", "__version__"} <= set(firefly_bridge.__all__)
assert {"Bridge", "Receipt"} <= set(dir(firefly_bridge))
assert firefly_bridge.__version__ == "0.4.0rc1"
try:
    firefly_bridge.nonexistent_export
except AttributeError:
    pass
else:
    raise AssertionError("unknown export unexpectedly resolved")
"""
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()


def test_rc4_runtime_and_project_version():
    from firefly_bridge import __version__

    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    assert __version__ == project["project"]["version"] == "0.4.0rc1"
