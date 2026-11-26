"""The suite must not leave anything behind in $TMPDIR.

Runs the modules that create temporary directories in a child pytest with an isolated, empty
TMPDIR (pytest's own tmp_path goes to a separate --basetemp) and asserts TMPDIR is empty after.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ["tests/test_bridge.py", "tests/test_refined.py", "tests/test_channel_keygen.py"]
CHILD = "FFB_TMP_HYGIENE_CHILD"


@pytest.mark.skipif(os.environ.get(CHILD) == "1", reason="child run")
def test_suite_leaves_tmpdir_empty() -> None:
    with tempfile.TemporaryDirectory(prefix="ffb-hygiene-") as outer:
        iso, basetemp = Path(outer) / "tmp", Path(outer) / "basetemp"
        iso.mkdir()
        env = dict(os.environ, TMPDIR=str(iso), PYTHONPATH=str(ROOT), **{CHILD: "1"})
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
                            f"--basetemp={basetemp}", *MODULES], cwd=ROOT, env=env,
                           capture_output=True, text=True, timeout=600)
        assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-3000:]
        assert sorted(x.name for x in iso.iterdir()) == []
