"""speaker.py must stay standalone (stdlib only): channel-gh can run with only
firefly_bridge/speaker.py copied next to it and the package NOT installed.

Python runs with -S (no site-packages, so no installed/editable firefly_bridge) from a temp
copy of the documented layout: <dir>/scripts/channel-gh + <dir>/firefly_bridge/speaker.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "config.example.toml"


def _layout(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "firefly_bridge").mkdir()
    shutil.copy2(ROOT / "scripts" / "channel-gh", tmp_path / "scripts" / "channel-gh")
    shutil.copy2(ROOT / "firefly_bridge" / "speaker.py", tmp_path / "firefly_bridge" / "speaker.py")
    return tmp_path / "scripts" / "channel-gh"


def _env(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env.update(HOME=str(tmp_path / "home"), FIREFLY_BRIDGE_CONFIG=str(EXAMPLE))
    env.pop("FIREFLY_BRIDGE_SPEAKER", None)
    return env


def test_package_not_importable_in_isolated_interpreter(tmp_path: Path) -> None:
    p = subprocess.run(
        [sys.executable, "-S", "-c", "import firefly_bridge"],
        cwd=tmp_path,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.returncode != 0  # the test below really runs without the package


def test_channel_gh_runs_with_standalone_speaker(tmp_path: Path) -> None:
    script = _layout(tmp_path)
    p = subprocess.run(
        [sys.executable, "-S", str(script), "roster"],
        cwd=tmp_path,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.returncode == 0, p.stderr[-2000:]
    assert "ModuleNotFoundError" not in p.stderr


def test_standalone_speaker_load_key(tmp_path: Path) -> None:
    _layout(tmp_path)
    key = tmp_path / "k.key"
    key.write_text("11" * 32 + "\n")
    os.chmod(key, 0o600)
    code = (
        "import importlib.util,sys;"
        f"s=importlib.util.spec_from_file_location('sp', {str(tmp_path / 'firefly_bridge' / 'speaker.py')!r});"
        "m=importlib.util.module_from_spec(s);sys.modules['sp']=m;s.loader.exec_module(m);"
        f"print(len(m.load_key({str(key)!r})))"
    )
    p = subprocess.run(
        [sys.executable, "-S", "-c", code],
        cwd=tmp_path,
        env=_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.returncode == 0, p.stderr[-2000:]
    assert p.stdout.strip() == "32"
