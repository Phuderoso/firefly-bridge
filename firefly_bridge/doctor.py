"""Read-only offline diagnostics; snapshots are not live scheduler evidence."""

import hashlib
import json
import stat
import time
from pathlib import Path

from firefly_bridge import __version__
from firefly_bridge.privacy import safe


def doctor(cfg):
    path = Path(cfg.state_dir) / "status.json"
    result = {
        "version": __version__,
        "mode": "read_only_local_snapshot",
        "requested_session_id": cfg.session_id,
        "remote_state": "unknown",
        "scheduler": {
            "state": "unknown",
            "expiry": "unknown",
            "seven_day_estimate": "unavailable_without_creation_time",
        },
        "permission_profiles": [
            {"sender": s, "permission_mode": cfg.permission_mode_for(s)}
            for s in cfg.agent_names()
        ],
        "turn_attestation": "experimental_not_live_validated",
    }
    if path.exists():
        try:
            age = time.time() - path.stat().st_mtime
            snapshot = json.loads(path.read_text())
            result["snapshot_age_s"] = age
            result["snapshot"] = snapshot
            result["remote_state"] = "unknown"  # doctor never claims live verification
        except (ValueError, OSError):
            result["snapshot"] = "unavailable"
    socket = Path(cfg.socket_path) if cfg.socket_path else None
    if socket and socket.exists():
        info = socket.lstat()
        result["leader_socket"] = {
            "is_socket": stat.S_ISSOCK(info.st_mode),
            "mode": oct(stat.S_IMODE(info.st_mode)),
        }
    else:
        result["leader_socket"] = "missing_or_not_configured"
    digest = hashlib.sha256()
    for source in sorted(Path(__file__).parent.glob("*.py")):
        digest.update(source.name.encode())
        digest.update(source.read_bytes())
    result["source_sha256"] = digest.hexdigest()
    return safe(result)
