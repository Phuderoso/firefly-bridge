"""Read-only Mac preflight and the static gate report.

`grok sessions search` is excluded: the user guide says it combines a local
index with remote results. Session transcript files under ~/.grok are not read.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable

from firefly_bridge.contract import CITATIONS, RETRIEVED, live_blockers

ALLOWLIST = (
    ("grok", "version"),
    ("grok", "leader", "list", "--help"),
    ("grok", "leader", "list", "--json"),
    ("grok", "sessions", "list", "--limit", "50"),
)

SECRET_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "api_key",
    "apikey",
    "api-key",
    "cookie",
    "bearer",
    "credential",
)


class PreflightRefused(RuntimeError):
    pass


def contract_report() -> dict:
    blockers = live_blockers()
    return {
        "retrieved": RETRIEVED,
        "live_send_allowed": False,
        "send_authorized_by_passing_gates": False,
        "noninterruption_guaranteed": False,
        "disk_load_is_live_attachment": False,
        "busy_query_documented": False,
        "composer_preservation_documented": False,
        "agent_speaker_documented": False,
        "live_transport": "disabled",
        "blockers": blockers,
        "citations": [{"id": c["id"], "url": c["url"], "anchor": c["anchor"]} for c in CITATIONS],
        "gates": _gates({}),
        "next_step": (
            "Notify the user. Do not send. Optional next action is the "
            "read-only Mac preflight. It cannot open this gate."
        ),
    }


def mac_plan() -> dict:
    return {
        "executed_on_this_machine": False,
        "live_send_allowed": False,
        "requires_both": ["AGENT_PREFLIGHT_EXECUTE=1", "--execute"],
        "commands_in_order": [" ".join(argv) for argv in ALLOWLIST],
        "skipped": [
            "grok agent stdio",
            "grok -p",
            "grok --resume",
            "grok --continue",
            "grok sessions search",
            "grok sessions delete",
            "grok leader kill",
            "grok usage",
            "any read of ~/.grok/sessions or auth files",
        ],
        "user_env": {
            "PINNED_SESSION_ID": "Exact session id. If unset, sessions list is skipped.",
            "AGENT_SESSION_CWD": (
                "Absolute workspace directory of that session. Refused when a path "
                "segment is .grok. If unset or unsafe, session presence stays unknown."
            ),
        },
        "how_to_read_results": (
            "leader_count is only the length of a JSON list from grok leader list "
            "--json, and only after that command's own --help prints --json. "
            "The vendor CLI reference retrieved with these docs does not document "
            "the subcommand. An empty list means this output discovered no leader. "
            "It does not mean attachment is impossible, and a non-empty list does "
            "not mean a prompt may be sent. pinned_session_id_seen is a boolean "
            "substring check. Summaries are discarded. Neither observation makes "
            "disk load into live attachment, and neither proves the turn is idle."
        ),
        "when_a_live_test_could_proceed": (
            "Only after a vendor document states all of: a second client attaches "
            "to the same running in-memory session; a prompt is queued behind an "
            "active human turn and cannot steer or cancel it; the TUI draft buffer "
            "is left untouched; and a speaker identity other than the user prompt "
            "exists. A new build would still have to enable the transport. Leader "
            "presence and a visible session id are not sufficient."
        ),
        "when_a_coordinated_restart_would_be_required": (
            "If a future design needs peerb restarted, use_leader flipped, or a new "
            "agent process, that is a coordinated change. This preflight does not "
            "do it, and a restart would still not supply the missing semantics."
        ),
    }


def evaluate_observation(observation: dict) -> dict:
    """Apply gates to an observation. Ignores any caller-supplied live_send_allowed."""

    obs = _sanitize_observation(observation)
    report = {
        "retrieved": RETRIEVED,
        "observation": obs,
        "live_send_allowed": False,
        "send_authorized_by_passing_gates": False,
        "noninterruption_guaranteed": False,
        "disk_load_is_live_attachment": False,
        "busy_query_documented": False,
        "leader_interpretation": _leader_interpretation(obs),
        "session_interpretation": _session_interpretation(obs),
        "gates": _gates(obs),
        "coordinated_restart_performed": False,
        "send_remains_blocked_because": (
            "Non-interruption is not guaranteed by the retrieved contract. "
            "session/load remains a history replay. This report does not authorize a send."
        ),
    }
    return report


def execute_readonly(
    *,
    pinned_session_id: str | None,
    session_cwd: str | None,
    runner: Callable | None = None,
    env_execute: str | None = None,
) -> dict:
    if env_execute != "1":
        raise PreflightRefused("AGENT_PREFLIGHT_EXECUTE=1 is required")
    run = runner or _subprocess_runner
    observation: dict = {
        "grok_found": False,
        "commands": [],
        "leader_list_ran": False,
        "sessions_list_ran": False,
        "pinned_session_id_provided": bool(pinned_session_id),
        "pinned_session_id_seen": None,
        "session_cwd_refused": False,
        "secrets_redacted": False,
    }
    try:
        version = run(("grok", "version"), cwd=None)
    except FileNotFoundError:
        observation["grok_found"] = False
        observation["grok_missing"] = True
        return evaluate_observation(observation)

    observation["grok_found"] = True
    observation["commands"].append("grok version")
    observation["grok_version"] = _safe_version(version.stdout)
    observation["version_exit"] = version.returncode
    observation["version_stderr_bytes"] = len(version.stderr or b"")

    help_run = run(("grok", "leader", "list", "--help"), cwd=None)
    observation["commands"].append("grok leader list --help")
    help_text = (help_run.stdout or b"").decode("utf-8", "replace")
    documents_json = help_run.returncode == 0 and "--json" in help_text
    observation["leader_help_documents_json"] = documents_json
    observation["leader_help_exit"] = help_run.returncode
    if documents_json:
        listed = run(("grok", "leader", "list", "--json"), cwd=None)
        observation["commands"].append("grok leader list --json")
        observation["leader_list_ran"] = True
        summary = _summarize_leader(listed.stdout)
        observation.update(summary)
    else:
        observation["leader_interpretation_hint"] = "help_did_not_document_json_so_list_was_not_run"

    cwd, refused = _safe_cwd(session_cwd)
    if pinned_session_id and cwd:
        listed = run(("grok", "sessions", "list", "--limit", "50"), cwd=cwd)
        observation["commands"].append("grok sessions list --limit 50")
        observation["sessions_list_ran"] = True
        observation["sessions_list_exit"] = listed.returncode
        body = (listed.stdout or b"").decode("utf-8", "replace")
        observation["pinned_session_id_seen"] = pinned_session_id in body
        observation["sessions_stdout_bytes"] = len(body.encode("utf-8"))
        if _looks_secret(body):
            observation["secrets_redacted"] = True
    else:
        observation["session_cwd_refused"] = refused
        observation["pinned_session_id_seen"] = None
        if pinned_session_id and not cwd:
            observation["session_skipped"] = "cwd_missing_or_unsafe"
        elif not pinned_session_id:
            observation["session_skipped"] = "session_id_not_pinned"

    return evaluate_observation(observation)


def _gates(obs: dict) -> list[dict]:
    return [
        {
            "id": "contract_attach",
            "pass": False,
            "detail": "Vendor text does not say a second client joins the running TUI session.",
        },
        {
            "id": "noninterruption",
            "pass": False,
            "detail": "No documented busy query or non-steering queue. Do not send.",
        },
        {
            "id": "composer",
            "pass": False,
            "detail": "Draft-buffer preservation is not documented.",
        },
        {
            "id": "speaker",
            "pass": False,
            "detail": "agent-a is not a documented ACP speaker. Receipt attribution only.",
        },
        {
            "id": "not_disk_load",
            "pass": False,
            "detail": "The documented existing-session ACP method is session/load, which replays history.",
        },
        {
            "id": "leader_observed",
            "pass": False,
            "informational": True,
            "detail": _leader_interpretation(obs),
        },
        {
            "id": "session_pinned_seen",
            "pass": False,
            "informational": True,
            "detail": _session_interpretation(obs),
        },
        {
            "id": "no_restart",
            "pass": True,
            "detail": "This preflight does not restart peerb or edit config. A restart would be a separate coordinated change and still would not open the send gate.",
        },
    ]


def _sanitize_observation(observation: dict) -> dict:
    allowed_cmds = {" ".join(argv) for argv in ALLOWLIST}
    clean: dict = {}
    if not isinstance(observation, dict):
        return clean
    for key, value in observation.items():
        if key in {
            "live_send_allowed",
            "noninterruption_guaranteed",
            "stdout",
            "stderr",
            "raw",
            "sessions_raw",
            "leader_raw",
            "summary",
            "text",
        }:
            continue
        if key == "commands" and isinstance(value, list):
            clean["commands"] = [item for item in value if item in allowed_cmds]
            continue
        if key == "grok_version" and isinstance(value, str):
            clean["grok_version"] = "redacted" if _looks_secret(value) else value[:120]
            continue
        if isinstance(value, (dict, list)):
            continue
        if isinstance(value, str) and len(value) > 180:
            continue
        clean[key] = value
    return clean


def _leader_interpretation(obs: dict) -> str:
    if not obs or not obs.get("leader_list_ran"):
        return (
            "leader_availability_unknown. grok leader list is not in the retrieved "
            "CLI reference. The list command runs only when its own --help prints --json."
        )
    count = obs.get("leader_count")
    if count == 0:
        return (
            "no_leader_in_this_output. Same shape as an earlier empty list: nothing "
            "discovered in this output, not impossibility, and not proof the TUI is isolated."
        )
    if isinstance(count, int) and count > 0:
        return (
            "leader_process_listed. This is not session attachment, not an idle flag, "
            "and not permission to prompt."
        )
    return "leader_output_unparsed. Availability stays unknown."


def _session_interpretation(obs: dict) -> str:
    if not obs or not obs.get("sessions_list_ran"):
        why = obs.get("session_skipped") if obs else None
        return (
            "session_presence_unknown"
            + (f" ({why})" if why else "")
            + ". Missing from this list is not absence. The list is per working directory."
        )
    if obs.get("pinned_session_id_seen") is True:
        return (
            "pinned id appeared in grok sessions list output for the given cwd. "
            "That is index visibility, not a live attach, and the summary text was discarded."
        )
    return (
        "pinned id did not appear in this directory's list output. "
        "Do not fall back to the most recent session or to session/new."
    )


def _summarize_leader(raw: bytes) -> dict:
    text = raw.decode("utf-8", "replace")
    secret = _looks_secret(text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {
            "leader_count": None,
            "leader_json_shape": "unparsed",
            "secrets_redacted": secret,
        }
    if isinstance(data, list):
        return {
            "leader_count": len(data),
            "leader_json_shape": "list",
            "secrets_redacted": secret or _tree_has_secret(data),
        }
    return {
        "leader_count": None,
        "leader_json_shape": type(data).__name__,
        "secrets_redacted": True,
    }


def _tree_has_secret(node) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            if any(mark in str(key).lower() for mark in SECRET_MARKERS):
                return True
            if _tree_has_secret(value):
                return True
        return False
    if isinstance(node, list):
        return any(_tree_has_secret(item) for item in node)
    return False


def _looks_secret(text: str) -> bool:
    lowered = text.lower()
    return any(mark in lowered for mark in ("bearer ", "api_key", "api-key", "xai-"))


def _safe_version(raw: bytes) -> str:
    line = raw.decode("utf-8", "replace").splitlines()
    text = line[0].strip() if line else ""
    if _looks_secret(text):
        return "redacted"
    return text[:120]


def _safe_cwd(session_cwd: str | None) -> tuple[str | None, bool]:
    if not session_cwd:
        return None, False
    if not os.path.isabs(session_cwd):
        return None, True
    real = os.path.realpath(session_cwd)
    parts = [part for part in real.split(os.sep) if part]
    if ".grok" in parts:
        return None, True
    if not os.path.isdir(real):
        return None, True
    return real, False


class _Completed:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _subprocess_runner(argv: tuple[str, ...], cwd: str | None) -> _Completed:
    if argv not in ALLOWLIST:
        raise PreflightRefused("argv_not_allowlisted")
    try:
        completed = subprocess.run(
            list(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return _Completed(124, exc.stdout or b"", exc.stderr or b"")
    except FileNotFoundError:
        raise
    return _Completed(completed.returncode, completed.stdout or b"", completed.stderr or b"")
