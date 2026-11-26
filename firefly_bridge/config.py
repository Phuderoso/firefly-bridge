"""Daemon configuration: TOML file plus FIREFLY_BRIDGE_* environment overrides.

Nothing here is user-specific. Every path is expanded at load time
(``~`` and ``$VARS``), so example configs only ever contain placeholders.

Lookup order (later wins):
1. built-in defaults
2. TOML file: ``--config PATH`` or ``$FIREFLY_BRIDGE_CONFIG`` or
   ``$XDG_CONFIG_HOME/firefly-bridge/config.toml`` (if it exists)
3. environment variables ``FIREFLY_BRIDGE_<FIELD>`` (upper-case field name)
"""

from __future__ import annotations

import ast
import math
import os
import re
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None  # type: ignore[assignment]

from firefly_bridge.messages import validate_session_id


def parse_toml_text(text: str) -> dict:
    """Parse TOML using stdlib tomllib (3.11+) or a safe flat-subset parser on 3.9/3.10."""
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError("toml_decode_error") from exc
    root: dict = {}
    current = root
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            sec = line[1:-1].strip()
            if not sec or any(c.isspace() for c in sec):
                raise ValueError("toml_decode_error")
            current = root.setdefault(sec, {})
            continue
        if "=" not in line:
            raise ValueError("toml_decode_error")
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key or not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise ValueError("toml_decode_error")
        # Strip trailing comment outside quotes/brackets
        in_str = None
        for idx, ch in enumerate(val):
            if ch in ('"', "'") and (idx == 0 or val[idx - 1] != "\\"):
                if in_str == ch:
                    in_str = None
                elif in_str is None:
                    in_str = ch
            elif ch == "#" and in_str is None:
                val = val[:idx].strip()
                break
        low = val.lower()
        if low in ("true", "false"):
            current[key] = low == "true"
        elif low in ("nan", "+nan", "-nan"):
            current[key] = float("nan")
        elif low in ("inf", "+inf"):
            current[key] = float("inf")
        elif low == "-inf":
            current[key] = float("-inf")
        else:
            try:
                parsed = ast.literal_eval(val)
            except Exception as exc:
                raise ValueError("toml_decode_error") from exc
            if not isinstance(parsed, (str, int, float, list)):
                raise ValueError("toml_decode_error")
            current[key] = parsed
    return root

ENV_PREFIX = "FIREFLY_BRIDGE_"
AUTH_MODES = ("prefix", "hmac")
PERMISSION_MODES = (
    "pending",
    "allowlist",
    "allowlist_shared",
    "allow_all",
    "allow_all_own_turns",
)
BUSY_POLICIES = ("wait", "fail")
ADAPTER_MODES = ("attested", "stock_grok")


class ConfigError(ValueError):
    pass


def _default_state_dir() -> str:
    base = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return str(Path(base).expanduser() / "firefly-bridge")


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "firefly-bridge" / "config.toml"


@dataclass
class BridgeConfig:
    # --- target -----------------------------------------------------------
    socket_path: str = ""  # leader socket of the target grok-tui, e.g. ~/.grok/leader-<name>.sock
    session_id: str = ""  # the target session id (pinned; never "latest")
    session_cwd: str = ""  # cwd passed to session/load; defaults to the daemon cwd
    grok_bin: str = "grok"  # resolved through PATH unless absolute
    # --- identity ---------------------------------------------------------
    sender: str = "agent-a"
    prefix: str = "agent-a: "
    auth_mode: str = "prefix"  # "prefix" (compat) or "hmac" (prefix + signed trailer)
    hmac_key_file: str = ""  # required when auth_mode == "hmac"; must be mode 0600
    # --- timeouts (seconds) ------------------------------------------------
    connect_timeout_s: float = 30.0  # initialize
    load_timeout_s: float = 120.0  # session/load (history replay can be large)
    turn_timeout_s: float = 600.0  # observation timeout; NEVER auto-cancel
    cancel_grace_s: float = 15.0  # wait for stopReason=cancelled after session/cancel
    busy_wait_s: float = 1800.0  # how long an outbox message may wait for a free slot
    busy_policy: str = "wait"  # "wait" (up to busy_wait_s) or "fail" (immediately)
    max_outbox: int = 3  # enqueue refuses beyond this many waiting messages
    poll_interval_s: float = 0.5
    # --- safety gates -------------------------------------------------------
    live_send: bool = False  # MUST be explicitly enabled; otherwise receipts say live_send_disabled
    strip_grok_sandbox: bool = False  # opt-in only, see THREAT_MODEL.md
    # --- permissions for bridge-started turns ---------------------------------
    permission_mode: str = "pending"  # deprecated global setting: non-pending is rejected
    # Placeholder agents. Replace the list in config; unknown agents stay pending.
    agents: list[str] = field(default_factory=lambda: ["agent-a", "agent-b", "agent-c"])
    agent_a_permission_mode: str = "pending"
    agent_b_permission_mode: str = "pending"
    agent_c_permission_mode: str = "pending"
    permission_mode_overrides: dict[str, str] = field(default_factory=dict)
    protected_tools_enabled: bool = True  # hard gate before ANY mode; explicit opt-out only
    shared_dir: str = "shared/"  # allowlist root; relative paths resolve against session_cwd
    allowed_tool_kinds: list[str] = field(default_factory=lambda: ["edit"])
    # --- local state --------------------------------------------------------
    state_dir: str = field(default_factory=_default_state_dir)
    config_path: str = ""  # load_config records the actual source; embedding may supply it

    # IPC credentials are independent from optional outbound signatures.
    ipc_keys_dir: str = ""  # <principal>.key, all different, mode 0600
    ipc_key_file: str = ""  # client only
    ipc_principal: str = "agent-a"
    per_sender_pending: int = 1
    per_sender_daily_quota: int = 3
    sender_interval_s: float = 1800.0
    global_interval_s: float = 0.0  # legacy name: now an additional PER-SENDER floor
    pacing_minimums_enabled: bool = True  # explicit opt-out required below 60/600 seconds
    post_turn_interval_s: float = 60.0  # after ANY confirmed terminal, for all senders
    target_interval_s: float = 600.0  # real target-wide floor between dispatch starts
    quiet_hours_start: str = ""  # HH:MM; both empty disables quiet hours
    quiet_hours_end: str = ""
    quiet_hours_timezone: str = "UTC"
    admission_max_age_s: float = 5.0
    max_body_bytes: int = 32000
    max_reply_bytes: int = 64000
    max_queue_bytes: int = 96000
    max_frame_bytes: int = 8388608
    skip_oversized_frames: bool = True
    # --- unified stock-leader / wake integration (RC9) -----------------------
    adapter_mode: str = "attested"  # "attested" (strict default) or "stock_grok"
    wake_dir: str = ""  # writes reply files and the wake file when set
    wake_filename: str = "WAKE.md"
    reply_prefix: str = "reply_"
    inbound_dir: str = "memory/shared/inbound"
    relay_principal: str = "agent-a"
    updates_jsonl_path: str = ""  # optional fallback/watcher path for stock_grok
    hold_pid_file: str = ""  # external hold pid file (standalone channel fallback)
    approvals_log_path: str = ""  # external approvals log path
    ledger_path: str = ""  # legacy JSON ledger path for standalone fallback
    answer_permissions: bool = False  # standalone channel fallback flag

    def protected_resources(self) -> dict:
        """Known broker resources, not content inspection or guessed secret names.

        Resource paths follow the daemon process cwd; requested file paths follow
        session_cwd. Keep both lexical and real identities in the gate.
        """

        def absolute(value):
            expanded = os.path.expandvars(os.path.expanduser(value))
            return expanded if os.path.isabs(expanded) else os.path.join(os.getcwd(), expanded)

        directories = (
            self.ipc_keys_dir,
            self.state_dir,
            str(default_config_path().parent),
            os.path.join(os.getcwd(), ".agent"),
        )
        files = (
            self.hmac_key_file,
            self.ipc_key_file,
            self.config_path,
            str(default_config_path()),
        )
        return {
            "protected_dirs": tuple(absolute(v) for v in directories if v),
            "protected_files": tuple(absolute(v) for v in files if v),
        }

    def agent_names(self) -> tuple[str, ...]:
        """Configured agent ids. Defaults are placeholders, not a fixed deployment."""
        raw = self.agents or ["agent-a", "agent-b", "agent-c"]
        names: list[str] = []
        for item in raw:
            name = str(item).strip()
            if name in {"human", "recipient"} or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name):
                raise ConfigError("agent_name_invalid")
            if name not in names:
                names.append(name)
        if not names:
            raise ConfigError("agents_required")
        return tuple(names)

    def permission_mode_for(self, sender: str) -> str:
        if sender not in self.agent_names():
            raise ConfigError("sender_invalid_or_reserved")
        slots = {
            "agent-a": self.agent_a_permission_mode,
            "agent-b": self.agent_b_permission_mode,
            "agent-c": self.agent_c_permission_mode,
        }
        mode = slots.get(sender)
        if mode is None:
            overrides = self.permission_mode_overrides or {}
            mode = str(overrides.get(sender, "pending"))
        if mode not in PERMISSION_MODES:
            raise ConfigError("permission_mode_invalid")
        return mode

    @property
    def applicable_cooldown_s(self) -> float:
        # Never couple agent-a's dispatch time to agent-b/agent-c. State is target-bound.
        return max(self.sender_interval_s, self.global_interval_s)

    def quiet_now(self, epoch: float) -> bool:
        if not self.quiet_hours_start:
            return False
        now = datetime.fromtimestamp(epoch, ZoneInfo(self.quiet_hours_timezone))
        minute = now.hour * 60 + now.minute

        def minutes(value):
            h, m = map(int, value.split(":"))
            return h * 60 + m

        start, end = minutes(self.quiet_hours_start), minutes(self.quiet_hours_end)
        return start <= minute < end if start < end else minute >= start or minute < end

    # ------------------------------------------------------------------
    def resolved(self, env: dict | None = None) -> BridgeConfig:
        env_map = os.environ if env is None else env
        home_override = env_map.get("HOME")

        def expand(val: str) -> str:
            if home_override and (val == "~" or val.startswith("~/")):
                val = home_override.rstrip("/") + val[1:]
            else:
                val = os.path.expanduser(val)
            return os.path.expandvars(val)

        out = BridgeConfig(**asdict(self))
        for name in (
            "socket_path",
            "session_cwd",
            "hmac_key_file",
            "state_dir",
            "config_path",
            "ipc_keys_dir",
            "ipc_key_file",
            "wake_dir",
            "updates_jsonl_path",
            "hold_pid_file",
            "approvals_log_path",
            "ledger_path",
        ):
            value = getattr(out, name)
            if value:
                setattr(out, name, expand(value))
        if out.grok_bin and ("/" in out.grok_bin or out.grok_bin.startswith("~")):
            out.grok_bin = expand(out.grok_bin)
        if out.shared_dir:
            out.shared_dir = expand(out.shared_dir)
        return out

    def validate(self, *, require_target: bool = True) -> BridgeConfig:
        if require_target:
            if not self.socket_path:
                raise ConfigError("socket_path_required")
            validate_session_id(self.session_id or None)
        if self.auth_mode not in AUTH_MODES:
            raise ConfigError("auth_mode_invalid")
        if self.auth_mode == "hmac" and not self.hmac_key_file:
            raise ConfigError("hmac_key_file_required")
        if type(self.protected_tools_enabled) is not bool:
            raise ConfigError("protected_tools_enabled_not_bool")
        if type(self.skip_oversized_frames) is not bool:
            raise ConfigError("skip_oversized_frames_not_bool")
        if type(self.answer_permissions) is not bool:
            raise ConfigError("answer_permissions_not_bool")
        if self.adapter_mode not in ADAPTER_MODES:
            raise ConfigError("adapter_mode_invalid")
        if type(self.max_frame_bytes) is not int or not 131072 <= self.max_frame_bytes <= 16777216:
            raise ConfigError("max_frame_bytes_out_of_bounds")
        if self.permission_mode != "pending":
            raise ConfigError("global_permission_mode_removed_use_per_sender_policy")
        for sender in self.agent_names():
            if self.permission_mode_for(sender) not in PERMISSION_MODES:
                raise ConfigError("permission_mode_invalid")
        if self.busy_policy not in BUSY_POLICIES:
            raise ConfigError("busy_policy_invalid")
        if self.sender not in self.agent_names():
            raise ConfigError("sender_invalid_or_reserved")
        if self.prefix != self.sender + ": ":
            raise ConfigError("prefix_must_match_sender")
        if self.ipc_principal not in (*self.agent_names(), "human", "recipient"):
            raise ConfigError("ipc_principal_invalid")
        for name in (
            "per_sender_pending",
            "per_sender_daily_quota",
            "max_body_bytes",
            "max_reply_bytes",
            "max_queue_bytes",
        ):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= 1000000:
                raise ConfigError(f"{name}_out_of_bounds")
        for name in (
            "sender_interval_s",
            "global_interval_s",
            "post_turn_interval_s",
            "target_interval_s",
        ):
            if (
                type(getattr(self, name)) not in (int, float)
                or not math.isfinite(getattr(self, name))
                or not 0 <= getattr(self, name) <= 86400
            ):
                raise ConfigError(f"{name}_out_of_bounds")
        if type(self.pacing_minimums_enabled) is not bool:
            raise ConfigError("pacing_minimums_enabled_not_bool")
        if self.pacing_minimums_enabled and (
            self.post_turn_interval_s < 60 or self.target_interval_s < 600
        ):
            raise ConfigError("pacing_below_minimum_requires_explicit_optout")
        if not isinstance(self.quiet_hours_timezone, str):
            raise ConfigError("quiet_hours_timezone_invalid")
        try:
            ZoneInfo(self.quiet_hours_timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ConfigError("quiet_hours_timezone_invalid") from None
        values = (self.quiet_hours_start, self.quiet_hours_end)
        if values != ("", ""):
            if (
                any(
                    not isinstance(v, str)
                    or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", v)
                    for v in values
                )
                or values[0] == values[1]
            ):
                raise ConfigError("quiet_hours_range_invalid")
        if (
            type(self.admission_max_age_s) not in (int, float)
            or not math.isfinite(self.admission_max_age_s)
            or not 0 < self.admission_max_age_s <= 30
        ):
            raise ConfigError("admission_max_age_s_out_of_bounds")
        for name in (
            "connect_timeout_s",
            "load_timeout_s",
            "turn_timeout_s",
            "cancel_grace_s",
            "poll_interval_s",
        ):
            value = getattr(self, name)
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value <= 0
                or value > 86400
            ):
                raise ConfigError(f"{name}_out_of_bounds")
        if (
            type(self.busy_wait_s) not in (int, float)
            or not math.isfinite(self.busy_wait_s)
            or self.busy_wait_s < 0
            or self.busy_wait_s > 86400
        ):
            raise ConfigError("busy_wait_s_out_of_bounds")
        if self.busy_wait_s < max(
            self.applicable_cooldown_s, self.post_turn_interval_s, self.target_interval_s
        ):
            raise ConfigError("busy_wait_s_must_cover_cooldowns")
        if not isinstance(self.max_outbox, int) or not 0 <= self.max_outbox <= 1000:
            raise ConfigError("max_outbox_out_of_bounds")
        if any(
            self.permission_mode_for(s) in ("allowlist", "allowlist_shared")
            for s in self.agent_names()
        ):
            if not self.shared_dir:
                raise ConfigError("shared_dir_required_for_allowlist")
            bad = set(self.allowed_tool_kinds) - {"edit"}
            if bad:
                # Only file edits inside shared_dir may ever be auto-approved.
                raise ConfigError("only_edit_kind_may_be_allowlisted")
        return self

    def public_dict(self) -> dict:
        """Config as JSON-safe dict. Contains paths, never key material."""
        return asdict(self)


def _coerce(name: str, raw, target_type):
    # dataclasses.fields().type is a string under from __future__ import annotations.
    label = (
        target_type
        if isinstance(target_type, str)
        else getattr(target_type, "__name__", str(target_type))
    )
    origin = getattr(target_type, "__origin__", None)
    if label in {"bool", "bool | None"} or target_type is bool:
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off", ""}:
            return False
        raise ConfigError(f"{name}_not_bool")
    if label == "int" or target_type is int:
        try:
            return int(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{name}_not_int") from exc
    if label == "float" or target_type is float:
        try:
            return float(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{name}_not_number") from exc
    if label.startswith("list") or origin is list or target_type is list:
        if isinstance(raw, list):
            return [str(x) for x in raw]
        return [part.strip() for part in str(raw).split(",") if part.strip()]
    if label.startswith("dict") or origin is dict or target_type is dict:
        if not isinstance(raw, dict):
            raise ConfigError(f"{name}_not_map")
        return {str(key): str(value) for key, value in raw.items()}
    return str(raw)


def load_config(
    path: str | Path | None = None,
    env: dict | None = None,
    *,
    require_target: bool = True,
) -> BridgeConfig:
    env = dict(os.environ if env is None else env)
    data: dict = {}
    explicit = path or env.get(ENV_PREFIX + "CONFIG")
    candidate = Path(explicit).expanduser() if explicit else default_config_path()
    if explicit and not candidate.exists():
        raise ConfigError("config_file_not_found")
    if candidate.exists():
        try:
            data = parse_toml_text(candidate.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ConfigError("config_toml_invalid") from exc
        raw = data
        flat = {k: v for k, v in raw.items() if not isinstance(v, dict)}
        bridge_sec = raw.get("bridge") if isinstance(raw.get("bridge"), dict) else {}
        tel_sec = raw.get("channel") if isinstance(raw.get("channel"), dict) else {}
        merged: dict = {}
        for sec in (flat, tel_sec, bridge_sec):
            merged.update(sec)
        data = merged
    known = {f.name: f for f in fields(BridgeConfig)}
    unknown = set(data) - set(known)
    if unknown:
        raise ConfigError("unknown_config_keys:" + ",".join(sorted(unknown)))
    values: dict = {}
    for name, value in data.items():
        values[name] = _coerce(name, value, known[name].type)
    for name, f in known.items():
        key = ENV_PREFIX + name.upper()
        if key in env:
            values[name] = _coerce(name, env[key], f.type)
    # The loaded source cannot be concealed by a config/env field claiming a
    # different file. No credential content is read by the tool gate.
    values["config_path"] = str(candidate.absolute())
    cfg = BridgeConfig(**values).resolved(env=env)
    return cfg.validate(require_target=require_target)
