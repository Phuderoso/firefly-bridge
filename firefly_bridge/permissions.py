"""Permission policy. Ownership/consent are checked by the broker first.

pending never approves/rejects, including on timeout. allowlist is a legacy
alias for allowlist_shared. No mode ever chooses allow_always.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field

from firefly_bridge.protected import protected_reason

PATH_KEYS = (
    "path",
    "file_path",
    "filePath",
    "target_file",
    "targetFile",
    "abs_path",
    "absPath",
    "source",
    "destination",
    "source_path",
    "destination_path",
    "from",
    "to",
)


@dataclass
class PermissionDecision:
    action: str  # "ignore" | "pending" | "approve" | "deny"
    reason: str
    option_id: str | None = None
    paths: list[str] = field(default_factory=list)
    tool_kind: str | None = None
    title: str | None = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "option_id": self.option_id,
            "paths": list(self.paths),
            "tool_kind": self.tool_kind,
            "title": self.title,
        }


def _params(request: dict) -> dict:
    params = request.get("params")
    return params if isinstance(params, dict) else {}


def extract_paths(tool_call: dict) -> list[str]:
    found: list[str] = []
    locations = tool_call.get("locations")
    if isinstance(locations, list):
        for loc in locations:
            if isinstance(loc, dict) and isinstance(loc.get("path"), str):
                found.append(loc["path"])
    raw = tool_call.get("rawInput")
    if isinstance(raw, dict):
        for key in PATH_KEYS:
            if isinstance(raw.get(key), str):
                found.append(raw[key])
        # Multi-file edit shapes
        for key in ("paths", "files", "edits"):
            items = raw.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        found.append(item)
                    elif isinstance(item, dict):
                        for pk in PATH_KEYS:
                            if isinstance(item.get(pk), str):
                                found.append(item[pk])
    # de-dup, keep order
    out: list[str] = []
    for p in found:
        if p not in out:
            out.append(p)
    return out


def denied_decision(request: dict, reason: str) -> PermissionDecision:
    params = _params(request)
    tool = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
    options = params.get("options") if isinstance(params.get("options"), list) else []
    reject = next(
        (
            o.get("optionId")
            for o in options
            if isinstance(o, dict)
            and o.get("kind") == "reject_once"
            and isinstance(o.get("optionId"), str)
        ),
        None,
    )
    return PermissionDecision(
        "deny",
        reason,
        option_id=reject,
        paths=extract_paths(tool),
        tool_kind=tool.get("kind"),
        title=tool.get("title"),
    )


def path_inside(path: str, root: str, base: str) -> bool:
    """True if ``path`` (relative to ``base``) resolves strictly inside ``root``."""
    if not path or "\x00" in path:
        return False
    root_abs = os.path.realpath(root if os.path.isabs(root) else os.path.join(base, root))
    cand = path if os.path.isabs(path) else os.path.join(base, path)
    cand_abs = os.path.realpath(cand)
    try:
        common = os.path.commonpath([root_abs, cand_abs])
    except ValueError:
        return False
    return common == root_abs and cand_abs != root_abs


class PermissionPolicy:
    def __init__(
        self,
        mode: str = "pending",
        shared_dir: str = "shared/",
        allowed_tool_kinds: list[str] | None = None,
        base_dir: str | None = None,
        protected_tools_enabled: bool = True,
        protected_dirs: tuple[str, ...] = (),
        protected_files: tuple[str, ...] = (),
    ) -> None:
        if mode == "allowlist_shared":
            mode = "allowlist"
        if mode == "allow_all":
            mode = "allow_all_own_turns"  # backward compatible spelling, same ownership gates
        if mode not in ("pending", "allowlist", "allow_all_own_turns"):
            raise ValueError("permission_mode_invalid")
        kinds = list(allowed_tool_kinds or ["edit"])
        if mode == "allowlist" and set(kinds) - {"edit"}:
            raise ValueError("only_edit_kind_may_be_allowlisted")
        if mode == "allow_all_own_turns":
            warnings.warn(
                "DANGER: allow_all_own_turns AUTO-APPROVES ELIGIBLE TOOLS on attested own turns; "
                "subject to the independent protected-tool gate. Not human approval.",
                RuntimeWarning,
                stacklevel=2,
            )
        self.protected_dirs = tuple(protected_dirs)
        self.protected_files = tuple(protected_files)
        self.protected_tools_enabled = protected_tools_enabled
        self.mode = mode
        self.shared_dir = shared_dir
        self.allowed_tool_kinds = kinds
        self.base_dir = base_dir or os.getcwd()

    def protected_decision(self, request: dict) -> PermissionDecision | None:
        if not self.protected_tools_enabled:
            return None
        params = _params(request)
        tool = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
        paths = extract_paths(tool)
        reason = protected_reason(
            tool,
            paths,
            self.base_dir,
            protected_dirs=self.protected_dirs,
            protected_files=self.protected_files,
        )
        if not reason:
            return None
        options = params.get("options") if isinstance(params.get("options"), list) else []
        reject = next(
            (
                o.get("optionId")
                for o in options
                if isinstance(o, dict)
                and o.get("kind") == "reject_once"
                and isinstance(o.get("optionId"), str)
            ),
            None,
        )
        return PermissionDecision(
            "deny",
            reason,
            option_id=reject,
            paths=paths,
            tool_kind=tool.get("kind"),
            title=tool.get("title"),
        )

    def decide(self, request: dict, *, own_turn: bool) -> PermissionDecision:
        params = _params(request)
        tool_call = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
        kind = tool_call.get("kind") if isinstance(tool_call.get("kind"), str) else None
        title = tool_call.get("title") if isinstance(tool_call.get("title"), str) else None
        paths = extract_paths(tool_call)
        common = dict(paths=paths, tool_kind=kind, title=title)
        if request.get("method") != "session/request_permission":
            return PermissionDecision("ignore", "not_a_permission_request", **common)
        if not own_turn:
            return PermissionDecision("ignore", "not_bridge_turn_first_answer_wins", **common)
        options = params.get("options") if isinstance(params.get("options"), list) else []
        protected = self.protected_decision(request)
        if protected is not None:
            return protected

        def _allow_once_id() -> str | None:
            for opt in options:
                if (
                    isinstance(opt, dict)
                    and opt.get("kind") == "allow_once"
                    and isinstance(opt.get("optionId"), str)
                ):
                    return opt["optionId"]
            return None

        if self.mode == "allow_all_own_turns":
            option_id = _allow_once_id()
            if option_id is None:
                return PermissionDecision("pending", "no_allow_once_option", **common)
            return PermissionDecision(
                "approve", "allow_all_own_turn", option_id=option_id, **common
            )
        if self.mode != "allowlist":
            return PermissionDecision("pending", "policy_pending_approve_nothing", **common)
        if kind not in self.allowed_tool_kinds:
            return PermissionDecision("pending", "tool_kind_not_allowlisted", **common)
        if not paths:
            return PermissionDecision("pending", "no_paths_in_tool_call", **common)
        outside = [p for p in paths if not path_inside(p, self.shared_dir, self.base_dir)]
        if outside:
            return PermissionDecision("pending", "path_outside_shared_dir", **common)
        options = params.get("options") if isinstance(params.get("options"), list) else []
        option_id = None
        for opt in options:
            if (
                isinstance(opt, dict)
                and opt.get("kind") == "allow_once"
                and isinstance(opt.get("optionId"), str)
            ):
                option_id = opt["optionId"]
                break
        if option_id is None:
            return PermissionDecision("pending", "no_allow_once_option", **common)
        return PermissionDecision(
            "approve", "edit_inside_shared_dir", option_id=option_id, **common
        )


def selected_result(option_id: str) -> dict:
    return {"outcome": {"outcome": "selected", "optionId": option_id}}


def cancelled_result() -> dict:
    return {"outcome": {"outcome": "cancelled"}}
