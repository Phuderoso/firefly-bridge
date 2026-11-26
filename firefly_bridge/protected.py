"""Non-overridable-by-mode tool gate; not an OS sandbox or a shell parser.

The trusted leader supplies tool kind and structured input. Opaque execution,
network, indirect/MCP and unknown shapes fail closed, rather than pretending a
keyword search can constrain arbitrary code. Disable only by explicit config.
"""

from __future__ import annotations

import os
import re
import unicodedata

LAWS = {
    "tcc": "forbidden",
    "credentials": "forbidden",
    "bridge_resources": "forbidden",
    "authority": "active_target_lock_required",
    "external_send": "forbidden",
    "funnel": "forbidden",
    "network_exposure": "forbidden",
    "tmux_inject": "forbidden",
    "duplicate_merge": "do_not_merge",
    "close_orders": "closed",
}

RULES = (
    (
        "tcc",
        r"tcc[-_ ]allow[-_ ]guard|\btccutil\b|\bosascript\b|system events|system (?:settings|preferences)|ktccservice|\btcc\.db\b|com\.apple\.tcc|macos.{0,30}permission|permission.{0,30}(?:dialog|macos)",
    ),
    (
        "close_orders",
        r"closed[-_ ]order[-_ ](?:alpha|beta)|close[-_ ]orders",
    ),
    (
        "credentials",
        r"(?:^|[/\\\s_.-])(?:credentials?|secrets?|passwords?|tokens?|keychains?|cookies?|vault)(?:$|[/\\\s_.:=\"-])|\.ssh\b|\.aws\b|\.env\b|\.grok\b|\.netrc\b|\.kube\b|id_(?:rsa|ed25519|ecdsa)|recovery[-_ ]codes?|\.(?:pem|p12|keychain-db)\b|api[-_ ]?key|access[-_ ]?token|private[-_ ]?key|1password|login data|\bbearer\b|\b(?:pypi-|ghp_|github_pat_|sk-)[a-z0-9_-]{8,}",
    ),
    # `\bextra\b` stays: the bare word is an outbound-send signal (a side channel
    # that is not one of the named transports). The boundary avoids "extract".
    (
        "external_send",
        r"send[-_ ]?(?:email|mail|message|sms)|(?:create|publish)[-_ ]?posts?|gmail|outlook|slack|whatsapp|telegram|\bextra\b|\btwilio\b|\bmailto:",
    ),
    (
        "network_exposure",
        r"\bfunnel\b|tailscale|ngrok|cloudflared|\btunnel\b|0\.0\.0\.0|\[?::\]?|(?:bind|listen)[-_ :=]|port[-_ ]?forward",
    ),
    ("tmux_inject", r"\btmux\b|send[-_ ]?keys|tmux[-_ ]?inject"),
    (
        "duplicate_merge",
        r"merge[-_ ]duplicates|duplicate[-_ ]merge",
    ),
)
COMPILED = [(name, re.compile(pattern)) for name, pattern in RULES]
FILE_KEYS = frozenset(
    {
        "path",
        "file_path",
        "filePath",
        "target_file",
        "targetFile",
        "abs_path",
        "absPath",
        "paths",
        "files",
        "edits",
        "content",
        "text",
        "old_string",
        "new_string",
        "replace_all",
        "offset",
        "limit",
        "line",
        "start_line",
        "end_line",
        "encoding",
    }
)


def _flatten(value, *, depth=0, budget=None):
    budget = [1024] if budget is None else budget
    budget[0] -= 1
    if depth > 12 or budget[0] < 0:
        raise ValueError("tool_input_too_complex")
    if isinstance(value, str):
        if len(value) > 65536 or any(unicodedata.category(c) == "Cf" for c in value):
            raise ValueError("tool_input_opaque")
        yield unicodedata.normalize("NFKC", value).casefold()
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(k, depth=depth + 1, budget=budget)
            yield from _flatten(v, depth=depth + 1, budget=budget)
    elif isinstance(value, list):
        for v in value:
            yield from _flatten(v, depth=depth + 1, budget=budget)
    elif value is not None and type(value) not in (bool, int, float):
        raise ValueError("tool_input_opaque")


def _file_shape(value, depth=0):
    if depth > 12:
        return False
    if isinstance(value, dict):
        return all(k in FILE_KEYS and _file_shape(v, depth + 1) for k, v in value.items())
    if isinstance(value, list):
        return all(_file_shape(v, depth + 1) for v in value)
    return value is None or type(value) in (str, bool, int, float)


def _path_identities(path: str, base_dir: str) -> set[str]:
    """Conservative comparison across Linux/Mac case and Unicode conventions.

    realpath must see symlinks *before* collapsing '..'. Retain the lexical
    identity too, so differently-cased aliases cannot hide a configured root.
    Only path metadata is used; files/keys are never opened or read.
    """
    if not path or "\x00" in path:
        raise ValueError("invalid_resource_path")
    expanded = os.path.expandvars(os.path.expanduser(path))
    joined = expanded if os.path.isabs(expanded) else os.path.join(base_dir, expanded)
    return {
        unicodedata.normalize("NFKC", p).casefold()
        for p in (os.path.normpath(joined), os.path.realpath(joined))
    }


def _overlaps_resource(targets: set[str], resources: set[str]) -> bool:
    # Ancestors are protected too: deleting/recursively reading a parent must not
    # bypass a child resource. Separators prevent sibling-prefix overblocking.
    return any(
        a == b or a.startswith(b.rstrip(os.sep) + os.sep) or b.startswith(a.rstrip(os.sep) + os.sep)
        for a in targets
        for b in resources
    )


def _own_resource_reason(paths, base_dir, protected_dirs, protected_files):
    resources = set()
    for path in (*protected_dirs, *protected_files):
        resources.update(_path_identities(path, os.getcwd()))
    for path in paths:
        if _overlaps_resource(_path_identities(path, base_dir), resources):
            return "protected_bridge_resource"
    return None


def protected_paths_reason(paths, base_dir, *, protected_dirs=(), protected_files=()):
    try:
        return _own_resource_reason(paths, base_dir, protected_dirs, protected_files)
    except (ValueError, TypeError, OSError, RecursionError):
        return "protected_unclassified_target"


def protected_reason(
    tool: dict, paths: list[str], base_dir: str, *, protected_dirs=(), protected_files=()
) -> str | None:
    """Return a fixed denial code. Never includes command/path/secret content."""
    try:
        own_resource = _own_resource_reason(paths, base_dir, protected_dirs, protected_files)
        if own_resource:
            return own_resource
        strings = list(_flatten(tool))
        for path in paths:
            expanded = os.path.expanduser(path)
            canonical = os.path.realpath(
                expanded if os.path.isabs(expanded) else os.path.join(base_dir, expanded)
            )
            strings.append(unicodedata.normalize("NFKC", canonical).casefold())
        for name, pattern in COMPILED:
            if any(pattern.search(text) for text in strings):
                return "protected_" + name
        # Only structured file operations can be classified locally. A shell,
        # script, remote tool or self-declared capability is not a safe bypass.
        raw = tool.get("rawInput")
        if tool.get("kind") not in ("read", "edit", "delete"):
            return "protected_opaque_execution"
        if not isinstance(raw, dict) or not raw or not paths:
            return "protected_unclassified_tool"
        if not _file_shape(raw):
            return "protected_unclassified_tool"
        if any(not p or "://" in p or p.startswith(("//", "\\\\")) or "\x00" in p for p in paths):
            return "protected_unclassified_target"
        # An arbitrary name under a file kind must not disguise an MCP/shell tool.
        name = tool.get("name", tool.get("toolName"))
        if name is not None and name not in (
            "read_file",
            "edit_file",
            "write_file",
            "delete_file",
            "Read",
            "Edit",
            "Write",
        ):
            return "protected_unclassified_tool"
        return None
    except (ValueError, TypeError, OSError, RecursionError):
        return "protected_unclassified_tool"
