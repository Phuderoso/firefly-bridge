"""Shared canal speaker parse + VIP roster (single source of truth).

Who a channel comment is *from* is read from the comment body only, in this order:

1. leading ``<!-- channel-bot: Nome -->`` marker (bots that post on the canal themselves);
2. a ``de:`` / ``from:`` header line at the top;
3. the ``— Nome`` signature at the bottom.

The GitHub login is NEVER a speaker: every canal comment is posted by the owner's
account, so the login says nothing about which agent wrote it. ``resolve_speaker``
accepts a ``login=`` argument only so callers can pass it and have it ignored on record.

The VIP roster (who may wake a terminal directly) lives in ONE list in the user
config.toml, with its name aliases next to it::

    [channel_roster]
    vip = ["agent-a", "agent-b", "agent-c", "agent-d", ...]

    [channel_roster.aliases]
    agent-d = ["agentdext", "agent-d[ext]", "agent-d-alt"]

No roster and no alias is compiled in. A missing or empty roster fails closed: nobody is VIP.

Canal authenticity (HMAC, opt-in) lives here too, so channel-gh and wake_watch share
ONE format. A signed comment ends with one trailer line::

    <!-- channel-sig v=1 from=Nome ts=<unix> nonce=<hex> mac=<hmac-sha256 hex> -->

The MAC covers every byte above the trailer (para:, de:, text, signature, reply-to, markers),
the signer, the timestamp and the nonce. Keys are per sender, 0600 files::

    [channel_identity]          # who THIS terminal posts as (send/reply/ack sign with it)
    name = "peerb"
    key_file = "~/.config/channel/keys/peerb.key"

    [channel_keyring]           # who this terminal can verify: <dir>/<nome>.key
    dir = "~/.config/channel/keyring"

    [channel_roster]
    owner = "..."                 # owner wake ALWAYS needs a verified signature from the owner

    [channel_wake]
    legacy_unsigned_wake = false  # default: NO wake authority without a verified channel-sig

Wake authority (wake_gate) comes ONLY from a verified trailer: a VIP speaker must have signed it
herself, and a `<!-- agent-relay -->` only borrows agent-a's authority when agent-a signed it.
Markers, `de:` and `— Nome` without a valid trailer are display text: the message is still
sent, delivered and shown (marked unverified), it just cannot wake anybody. Without a keyring
nothing verifies, so nothing wakes, unless the config opts in to `legacy_unsigned_wake = true`
(pre-HMAC behaviour for non-owner VIPs; the owner still needs his signature; a present-but-invalid
trailer is still gated). Send is never blocked by any of this.

Stdlib only; importable from the standalone ``channel-gh`` script and from wake_watch.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RELAY_MARK = "<!-- agent-relay -->"
RELAY_BY = "agent-a"
BOT_MARK_RE = re.compile(r"^<!--\s*channel-bot\s*:\s*([^<>]*?)\s*-->$", re.IGNORECASE)
HEADER_RE = re.compile(
    r"^\s*(?:\*\*)?\s*(para|to|de|from)\s*:\s*(.*?)\s*(?:\*\*)?\s*$", re.IGNORECASE
)
SIGNATURE_RE = re.compile(r"^\s*(?:—|--|–)\s*(\S.*?)\s*$")

ROSTER_SECTION = "channel_roster"
ROSTER_KEY = "vip"
DEFAULT_CONFIG_REL = Path("firefly-bridge") / "config.toml"

SIG_LINE_RE = re.compile(
    r"^<!--\s*channel-sig\s+v=1\s+from=(?P<from>[^\s<>]+)\s+ts=(?P<ts>\d{1,12})\s+"
    r"nonce=(?P<nonce>[0-9a-f]{16,64})\s+mac=(?P<mac>[0-9a-f]{64})\s*-->$"
)
SIG_MAX_SKEW_S = 600  # trailer ts vs GitHub created_at: an old signed body cannot be re-posted
MIN_KEY_BYTES = 32
IDENTITY_SECTION = "channel_identity"
KEYRING_SECTION = "channel_keyring"
WAKE_SECTION = "channel_wake"
LEGACY_WAKE_KEY = "legacy_unsigned_wake"

SOURCE_MARKER = "marker"
SOURCE_DE = "de"
SOURCE_SIGNATURE = "signature"


# --- body parse ---------------------------------------------------------------------------


def leading_html_comments(body: str) -> list[str]:
    out: list[str] = []
    for raw in (body or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("<!--") and line.endswith("-->"):
            out.append(line)
            continue
        break
    return out


def bot_marker_name(body: str) -> str:
    """`<!-- channel-bot: Nome -->` in the leading HTML-comment block -> "Nome"."""
    for line in leading_html_comments(body):
        match = BOT_MARK_RE.match(line)
        if match and match.group(1).strip():
            return match.group(1).strip()
    return ""


def is_agent_relay(body: str) -> bool:
    return (body or "").lstrip().startswith(RELAY_MARK)


def is_relay_comment(body: str) -> bool:
    """Relay/bot-originated: agent-a's relay marker or a `channel-bot: Nome` marker."""
    return is_agent_relay(body) or bool(bot_marker_name(body))


def parse_headers(body: str, max_lines: int = 6) -> dict[str, str]:
    """Read `para:`/`to:`/`de:`/`from:` lines from the top of a comment body."""
    headers: dict[str, str] = {}
    seen = 0
    for raw in (body or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("<!--"):
            continue
        seen += 1
        if seen > max_lines:
            break
        match = HEADER_RE.match(line)
        if not match:
            break
        key = match.group(1).lower()
        key = {"to": "para", "from": "de"}.get(key, key)
        headers.setdefault(key, match.group(2).strip())
    return headers


def parse_signature(body: str) -> str:
    """Return the `— <sender>` signature at the bottom of a comment, if any."""
    for raw in reversed((body or "").splitlines()):
        line = raw.strip()
        if not line or line.startswith("<!--"):
            continue
        match = SIGNATURE_RE.match(line)
        return match.group(1).strip() if match else ""
    return ""


@dataclass(frozen=True)
class Speaker:
    """Who a comment says it is from, and how we know."""

    name: str = ""
    source: str = ""  # marker | de | signature | "" (unknown)
    relay_by: str = ""  # "agent-a" when the comment is a agent-relay

    @property
    def wake_principal(self) -> str:
        """Whose authority a wake runs under: the relayer vouches for a relayed message."""
        return self.relay_by or self.name


def resolve_speaker(body: str, *, login: str | None = None) -> Speaker:
    """marker > `de:` > signature. ``login`` is accepted and deliberately ignored."""
    del login  # the GitHub login is the owner's account for every comment; never a speaker
    relay_by = current_relay_principal() if is_agent_relay(body) else ""
    name = bot_marker_name(body)
    if name:
        return Speaker(name, SOURCE_MARKER, relay_by)
    name = parse_headers(body).get("de", "")
    if name:
        return Speaker(name, SOURCE_DE, relay_by)
    name = parse_signature(body)
    if name:
        return Speaker(name, SOURCE_SIGNATURE, relay_by)
    return Speaker("", "", relay_by)


def comment_sender(body: str) -> str:
    """Who the comment says it is from: channel-bot marker, then `de:`, then signature."""
    return resolve_speaker(body).name


# --- names --------------------------------------------------------------------------------


def _base_key(value: str) -> str:
    """Case/space-insensitive key; a trailing `[...]` tag is dropped (`agent-d[ext]` -> `agent-d`)."""
    key = " ".join((value or "").split()).casefold().strip("*`'\"")
    return re.sub(r"\s*\[[^\]]*\]$", "", key).strip()


def norm_name(value: str, alias_map: dict[str, str] | None = None) -> str:
    """Canonical key: aliases from config fold to one key (`agent-d-alt` -> `agent-d`)."""
    key = _base_key(value)
    amap = active_aliases() if alias_map is None else alias_map
    return _base_key(amap[key]) if key in amap else key


def canonical_name(value: str, alias_map: dict[str, str] | None = None) -> str:
    """Canonical spelling from the config aliases (`agent-d-alt` -> `agent-d`); else the name as written."""
    amap = active_aliases() if alias_map is None else alias_map
    return amap.get(_base_key(value), (value or "").strip())


def name_tokens(value: str, alias_map: dict[str, str] | None = None) -> set[str]:
    """Split a header value like "peerb, agent-c" or "peera-peerb" into lowercase tokens.
    Each token is also added in its canonical form (`agent-d-alt` adds `agent-d`)."""
    tokens: set[str] = set()
    for part in re.split(r"[\s,;/&+]+|\be\b|\band\b", value or ""):
        part = part.strip().strip("*" + "`" + "'" + '"').lower()
        if not part:
            continue
        tokens.add(part)
        tokens.update(p for p in part.split("-") if p)
    tokens.update(norm_name(t, alias_map) for t in list(tokens))
    return tokens


def names_match(value: str, aliases: list[str], alias_map: dict[str, str] | None = None) -> bool:
    tokens = name_tokens(value, alias_map)
    return any(norm_name(alias, alias_map) in tokens for alias in aliases if alias.strip())


# --- VIP roster + aliases (config.toml) ---------------------------------------------------
#
#   [channel_roster]
#   vip = ["agent-a", "agent-b", "agent-c", "agent-d", ...]
#
#   [channel_roster.aliases]          # spelling only: never makes anyone VIP
#   agent-d = ["agentdext", "agent-d[ext]", "agent-d-alt"]
#
# Nothing here is compiled in (no deployment names in code). Missing file/section => no VIP and
# no aliases (fail closed).


class RosterError(ValueError):
    pass


@dataclass(frozen=True)
class RosterConfig:
    vip: tuple[str, ...] = ()
    aliases: dict[str, str] = field(default_factory=dict)  # base key of every spelling -> canonical spelling
    owner: tuple[str, ...] = ()  # `[channel_roster] owner`: wake only with a verified owner signature
    relay_principal: str = "agent-a"


def default_config_path() -> Path:
    override = os.environ.get("FIREFLY_BRIDGE_CONFIG")
    if override:
        return Path(os.path.expanduser(os.path.expandvars(override)))
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / DEFAULT_CONFIG_REL


_KV_LIST_RE = re.compile(r"^\s*(\"[^\"]+\"|[A-Za-z0-9_\-\[\]]+)\s*=\s*\[(.*)\]\s*(?:#.*)?$")
_ITEM_RE = re.compile(r"\"([^\"]*)\"|'([^']*)'")


def _parse_roster_fallback(text: str) -> dict:  # pragma: no cover - py<3.11 only
    """Python < 3.11: one-line `key = [...]` entries under the two roster tables."""
    out: dict = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and not line.startswith("[["):
            section = line.split("#", 1)[0].strip()[1:-1].strip()
            continue
        match = _KV_LIST_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip('"')
        vals = [a or b for a, b in _ITEM_RE.findall(match.group(2))]
        if section == ROSTER_SECTION and key in (ROSTER_KEY, "owner"):
            out[key] = vals
        elif section == f"{ROSTER_SECTION}.aliases":
            out.setdefault("aliases", {})[key] = vals
    return out


def parse_roster_config_text(text: str) -> RosterConfig:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # pragma: no cover - py<3.11
        tomllib = None  # type: ignore[assignment]
    if tomllib is not None:
        try:
            table = tomllib.loads(text).get(ROSTER_SECTION) or {}
        except tomllib.TOMLDecodeError as exc:
            raise RosterError("config_toml_invalid") from exc
    else:  # pragma: no cover
        table = _parse_roster_fallback(text)
    if not isinstance(table, dict):
        raise RosterError("roster_section_must_be_table")
    raw_vip = table.get(ROSTER_KEY, [])
    if not isinstance(raw_vip, list) or not all(isinstance(x, str) for x in raw_vip):
        raise RosterError("roster_vip_must_be_list_of_strings")
    raw_alias = table.get("aliases", {})
    if not isinstance(raw_alias, dict):
        raise RosterError("roster_aliases_must_be_table")
    amap: dict[str, str] = {}
    for canon, spellings in raw_alias.items():
        if not isinstance(spellings, list) or not all(isinstance(x, str) for x in spellings):
            raise RosterError(f"roster_alias_must_be_list_of_strings:{canon}")
        canon = canon.strip()
        for spelling in [canon, *spellings]:
            key = _base_key(spelling)
            if not key:
                continue
            if key in amap and _base_key(amap[key]) != _base_key(canon):
                raise RosterError(f"roster_alias_conflict:{spelling}")
            amap[key] = canon
    vip: list[str] = []
    seen: set[str] = set()
    for name in raw_vip:
        name = amap.get(_base_key(name), name.strip())
        key = _base_key(name)
        if key and key not in seen:
            seen.add(key)
            vip.append(name)
    raw_owner = table.get("owner", [])
    if isinstance(raw_owner, str):
        raw_owner = [raw_owner]
    if not isinstance(raw_owner, list) or not all(isinstance(x, str) for x in raw_owner):
        raise RosterError("roster_owner_must_be_string_or_list")
    owner = tuple(amap.get(_base_key(o), o.strip()) for o in raw_owner if o.strip())
    relay = str(table.get("relay_principal") or "agent-a").strip() or "agent-a"
    return RosterConfig(tuple(vip), amap, owner, relay)


def parse_roster_text(text: str) -> list[str]:
    """`[channel_roster] vip` from config TOML text; [] when absent (fail closed)."""
    return list(parse_roster_config_text(text).vip)


_CACHE: dict[str, tuple] = {}
_ACTIVE: list[str | None] = [None]  # explicit config path in use (None = default path)


def load_roster_config(config_path: str | Path | None = None) -> RosterConfig:
    path = (Path(config_path) if config_path else default_config_path()).expanduser()
    try:
        st = path.stat()
        stamp = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return RosterConfig()
    hit = _CACHE.get(str(path))
    if hit and hit[0] == stamp:
        return hit[1]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return RosterConfig()
    cfg = parse_roster_config_text(text)
    _CACHE[str(path)] = (stamp, cfg)
    return cfg


def current_relay_principal() -> str:
    """Relayer name from ``[channel_roster] relay_principal``, else ``agent-a``."""
    try:
        name = load_roster_config(_ACTIVE[0]).relay_principal
    except RosterError:
        return RELAY_BY
    return name or RELAY_BY


def use_config(config_path: str | Path | None) -> None:
    """Make this config's aliases the active ones for norm_name/names_match (None = default path)."""
    _ACTIVE[0] = str(config_path) if config_path else None


def active_aliases() -> dict[str, str]:
    try:
        return load_roster_config(_ACTIVE[0]).aliases
    except RosterError:
        return {}  # an invalid file surfaces through load_vip_roster, not through name matching


def load_vip_roster(config_path: str | Path | None = None) -> list[str]:
    """The VIP roster from config.toml (canonical spellings). Missing file/section -> []."""
    use_config(config_path)  # its aliases become the active ones (None = default path)
    return list(load_roster_config(config_path).vip)


def load_owner(config_path: str | Path | None = None) -> list[str]:
    """`[channel_roster] owner` (canonical spellings). Missing -> [] (no owner declared)."""
    try:
        return list(load_roster_config(config_path if config_path else _ACTIVE[0]).owner)
    except RosterError:
        return []


def is_owner(name: str, owners: list[str]) -> bool:
    key = norm_name(name)
    return bool(key) and key in {norm_name(o) for o in owners}


def is_vip(name: str, roster: list[str]) -> bool:
    key = norm_name(name)
    return bool(key) and key in {norm_name(v) for v in roster}


def canonical_vip(name: str, roster: list[str]) -> str:
    """Roster spelling for a VIP name (`agentc` -> `agent-c`, `agent-d-alt` -> `agent-d`), or "" when not VIP."""
    key = norm_name(name)
    for v in roster:
        if key and norm_name(v) == key:
            return v
    return ""


# --- canal HMAC (sign / verify) --------------------------------------------------------------


MAX_KEY_FILE_BYTES = 4096


def _read_key_file_once(target: Path) -> tuple[bytes | None, str]:
    """Open ``target`` once (O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK), check that same descriptor, read it.

    Stdlib only and self-contained, so a standalone ``speaker.py`` keeps working; ``envelope``
    imports it from here. Returns ``(raw_bytes, "")`` or ``(None, reason)`` with reason in
    ``missing``, ``not_regular``, ``unreadable``, ``mode``, ``owner`` or ``too_large``. Type,
    mode and owner come from ``fstat`` on the descriptor that is read, so the file cannot be
    swapped between the check and the read, and a symlink at ``target`` is refused.

    Scope: O_NOFOLLOW applies to the last path component only. Symlinked parent directories
    are still followed; keep key directories private (0700) and owned by the user.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(target, flags)
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        # ELOOP (symlink with O_NOFOLLOW), ENXIO (socket), EISDIR, EACCES, ...
        try:
            st = os.lstat(target)  # only to label the error; nothing is read through it
        except OSError:
            return None, "missing"
        if isinstance(exc, PermissionError) and stat.S_ISREG(st.st_mode):
            return None, "unreadable"
        return None, "not_regular"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not_regular"
        if st.st_mode & 0o077:
            return None, "mode"
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return None, "owner"
        chunks = []
        size = 0
        while size <= MAX_KEY_FILE_BYTES:
            chunk = os.read(fd, MAX_KEY_FILE_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_KEY_FILE_BYTES:
            return None, "too_large"
        return b"".join(chunks), ""
    finally:
        os.close(fd)


class KeyFileError(ValueError):
    pass


def load_key(path: str | Path) -> bytes:
    """Hex key file: regular file (no symlink), owned by us, no group/other bits, >= 32 bytes.

    Opened once with O_NOFOLLOW; type, mode and owner come from ``fstat`` on that same
    descriptor, which is then read, so the file cannot be swapped after the check.
    """
    target = Path(os.path.expanduser(str(path)))
    raw, reason = _read_key_file_once(target)
    if raw is None:
        raise KeyFileError(
            {
                "missing": f"key_file_missing: {target}",
                "not_regular": f"key_file_not_regular: {target}",
                "unreadable": f"key_file_unreadable: {target}",
                "too_large": f"key_file_too_large: {target}",
                "mode": f"key_file_mode_too_open: {target} must be 0600",
                "owner": f"key_file_wrong_owner: {target}",
            }[reason]
        )
    try:
        key = bytes.fromhex(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise KeyFileError(f"key_file_not_hex: {target}") from exc
    if len(key) < MIN_KEY_BYTES:
        raise KeyFileError(f"key_file_too_short: {target}")
    return key


def generate_key_file(path: str | Path) -> Path:
    """New random 32-byte key, mode 0600, never overwrites, never prints the key."""
    target = Path(os.path.expanduser(str(path)))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (secrets.token_hex(32) + "\n").encode("ascii"))
    finally:
        os.close(fd)
    return target


def _toml_table(config_path: str | Path | None, section: str) -> dict:
    path = (Path(config_path) if config_path else default_config_path()).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # pragma: no cover - py<3.11: flat `k = "v"` lines only
        out: dict = {}
        cur = ""
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1].strip()
            elif cur == section and "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                out[k.strip()] = v.split("#", 1)[0].strip().strip("\"'")
        return out
    try:
        table = tomllib.loads(text).get(section) or {}
    except tomllib.TOMLDecodeError as exc:
        raise RosterError("config_toml_invalid") from exc
    return table if isinstance(table, dict) else {}


def bound_identity(config_path: str | Path | None = None) -> tuple[str, bytes | None]:
    """(name, key) from `[channel_identity]`; ("", None) when unbound (legacy, unsigned)."""
    table = _toml_table(config_path, IDENTITY_SECTION)
    name = str(table.get("name") or "").strip()
    key_file = str(table.get("key_file") or "").strip()
    if not name:
        return "", None
    if not key_file:
        raise KeyFileError("identity_key_file_required")
    return name, load_key(key_file)


def load_keyring_dir(path: str | Path) -> dict[str, bytes]:
    """`<dir>/<nome>.key` -> {norm_name(nome): key}. Bad files are skipped (never trusted)."""
    ring: dict[str, bytes] = {}
    base = Path(os.path.expanduser(str(path)))
    if not base.is_dir():
        return ring
    for f in sorted(base.glob("*.key")):
        try:
            ring[norm_name(f.stem)] = load_key(f)
        except KeyFileError:
            continue
    return ring


def load_legacy_unsigned_wake(config_path: str | Path | None = None) -> bool:
    """`[channel_wake] legacy_unsigned_wake` (default False). Only a TOML true / "true" opts in;
    anything else, a missing file or an invalid config keeps the strict default (fail closed)."""
    try:
        table = _toml_table(config_path if config_path else _ACTIVE[0], WAKE_SECTION)
    except RosterError:
        return False
    value = table.get(LEGACY_WAKE_KEY, False)
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return value is True


def load_keyring(config_path: str | Path | None = None) -> dict[str, bytes] | None:
    """None = no `[channel_keyring]` configured (verification off -> auth "no_keyring")."""
    d = str(_toml_table(config_path, KEYRING_SECTION).get("dir") or "").strip()
    return load_keyring_dir(d) if d else None


def _sig_canonical(signer: str, ts: int, nonce: str, content: str) -> bytes:
    # _base_key (not norm_name): a MAC must not change meaning when alias config changes.
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"channel-sig/v1\n{_base_key(signer)}\n{ts}\n{nonce}\n{digest}".encode()


def sign_body(body: str, signer: str, key: bytes, *, ts: int | None = None, nonce: str | None = None) -> str:
    """Append the signed trailer. Idempotent-safe: an existing trailer is replaced, not stacked."""
    if not re.fullmatch(r"[^\s<>]+", signer or ""):
        raise ValueError("signer name cannot be empty or contain spaces or <>")
    content, _ = split_signature(body)
    if not content.endswith("\n"):
        content += "\n"
    ts = int(time.time()) if ts is None else int(ts)
    nonce = nonce or secrets.token_hex(16)
    mac = hmac.new(key, _sig_canonical(signer, ts, nonce, content), hashlib.sha256).hexdigest()
    return f"{content}<!-- channel-sig v=1 from={signer} ts={ts} nonce={nonce} mac={mac} -->\n"


def split_signature(body: str):
    """(content above the trailer, trailer match | None). Only the LAST non-empty line counts."""
    text = body or ""
    stripped = text.rstrip("\n")
    head, _, last = stripped.rpartition("\n")
    match = SIG_LINE_RE.match(last.strip())
    if not match:
        return text, None
    return (head + "\n") if head else "", match


def _relay_name(value: str, what: str) -> str:
    text = " ".join(str(value or "").split())
    if not text or "<!--" in text or "-->" in text or "\n" in str(value or ""):
        raise ValueError(f"relay_{what}_invalid")
    return text


def format_relay_body(de: str, message: str, *, para: str = "", reply_to: int | None = None) -> str:
    """The `<!-- agent-relay -->` body agent-a posts for someone else (unsigned).

    Same shape the canal already parses: relay marker, optional `<!-- reply-to: N -->`,
    `**de: Nome**`, optional `para: Nome`, blank line, text. Signing is a separate, opt-in
    step (``sign_relay_body``) so the unsigned shape stays byte-identical to today's relays.
    """
    de = _relay_name(de, "de")
    msg = (message or "").strip("\n")
    if not msg.strip():
        raise ValueError("relay_message_required")
    lines = [RELAY_MARK]
    if reply_to is not None:
        lines.append(f"<!-- reply-to: {int(reply_to)} -->")
    lines.append(f"**de: {de}**")
    if para:
        lines.append(f"para: {_relay_name(para, 'para')}")
    body = "\n".join(lines) + f"\n\n{msg}\n"
    if split_signature(body)[1] is not None:
        # a trailer typed into the message would read as a (forged) channel-sig
        raise ValueError("relay_message_has_sig_trailer")
    return body


def sign_relay_body(body: str, signer: str, key: bytes, *, ts: int | None = None,
                    nonce: str | None = None) -> str:
    """channel-sig v=1 over a agent-relay body, ONLY as the relayer (agent-a).

    verify_comment accepts a relay signed by the relayer (signed_by == RELAY_BY) and wake_gate
    then grants agent-a's authority, never the `de:` name's. Signing a relay as anybody else
    would be a vouch the gate does not model, so it is refused here.
    """
    if not is_agent_relay(body):
        raise ValueError("not_an_agent_relay")
    if _base_key(signer) != _base_key(current_relay_principal()):
        raise ValueError("relay_signer_must_be_relayer")
    return sign_body(body, signer, key, ts=ts, nonce=nonce)


AUTH_VERIFIED = "verified"
AUTH_NO_KEYRING = "no_keyring"
AUTH_UNSIGNED = "unsigned"
AUTH_UNKNOWN_KEY = "unknown_key"
# a present-but-invalid trailer is evidence of forgery/tampering, not just "unsigned"
AUTH_FORGED = ("bad_mac", "sender_mismatch", "stale", "replayed_nonce")
AUTH_WRONG_RECIPIENT = "wrong_recipient"  # valid signature, but `para:` names someone else


def _parse_created(created: str) -> float | None:
    text = (created or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # noqa: UP017 - py3.9 compat
    return dt.timestamp()


@dataclass(frozen=True)
class SigCheck:
    auth: str  # verified | unsigned | unknown_key | bad_mac | sender_mismatch | stale | replayed_nonce
    #           | wrong_recipient | no_keyring
    signed_by: str = ""

    @property
    def verified(self) -> bool:
        return self.auth == AUTH_VERIFIED


def verify_comment(
    comment: dict,
    keyring: dict[str, bytes] | None,
    seen_nonces: dict[str, int] | None = None,
    *,
    expected_recipient: list[str] | str | None = None,
) -> SigCheck:
    """Check the trailer of a canal comment against the keyring.

    The signer must be the speaker the body claims (marker > de: > signature, aliases folded).
    A agent-relay may instead be signed by agent-a (the relayer vouches for the `de:` bot); the
    wake gate then only grants agent-a's authority, never the relayed name's.

    Recipient binding: ``expected_recipient`` is the local identity (a name or its aliases).
    When given and the signed content has a ``para:``/``to:`` header that names none of them,
    the result is ``wrong_recipient`` (checked last, so the nonce is still recorded). A comment
    without ``para:`` is not addressed to anyone and is not recipient-bound (relays are routed
    by their original sender). ``None`` (the default) keeps the old, unbound behaviour.
    """
    body = comment.get("body") or ""
    content, sig = split_signature(body)
    if sig is None:
        return SigCheck(AUTH_NO_KEYRING if keyring is None else AUTH_UNSIGNED)
    signer = sig.group("from")
    if keyring is None:
        return SigCheck(AUTH_NO_KEYRING, signer)
    key = keyring.get(norm_name(signer))
    if key is None:
        return SigCheck(AUTH_UNKNOWN_KEY, signer)
    expected = hmac.new(
        key, _sig_canonical(signer, int(sig.group("ts")), sig.group("nonce"), content), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig.group("mac")):
        return SigCheck("bad_mac", signer)
    spk = resolve_speaker(content)
    allowed = {norm_name(spk.name)} if spk.name else set()
    if spk.relay_by:
        allowed.add(norm_name(spk.relay_by))
    if norm_name(signer) not in allowed:
        return SigCheck("sender_mismatch", signer)
    created = _parse_created(str(comment.get("created_at") or ""))
    if created is None or abs(created - int(sig.group("ts"))) > SIG_MAX_SKEW_S:
        return SigCheck("stale", signer)
    if seen_nonces is not None:
        cid = comment.get("id")
        first = seen_nonces.setdefault(sig.group("nonce"), cid)
        if first != cid:
            return SigCheck("replayed_nonce", signer)
    if expected_recipient is not None:
        aliases = [expected_recipient] if isinstance(expected_recipient, str) else list(expected_recipient)
        para = parse_headers(content).get("para", "")
        if para and not names_match(para, aliases):
            return SigCheck(AUTH_WRONG_RECIPIENT, signer)
    return SigCheck(AUTH_VERIFIED, signer)


WAKE = "wake"
GATED_NON_VIP = "gated_non_vip"
SUPPRESSED_SELF_ECHO = "suppressed_self_echo"
_AUTH_OK = (None, "", "verified", "no_keyring")


@dataclass(frozen=True)
class WakeDecision:
    action: str  # wake | gated_non_vip | suppressed_self_echo
    sender: str  # who the body says it is from (never the GitHub login)
    principal: str  # whose authority the wake runs under (agent-a for a vouched relay)
    reason: str = ""


def wake_gate(
    sender: str,
    *,
    own_aliases: list[str],
    roster: list[str],
    relay_by: str = "",
    auth: str | None = None,
    signed_by: str = "",
    owners: list[str] | None = None,
    legacy_unsigned: bool | None = None,
) -> WakeDecision:
    """THE VIP filter for waking a terminal (one place; wake_watch only calls this).

    - the terminal's own name as speaker (e.g. `<!-- channel-bot: peerb -->` echo) -> suppressed;
    - a agent-relay wakes under agent-a's authority ONLY when agent-a signed it (verified,
      signed_by == relay_by); otherwise the marker is just text and the sender stands alone;
    - otherwise the principal must be in the config roster, else gated_non_vip (terminal);
    - STRICT (default, R3): the wake also needs auth == "verified" and signed_by == the speaker
      (or the relayer for a relay). No keyring / unsigned / unknown key -> gated
      "signature_required". `legacy_unsigned=True` (config `[channel_wake]
      legacy_unsigned_wake = true`; None = read it from the active config) restores the
      pre-HMAC rule for NON-owner VIPs only.
    Unknown speaker or empty roster -> gated_non_vip (fail closed).

    HMAC (see verify_comment):
    - a "verified" relay must be signed by the relayer itself (signed_by == relay_by);
    - OWNER (`[channel_roster] owner`, default = the active config's): a wake that names the
      owner (as speaker or as a relayed `de:`) needs auth == "verified" AND signed_by == the owner
      (or == the relayer, for a relay the relayer signed) — ALSO without a keyring.
      Declaring `— Owner` / `de: Owner` / a marker in the body is never enough (reason
      owner_unverified). Send still works; only this escalation is closed;
    - any principal with a present-but-invalid trailer (bad_mac, sender_mismatch, stale,
      replayed_nonce) is gated (reason forged_signature).
    """
    sender = (sender or "").strip()
    if sender and names_match(sender, own_aliases):
        return WakeDecision(SUPPRESSED_SELF_ECHO, sender, sender, "self_echo")
    if auth == AUTH_WRONG_RECIPIENT:
        # signed for somebody else: never wakes this terminal, in strict or legacy mode
        return WakeDecision(GATED_NON_VIP, sender, sender, AUTH_WRONG_RECIPIENT)
    legacy = load_legacy_unsigned_wake() if legacy_unsigned is None else bool(legacy_unsigned)
    signed_ok = auth == AUTH_VERIFIED and bool(signed_by)
    if legacy:
        relay_ok = bool(relay_by) and auth in _AUTH_OK
        if relay_ok and auth == AUTH_VERIFIED and norm_name(signed_by) != norm_name(relay_by):
            relay_ok = False  # "verified" by the relayed bot itself is not the relayer's vouch
    else:
        relay_ok = bool(relay_by) and signed_ok and norm_name(signed_by) == norm_name(relay_by)
    principal = relay_by if relay_ok else sender
    if not principal:
        return WakeDecision(GATED_NON_VIP, sender, "", "unknown_speaker")
    if not roster:
        return WakeDecision(GATED_NON_VIP, sender, principal, "roster_empty")
    if not is_vip(principal, roster):
        return WakeDecision(GATED_NON_VIP, sender, principal, "not_in_roster")
    if auth in AUTH_FORGED:
        return WakeDecision(GATED_NON_VIP, sender, principal, "forged_signature")
    owner_list = load_owner() if owners is None else owners
    if is_owner(principal, owner_list) or is_owner(sender, owner_list):
        # The owner's name (directly, or as the relayed `de:`) needs a verified signature from the
        # owner, or from the relayer for a relay it signed. Never from body text alone.
        vouchers = {norm_name(sender)} | ({norm_name(relay_by)} if relay_ok else set())
        if not (signed_ok and norm_name(signed_by) in vouchers):
            return WakeDecision(GATED_NON_VIP, sender, principal, "owner_unverified")
    if not legacy:
        # strict: a marker / de: / — Nome / relay marker without a valid trailer grants nothing
        vouchers = {norm_name(sender)} | ({norm_name(relay_by)} if relay_ok else set())
        if not (signed_ok and norm_name(signed_by) in vouchers):
            return WakeDecision(GATED_NON_VIP, sender, principal, "signature_required")
    return WakeDecision(WAKE, sender, canonical_vip(principal, roster), "relay" if relay_ok else "vip")


def gate_comment(
    comment: dict,
    *,
    own_aliases: list[str],
    roster: list[str],
    keyring: dict[str, bytes] | None = None,
    seen_nonces: dict[str, int] | None = None,
    owners: list[str] | None = None,
    legacy_unsigned: bool | None = None,
) -> WakeDecision:
    """THE single gate for a raw canal comment: speaker + signature check + wake gate.

    wake_watch (and any watcher) must call this, never wake_gate with a self-computed auth.
    `keyring=None` means no `[channel_keyring]`: nothing verifies -> strict mode wakes nobody."""
    body = comment.get("body") or ""
    check = verify_comment(
        comment, keyring, seen_nonces, expected_recipient=[a for a in own_aliases if a.strip()] or None
    )
    spk = resolve_speaker(split_signature(body)[0])
    return wake_gate(
        spk.name,
        own_aliases=own_aliases,
        roster=roster,
        relay_by=spk.relay_by,
        auth=check.auth,
        signed_by=check.signed_by if check.verified else "",
        owners=owners,
        legacy_unsigned=legacy_unsigned,
    )


def _cli(argv: list[str] | None = None) -> int:
    """`python -m firefly_bridge.speaker vip [--config F]` -> roster, one name per line.
    `... canonical <Nome> [--config F]` -> roster spelling, exit 1 when not VIP."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    cfg = None
    if "--config" in args:
        i = args.index("--config")
        cfg = args[i + 1] if i + 1 < len(args) else None
        del args[i : i + 2]
    try:
        roster = load_vip_roster(cfg)
    except RosterError as exc:
        print(f"roster_error: {exc}", file=sys.stderr)
        return 3
    if args[:1] == ["vip"]:
        print("\n".join(roster))
        return 0
    if args[:1] == ["canonical"] and len(args) == 2:
        name = canonical_vip(args[1], roster)
        if name:
            print(name)
            return 0
        return 1
    print("uso: python -m firefly_bridge.speaker vip|canonical <Nome> [--config F]", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
