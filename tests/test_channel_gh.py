"""Tests for scripts/channel-gh (mocked gh; no network)."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import types
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "channel-gh"

_loader = importlib.machinery.SourceFileLoader("channel_gh", str(SCRIPT))
_spec = importlib.util.spec_from_loader("channel_gh", _loader)
assert _spec is not None
mod = importlib.util.module_from_spec(_spec)
_loader.exec_module(mod)


def test_script_has_no_compiled_roster_or_home_paths() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "vip = [" not in text
    assert "/Users/" not in text
    assert "/home/" not in text


def test_format_send_body() -> None:
    body = mod.format_send_body("agent-a", "teste de canal", "agent-a-setup")
    assert body.startswith("para: agent-a\n")
    assert "teste de canal" in body
    assert body.strip().endswith("— agent-a-setup")
    assert not body.lstrip().startswith(mod.RELAY_MARK)


def test_parse_and_load_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[channel]\nsession_id = \"sess-example-0001\"\n\n"
        "[github_canal]\nrepo = \"ExampleOwner/example-canal\"\npr = \"7\"\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("FIREFLY_BRIDGE_GITHUB_CANAL_REPO", raising=False)
    monkeypatch.delenv("FIREFLY_BRIDGE_GITHUB_CANAL_PR", raising=False)
    loaded = mod.load_canal_config(cfg)
    assert loaded["repo"] == "ExampleOwner/example-canal"
    assert loaded["pr"] == "7"
    monkeypatch.setenv("FIREFLY_BRIDGE_GITHUB_CANAL_REPO", "Other/repo")
    monkeypatch.setenv("FIREFLY_BRIDGE_GITHUB_CANAL_PR", "9")
    override = mod.load_canal_config(cfg)
    assert override["repo"] == "Other/repo"
    assert override["pr"] == "9"


def test_inbox_filters_relay_and_since() -> None:
    comments = [
        {
            "id": 1,
            "body": "para: agent-a\n\nhi\n\n— peerb\n",
            "created_at": "2026-11-11T20:00:00Z",
            "html_url": "https://example.test/1",
            "user": {"login": "alice"},
        },
        {
            "id": 2,
            "body": "<!-- agent-relay -->\n**de: agent-a**\n\nold\n",
            "created_at": "2026-11-11T20:01:00Z",
            "html_url": "https://example.test/2",
            "user": {"login": "agent-bot"},
        },
        {
            "id": 3,
            "body": "<!-- agent-relay -->\n**de: agent-a**\n\nnew\n",
            "created_at": "2026-11-11T20:05:00Z",
            "html_url": "https://example.test/3",
            "user": {"login": "agent-bot"},
        },
    ]
    since = mod.parse_iso("2026-11-11T20:02:00Z")
    items = mod.inbox_comments(comments, since)
    assert [i["id"] for i in items] == [3]
    assert items[0]["html_url"].endswith("/3")


def test_send_and_inbox_cli_with_mock_gh(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[github_canal]\nrepo = \"ExampleOwner/example-canal\"\npr = \"1\"\n",
        encoding="utf-8",
    )
    recorded: list[list[str]] = []

    def fake_gh(args: list[str], gh: str) -> str:
        recorded.append(args)
        if args[:2] == ["pr", "comment"]:
            assert args[2] == "1"
            assert "--repo" in args and "ExampleOwner/example-canal" in args
            body = args[args.index("--body") + 1]
            assert body.startswith("para: agent-a\n")
            assert "teste de canal" in body
            assert "— agent-a-setup" in body
            return "https://example.test/pull/1#issuecomment-99\n"
        if args[0] == "api":
            return json.dumps(
                [
                    {
                        "id": 99,
                        "body": "<!-- agent-relay -->\n**de: agent-a**\n\nok\n",
                        "created_at": "2026-11-11T21:00:00Z",
                        "html_url": "https://example.test/99",
                        "user": {"login": "example"},
                    }
                ]
            )
        raise AssertionError(args)

    rc = mod.main(
        ["--config", str(cfg), "send", "agent-a", "teste", "de", "canal", "--from", "agent-a-setup"],
        runner=fake_gh,
    )
    assert rc == 0
    assert capsys.readouterr().out.strip().endswith("issuecomment-99")

    rc = mod.main(
        ["--config", str(cfg), "inbox", "--since", "2026-11-11T20:00:00Z"],
        runner=fake_gh,
    )
    assert rc == 0
    items = json.loads(capsys.readouterr().out)
    assert len(items) == 1
    assert items[0]["body"].lstrip().startswith("<!-- agent-relay -->")


def test_require_config_without_repo() -> None:
    with pytest.raises(SystemExit, match="config_error"):
        mod.require_config({"repo": "", "pr": "", "config_path": "missing.toml"})


def test_parse_gh_comment_list_concatenated_and_ndjson() -> None:
    assert mod.parse_gh_comment_list("") == []
    one = mod.parse_gh_comment_list('[{"id": 1}, {"id": 2}]')
    assert [c["id"] for c in one] == [1, 2]
    two = mod.parse_gh_comment_list('[{"id": 1}][{"id": 2}]')
    assert [c["id"] for c in two] == [1, 2]
    nd = mod.parse_gh_comment_list('{"id": 3}\n{"id": 4}\n')
    assert [c["id"] for c in nd] == [3, 4]


# --- inbox --for / --mark-read / reply ----------------------------------------

def _c(cid: int, body: str, ts: str, login: str = "owner") -> dict:
    return {
        "id": cid,
        "body": body,
        "created_at": ts,
        "html_url": f"https://example.test/{cid}",
        "user": {"login": login},
    }


ADDRESSED_THREAD = [
    _c(10, "para: agent-a\n\npergunta da peerb\n\n— peerb\n", "2026-11-12T10:00:00Z"),
    _c(11, "<!-- agent-relay -->\n**de: agent-a**\n\nresposta pra peerb\n", "2026-11-12T10:02:00Z", "bot"),
    _c(12, "para: agent-a\n\npergunta da peerc\n\n— peerc\n", "2026-11-12T10:03:00Z"),
    _c(13, "<!-- agent-relay -->\n**de: agent-a**\n\nresposta pra peerc\n", "2026-11-12T10:04:00Z", "bot"),
    _c(14, "para: peerb\n\nrecado direto da agent-c\n\n— agent-c\n", "2026-11-12T10:05:00Z"),
    _c(15, "to: peera-peerb, agent-b\n\nrecado em inglês\n\n— agent-b\n", "2026-11-12T10:06:00Z"),
    _c(16, "para: peerb\n\nnota pra mim mesma\n\n— peerb\n", "2026-11-12T10:07:00Z"),
    _c(17, "para: agent-a\n\noutra da peerc\n\n— peerc\n", "2026-11-12T10:08:00Z"),
    _c(
        18,
        "<!-- agent-relay -->\n<!-- reply-to: 10 -->\n**de: agent-a**\n\nresposta tardia pra peerb\n",
        "2026-11-12T10:09:00Z",
        "bot",
    ),
    _c(19, "<!-- agent-relay -->\n**de: agent-c**\npara: peerb\n\nagent-c via relay\n", "2026-11-12T10:10:00Z", "bot"),
]

PEERB = ["peerb", "peera"]


def test_parse_headers_and_signature() -> None:
    h = mod.parse_headers("<!-- agent-relay -->\n**de: agent-a**\npara: peerb\n\ncorpo\n")
    assert h == {"de": "agent-a", "para": "peerb"}
    assert mod.parse_headers("to: A, B\n\nx")["para"] == "A, B"
    assert mod.parse_headers("oi\npara: peerb\n") == {}
    assert mod.parse_signature("x\n\n— peerb\n<!-- reply-to: 3 -->\n") == "peerb"
    assert mod.parse_signature("sem assinatura\n") == ""
    assert mod.names_match("peera-peerb, agent-b", PEERB)
    assert mod.names_match("agent-c e peerb", PEERB)
    assert not mod.names_match("Peerbie", PEERB)


def test_relay_original_sender() -> None:
    by_id = {c["id"]: c for c in ADDRESSED_THREAD}
    assert mod.relay_original_sender(by_id[11], ADDRESSED_THREAD) == "peerb"
    assert mod.relay_original_sender(by_id[13], ADDRESSED_THREAD) == "peerc"
    # explicit reply-to wins over "latest earlier para: agent-a" (which is peerc's #17)
    assert mod.relay_original_sender(by_id[18], ADDRESSED_THREAD) == "peerb"


def test_addressed_inbox_selects_only_her_comments() -> None:
    items = mod.addressed_inbox(ADDRESSED_THREAD, PEERB, None)
    assert [i["id"] for i in items] == [11, 14, 15, 18, 19]
    by_id = {i["id"]: i for i in items}
    assert by_id[11]["from"] == "agent-a" and by_id[11]["relay"] is True
    assert by_id[11]["text"] == "resposta pra peerb"
    assert by_id[14]["from"] == "agent-c" and by_id[14]["relay"] is False
    assert by_id[19]["from"] == "agent-c" and by_id[19]["text"] == "agent-c via relay"
    assert [i["id"] for i in mod.addressed_inbox(ADDRESSED_THREAD, PEERB, 14)] == [15, 18, 19]


def test_format_inbox_text_local_time() -> None:
    items = mod.addressed_inbox(ADDRESSED_THREAD, PEERB, 17)
    text = mod.format_inbox_text(items, "UTC", legacy_unsigned=True)  # pre-HMAC display (opt-in)
    assert text.startswith("#18 · 2026-11-12 10:09 UTC · de: agent-a via relay\nresposta tardia pra peerb")
    strict = mod.format_inbox_text(items, "UTC")  # default: unverified mail still shown, but marked
    assert strict.startswith("#18 · 2026-11-12 10:09 UTC · de: agent-a via relay (não verificado: no_keyring)\n")
    assert "\n---\n#19 · 2026-11-12 10:10 UTC · de: agent-c via relay\nagent-c via relay" in text
    local = mod.format_inbox_text(items, "UTC")
    assert " UTC " in local


def test_cursor_roundtrip_is_monotonic(tmp_path: Path) -> None:
    path = mod.cursor_path("peerb", tmp_path)
    assert path.name == "last_seen_peerb.json"
    assert mod.read_cursor(path) is None
    mod.write_cursor(path, 15)
    assert mod.read_cursor(path) == 15
    mod.write_cursor(path, 12)  # never moves backwards
    assert mod.read_cursor(path) == 15
    path.write_text("not json", encoding="utf-8")
    assert mod.read_cursor(path) is None


def _canal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text("[github_canal]\nrepo = \"ExampleOwner/example-canal\"\npr = \"1\"\n", encoding="utf-8")
    return cfg


def test_inbox_for_mark_read_is_idempotent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _canal_cfg(tmp_path)
    state = tmp_path / "state"
    thread = list(ADDRESSED_THREAD[:6])

    def fake_gh(args: list[str], gh: str) -> str:
        assert args[0] == "api", args  # inbox never posts
        return json.dumps(thread)

    base = ["--config", str(cfg), "inbox", "--for", "peerb,peera", "--state-dir", str(state)]

    cursor_file = state / "last_seen_peera_peerb.json"

    # peek without --mark-read: shown, cursor untouched
    assert mod.main(base, runner=fake_gh) == 0
    assert "#11 " in capsys.readouterr().out
    assert not cursor_file.exists()
    assert not (state / "last_seen_peerb.json").exists()

    # mark read: shown once, then silent
    assert mod.main([*base, "--mark-read"], runner=fake_gh) == 0
    out = capsys.readouterr().out
    assert "#11 " in out and "#14 " in out and "#15 " in out and "#13 " not in out
    assert mod.read_cursor(cursor_file) == 15
    assert mod.main([*base, "--mark-read"], runner=fake_gh) == 0
    assert capsys.readouterr().out == ""

    # a new comment for her arrives: delivered exactly once
    thread.append(ADDRESSED_THREAD[8])
    assert mod.main([*base, "--mark-read"], runner=fake_gh) == 0
    out = capsys.readouterr().out
    assert out.startswith("#18 ") and out.count("\n---\n") == 0
    assert mod.main([*base, "--mark-read"], runner=fake_gh) == 0
    assert capsys.readouterr().out == ""

    # --all ignores (does not reset) the cursor; --json is machine-readable
    assert mod.main([*base, "--all", "--json"], runner=fake_gh) == 0
    assert [i["id"] for i in json.loads(capsys.readouterr().out)] == [11, 14, 15, 18]
    assert mod.read_cursor(state / "last_seen_peera_peerb.json") == 18


def test_inbox_for_wait_polls_until_new_addressed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _canal_cfg(tmp_path)
    state = tmp_path / "state"
    fresh = _c(99, "para: peerb\n\nchegou no wait\n\n— agent-c\n", "2099-01-01T00:00:00Z")
    polls = {"n": 0}

    def fake_gh(args: list[str], gh: str) -> str:
        assert args[0] == "api", args  # wait never posts
        polls["n"] += 1
        if polls["n"] == 1:
            return "[]"
        return json.dumps([fresh])

    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    rc = mod.main(
        [
            "--config",
            str(cfg),
            "inbox",
            "--for",
            "peerb,peera",
            "--wait",
            "30",
            "--state-dir",
            str(state),
        ],
        runner=fake_gh,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "#99 " in out
    assert "chegou no wait" in out
    assert polls["n"] >= 2


def test_inbox_for_wait_timeout_empty_does_not_dump_backlog_or_mark_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _canal_cfg(tmp_path)
    state = tmp_path / "state"

    def fake_gh(args: list[str], gh: str) -> str:
        return json.dumps(ADDRESSED_THREAD)

    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    rc = mod.main(
        [
            "--config",
            str(cfg),
            "inbox",
            "--for",
            "peerb,peera",
            "--wait",
            "0",
            "--json",
            "--mark-read",
            "--state-dir",
            str(state),
        ],
        runner=fake_gh,
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == []
    assert not (state / "last_seen_peerb.json").exists()


class _FakeClock:
    """Monotonic clock driven by sleep(); gh only sees comments already posted."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, wall_skew_s: float = 0.0) -> None:
        self.t = 0.0
        self.polls = 0
        clock = self
        monkeypatch.setattr(
            mod,
            "time",
            types.SimpleNamespace(monotonic=lambda: clock.t, sleep=lambda s: setattr(clock, "t", clock.t + s)),
        )
        t0 = datetime(2026, 11, 14, 12, 0, 0, 700000, tzinfo=UTC)

        class _DT(datetime):
            @classmethod
            def now(cls, tz=None):  # box wall clock; the wait must not depend on it
                return t0 + timedelta(seconds=clock.t + wall_skew_s)

        monkeypatch.setattr(mod, "datetime", _DT)

    def gh(self, timeline: list[tuple[float, dict]], fail_at: tuple[int, ...] = ()) -> Callable[[list[str], str], str]:
        def fake_gh(args: list[str], gh: str) -> str:
            assert args[0] == "api", args  # wait never posts
            self.polls += 1
            if self.polls in fail_at:
                raise SystemExit("gh_error: Post https://api.github.com/graphql: net/http: TLS handshake timeout")
            return json.dumps([c for at, c in timeline if at <= self.t])

        return fake_gh


def _wait_for(cfg: Path, state: Path, *extra: str, names: str = "peerb,peera", wait: str = "60") -> list[str]:
    return ["--config", str(cfg), "inbox", "--for", names, "--wait", wait, "--state-dir", str(state), *extra]


def test_inbox_for_wait_returns_unread_backlog_and_never_skips_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg, state = _canal_cfg(tmp_path), tmp_path / "state"
    mod.write_cursor(state / "last_seen_peera_peerb.json", 10)
    clock = _FakeClock(monkeypatch)
    # #12 landed 2s before the wait (unread); #13 lands at +40s
    timeline = [(-600, ADDRESSED_THREAD[0]), (-2, _c(12, "para: peerb\n\nantes do wait\n\n— agent-c\n", "2026-11-14T11:59:58Z")),
                (40, _c(13, "para: peerb\n\ndurante\n\n— agent-c\n", "2026-11-14T12:00:40Z"))]
    assert mod.main(_wait_for(cfg, state, "--mark-read"), runner=clock.gh(timeline)) == 0
    out = capsys.readouterr().out
    assert out.startswith("#12 ") and clock.t == 0  # unread comes back at once
    assert mod.read_cursor(state / "last_seen_peera_peerb.json") == 12
    assert mod.main(_wait_for(cfg, state, "--mark-read"), runner=clock.gh(timeline)) == 0
    assert capsys.readouterr().out.startswith("#13 ")
    assert mod.read_cursor(state / "last_seen_peera_peerb.json") == 13


def test_inbox_for_wait_same_second_and_skewed_clock_still_deliver(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _canal_cfg(tmp_path)
    # wait starts at 12:00:00.7 (box clock 5s ahead); relay #14 gets created_at 12:00:00Z
    for skew, name in ((0.0, "s0"), (5.0, "s5")):
        clock = _FakeClock(monkeypatch, wall_skew_s=skew)
        timeline = [(-60, ADDRESSED_THREAD[0]), (0.2, _c(14, "para: peerb\n\nmesmo segundo\n\n— agent-c\n", "2026-11-14T12:00:00Z"))]
        state = tmp_path / name
        assert mod.main(_wait_for(cfg, state, "--mark-read", wait="40"), runner=clock.gh(timeline)) == 0
        assert capsys.readouterr().out.startswith("#14 "), skew
        assert clock.t == pytest.approx(20)  # next poll, not the timeout


def test_inbox_for_cursor_is_shared_across_alias_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg, state = _canal_cfg(tmp_path), tmp_path / "state"
    thread = list(ADDRESSED_THREAD[:6])

    def fake_gh(args: list[str], gh: str) -> str:
        return json.dumps(thread)

    base = ["--config", str(cfg), "inbox", "--state-dir", str(state), "--mark-read"]
    assert mod.main([*base, "--for", "peerb,peera"], runner=fake_gh) == 0
    assert "#15 " in capsys.readouterr().out
    assert mod.main([*base, "--for", "peera,peerb"], runner=fake_gh) == 0
    assert capsys.readouterr().out == ""
    assert sorted(p.name for p in state.glob("*.json")) == ["last_seen_peera_peerb.json"]


def test_inbox_for_reads_legacy_first_alias_cursor(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg, state = _canal_cfg(tmp_path), tmp_path / "state"
    mod.write_cursor(state / "last_seen_peerb.json", 15)  # written by the old aliases[0] key

    def fake_gh(args: list[str], gh: str) -> str:
        return json.dumps(ADDRESSED_THREAD[:6])

    argv = ["--config", str(cfg), "inbox", "--for", "peerb,peera", "--state-dir", str(state), "--mark-read"]
    assert mod.main(argv, runner=fake_gh) == 0
    assert capsys.readouterr().out == ""


def test_inbox_for_wait_recovers_from_transient_gh_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg, state = _canal_cfg(tmp_path), tmp_path / "state"
    clock = _FakeClock(monkeypatch)
    timeline = [(-60, ADDRESSED_THREAD[0]), (10, _c(20, "para: peerb\n\ndepois da falha\n\n— agent-c\n", "2026-11-14T12:00:10Z"))]
    assert mod.main(_wait_for(cfg, state), runner=clock.gh(timeline, fail_at=(2, 3))) == 0
    assert capsys.readouterr().out.startswith("#20 ")
    assert clock.polls == 4 and clock.t < 40  # backoff 2s, 4s instead of a 20s poll


def test_inbox_for_wait_fatal_or_persistent_gh_error_still_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg, state = _canal_cfg(tmp_path), tmp_path / "state"
    _FakeClock(monkeypatch)

    def auth_fail(args: list[str], gh: str) -> str:
        raise SystemExit("gh_error: HTTP 401: Bad credentials")

    with pytest.raises(SystemExit, match="Bad credentials"):
        mod.main(_wait_for(cfg, state), runner=auth_fail)

    def always_timeout(args: list[str], gh: str) -> str:
        raise SystemExit("gh_error: TLS handshake timeout")

    with pytest.raises(SystemExit, match="timeout"):
        mod.main(_wait_for(cfg, state, wait="600"), runner=always_timeout)
    with pytest.raises(SystemExit, match="timeout"):  # wait ends while gh is down
        mod.main(_wait_for(cfg, state, wait="3"), runner=always_timeout)


def test_inbox_for_wait_mark_read_without_cursor_never_skips_hidden_backlog(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Furo 4 (option B): no cursor yet, --wait hides old #12; #13 arrives and is shown.

    The cursor stops at 11 (just below the hidden unread), so the next run still
    delivers #12; #13 repeats once instead of #12 being lost.
    """
    cfg, state = _canal_cfg(tmp_path), tmp_path / "state"
    clock = _FakeClock(monkeypatch)
    old = _c(12, "para: peerb\n\nantigo nao lido\n\n— agent-c\n", "2026-11-14T11:00:00Z")
    new = _c(13, "para: peerb\n\nnovo\n\n— agent-c\n", "2026-11-14T12:00:40Z")
    timeline = [(-3600, ADDRESSED_THREAD[0]), (-3600, old), (40, new)]
    assert mod.main(_wait_for(cfg, state, "--mark-read"), runner=clock.gh(timeline)) == 0
    assert capsys.readouterr().out.startswith("#13 ")
    cursor = state / "last_seen_peera_peerb.json"
    assert mod.read_cursor(cursor) == 11
    argv = ["--config", str(cfg), "inbox", "--for", "peerb,peera", "--state-dir", str(state), "--mark-read"]
    assert mod.main(argv, runner=clock.gh(timeline)) == 0
    out = capsys.readouterr().out
    assert out.startswith("#12 ") and "#13 " in out
    assert mod.read_cursor(cursor) == 13


def test_mark_read_without_for_is_rejected(tmp_path: Path) -> None:
    cfg = _canal_cfg(tmp_path)
    with pytest.raises(SystemExit, match="usage_error"):
        mod.main(["--config", str(cfg), "inbox", "--mark-read"], runner=lambda a, g: "[]")


def test_reply_targets_sender_and_links_comment(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _canal_cfg(tmp_path)
    posted: list[str] = []

    def fake_gh(args: list[str], gh: str) -> str:
        if args[0] == "api":
            return json.dumps(ADDRESSED_THREAD)
        if args[:2] == ["pr", "comment"]:
            posted.append(args[args.index("--body") + 1])
            return "https://example.test/pull/1#issuecomment-100\n"
        raise AssertionError(args)

    assert mod.main(["--config", str(cfg), "reply", "11", "valeu", "--from", "peerb"], runner=fake_gh) == 0
    assert mod.main(["--config", str(cfg), "reply", "14", "oi", "agent-c", "--from", "peerb"], runner=fake_gh) == 0
    capsys.readouterr()
    assert posted[0].startswith("para: agent-a\n") and "valeu" in posted[0]
    assert "— peerb" in posted[0] and posted[0].rstrip().endswith("<!-- reply-to: 11 -->")
    assert posted[1].startswith("para: agent-c\n")
    # the reply's own signature still parses past the trailing marker
    assert mod.parse_signature(posted[0]) == "peerb"
    with pytest.raises(SystemExit, match="not_found"):
        mod.main(["--config", str(cfg), "reply", "999", "x"], runner=fake_gh)


def test_is_relay_comment_accepts_channel_bot_marker() -> None:
    assert mod.is_relay_comment("<!-- agent-relay -->\n**de: agent-c**\n")
    assert mod.is_relay_comment("  <!-- agent-relay -->\n")
    assert mod.is_relay_comment("<!-- channel-bot: agent-c -->\n**de: agent-c**\n")
    assert mod.is_relay_comment("  <!-- channel-bot: agent-b -->\npara: peerb\n")
    assert not mod.is_relay_comment("para: peerb\n\n<!-- channel-bot: agent-c -->\n")
    assert not mod.is_relay_comment("para: agent-a\n\n— peerb\n")
    assert mod.channel_bot_name("<!-- channel-bot: agent-c -->\n**de: agent-c**\n") == "agent-c"


def test_relay_original_sender_uses_channel_bot_name() -> None:
    thread = [
        _c(10, "para: agent-c\n\npergunta\n\n— peerb\n", "2026-11-12T10:00:00Z"),
        _c(
            20,
            "<!-- channel-bot: agent-c -->\n\nresposta sem de:\n",
            "2026-11-12T10:02:00Z",
            "bot",
        ),
        _c(
            21,
            "<!-- channel-bot: agent-c -->\npara: peerb\n\nresposta com para\n",
            "2026-11-12T10:03:00Z",
            "bot",
        ),
    ]
    assert mod.relay_original_sender(thread[1], thread) == "peerb"
    items = mod.addressed_inbox(thread, PEERB, None)
    assert [i["id"] for i in items] == [20, 21]
    by_id = {i["id"]: i for i in items}
    assert by_id[20]["relay"] is True
    assert by_id[20]["from"] == "agent-c"
    assert by_id[21]["from"] == "agent-c"


def test_format_send_body_does_not_double_sender_signature() -> None:
    once = mod.format_send_body("agent-a", "hello", "peerb")
    assert once.count("— peerb") == 1
    already = mod.format_send_body("agent-a", "hello\n\n— peerb", "peerb")
    assert already.count("— peerb") == 1
    assert already.strip().endswith("— peerb")
    en_dash = mod.format_send_body("agent-a", "hello\n\n-- peerb", "peerb")
    assert en_dash.count("peerb") == 1
    other = mod.format_send_body("agent-a", "hello\n\n— agent-c", "peerb")
    assert other.strip().endswith("— peerb")
    assert "— agent-c" in other


def test_canonical_cursor_is_order_independent(tmp_path: Path) -> None:
    assert mod.canonical_alias_key(["peerb", "peera"]) == "peera,peerb"
    assert mod.canonical_alias_key(["peera", "peerb"]) == "peera,peerb"
    a = mod.cursor_path_for_aliases(["peerb", "peera"], tmp_path)
    b = mod.cursor_path_for_aliases(["peera", "peerb"], tmp_path)
    assert a == b
    assert a.name == "last_seen_peera_peerb.json"
    single = mod.cursor_path_for_aliases(["peerb"], tmp_path)
    assert single.name == "last_seen_peerb.json"


def test_cursor_fallback_reads_legacy_aliases0(tmp_path: Path) -> None:
    legacy = mod.cursor_path("peerb", tmp_path)
    canonical = mod.cursor_path_for_aliases(["peerb", "peera"], tmp_path)
    mod.write_cursor(legacy, 42)
    value, path = mod.read_cursor_for_aliases(["peerb", "peera"], tmp_path)
    assert value == 42
    assert path == canonical
    assert path != legacy


def test_inbox_for_wait_floors_by_comment_id_not_clock(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same-second / clock-skew comments after the wait-start max id still print."""
    cfg = _canal_cfg(tmp_path)
    state = tmp_path / "state"
    already = _c(50, "para: peerb\n\nold unread\n\n— agent-c\n", "2026-11-01T00:00:00Z")
    same_second = _c(51, "para: peerb\n\njust arrived\n\n— agent-b\n", "2026-11-14T12:00:00Z")
    polls = {"n": 0}

    def fake_gh(args: list[str], gh: str) -> str:
        polls["n"] += 1
        if polls["n"] == 1:
            return json.dumps([already])
        return json.dumps([already, same_second])

    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    rc = mod.main(
        [
            "--config",
            str(cfg),
            "inbox",
            "--for",
            "peerb,peera",
            "--wait",
            "30",
            "--json",
            "--state-dir",
            str(state),
        ],
        runner=fake_gh,
    )
    assert rc == 0
    items = json.loads(capsys.readouterr().out)
    assert [i["id"] for i in items] == [51]
    assert "just arrived" in items[0]["text"]
    assert polls["n"] >= 2


def test_inbox_for_peerb_peera_and_peera_peerb_share_cursor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _canal_cfg(tmp_path)
    state = tmp_path / "state"
    thread = [_c(30, "para: peerb\n\nhi\n\n— agent-c\n", "2026-11-12T12:00:00Z")]

    def fake_gh(args: list[str], gh: str) -> str:
        return json.dumps(thread)

    base_a = ["--config", str(cfg), "inbox", "--for", "peerb,peera", "--state-dir", str(state)]
    base_b = ["--config", str(cfg), "inbox", "--for", "peera,peerb", "--state-dir", str(state)]
    assert mod.main([*base_a, "--mark-read"], runner=fake_gh) == 0
    capsys.readouterr()
    assert (state / "last_seen_peera_peerb.json").is_file()
    assert not (state / "last_seen_peerb.json").exists()
    assert not (state / "last_seen_peera.json").exists()
    assert mod.main([*base_b, "--mark-read"], runner=fake_gh) == 0
    assert capsys.readouterr().out == ""


def test_run_gh_retries_transient_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake_run(cmd, capture_output=True, text=True):
        calls["n"] += 1
        if calls["n"] < 3:
            return type("P", (), {"returncode": 1, "stderr": "HTTP 502 Bad Gateway", "stdout": ""})()
        return type("P", (), {"returncode": 0, "stderr": "", "stdout": "ok\n"})()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    assert mod.run_gh(["api", "x"]) == "ok\n"
    assert calls["n"] == 3


def test_run_gh_does_not_retry_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake_run(cmd, capture_output=True, text=True):
        calls["n"] += 1
        return type("P", (), {"returncode": 1, "stderr": "HTTP 404 Not Found", "stdout": ""})()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    with pytest.raises(SystemExit, match="gh_error"):
        mod.run_gh(["api", "x"])
    assert calls["n"] == 1
